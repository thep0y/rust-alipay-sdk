use std::convert::TryInto;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64ct::{Base64, Encoding};
use convert_case::{Case, Casing};
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use serde_json::Value;

use crate::alipay::{KeyType, SignType};
use crate::{
    alipay::AlipaySdkConfig,
    error::{AlipayResult, Error},
    time::{now, to_time_string},
    ParamsMap,
};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub fn base64_encode(data: &[u8]) -> String {
    Base64::encode_string(data)
}

pub fn base64_decode(src: &str) -> AlipayResult<Vec<u8>> {
    trace!("base64 decode source: {}", src);
    Ok(Base64::decode_vec(src).map_err(|e| {
        error!("解码 base64 出错：{}", e);
        e
    })?)
}

pub fn value_to_string(value: &Value) -> String {
    if value.is_string() {
        value.as_str().unwrap().to_string()
    } else {
        value.to_string()
    }
}

pub(crate) fn keys_to_snake_case(data: &ParamsMap) -> ParamsMap {
    let mut new_data = serde_json::Map::<String, Value>::with_capacity(data.len());
    for (k, v) in data.iter() {
        let new_key = k.to_case(Case::Snake);
        trace!("new key: {}", new_key);
        new_data.insert(new_key, v.clone());
    }

    new_data
}

pub(crate) fn keys_to_camel_case(data: &ParamsMap) -> ParamsMap {
    let mut new_data = serde_json::Map::<String, Value>::with_capacity(data.len());
    for (k, v) in data.iter() {
        new_data.insert(k.to_case(Case::Camel), v.clone());
    }

    new_data
}

fn parse_key(aes_key: &str) -> ([u8; 16], [u8; 16]) {
    ([b'0'; 16], aes_key.as_bytes().try_into().unwrap())
}

pub fn aes_encrypt(data: &ParamsMap, aes_key: &str) -> String {
    let plain = serde_json::to_vec(data).unwrap();

    let (iv, key) = parse_key(aes_key);

    let mut buf = [0u8; 48];
    let pt_len = plain.len();
    buf[..pt_len].copy_from_slice(&plain);

    let cipher_text = Aes128CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(&plain, &mut buf)
        .unwrap();

    base64_encode(cipher_text)
}

pub fn aes_decrypt(data: &str, aes_key: &str) -> AlipayResult<Value> {
    let cipher = base64_decode(data)?;

    let (iv, key) = parse_key(aes_key);

    let cipher_len = cipher.len();

    let mut buf = [0u8; 48];
    buf[..cipher_len].copy_from_slice(&cipher);

    let bytes = Aes128CbcDec::new(&key.into(), &iv.into())
        .decrypt_padded_b2b_mut::<Pkcs7>(&cipher, &mut buf)
        .unwrap();

    Ok(serde_json::from_slice(bytes).unwrap())
}

pub fn sign(method: &str, params: ParamsMap, config: &AlipaySdkConfig) -> AlipayResult<ParamsMap> {
    let mut sign_params = ParamsMap::new();
    sign_params.insert("method".to_owned(), Value::String(method.to_string()));
    sign_params.insert("appId".to_owned(), Value::String(config.app_id.clone()));
    sign_params.insert("charset".to_owned(), Value::String(config.charset.clone()));
    sign_params.insert("version".to_owned(), Value::String(config.version.clone()));
    sign_params.insert(
        "signType".to_owned(),
        Value::String(config.sign_type.to_string()),
    );
    sign_params.insert(
        "timestamp".to_owned(),
        Value::String(to_time_string(now()?)),
    );

    for (k, v) in params.iter() {
        if k == "needEncrypt" || k == "bizContent" || k == "biz_content" {
            continue;
        }
        sign_params.insert(k.clone(), v.clone());
    }

    if config.app_cert_sn.len() > 0 && config.alipay_root_cert_sn.len() > 0 {
        sign_params.insert(
            "appCertSn".to_owned(),
            Value::String(config.app_cert_sn.clone()),
        );
        sign_params.insert(
            "alipayRootCertSn".to_owned(),
            Value::String(config.alipay_root_cert_sn.clone()),
        );
    }

    if config.ws_service_url.len() > 0 {
        sign_params.insert(
            "wsServiceUrl".to_owned(),
            Value::String(config.ws_service_url.clone()),
        );
    }

    trace!("sign params: {:?}", sign_params);

    // 兼容官网的 biz_content;
    if params.contains_key("bizContent") && params.contains_key("biz_content") {
        return Err(Error::Params(
            "不能同时设置 bizContent 和 biz_content".to_owned(),
        ));
    }

    let biz_content = params.get("bizContent").or(params.get("biz_content"));

    if let Some(bc) = biz_content {
        let bc = keys_to_snake_case(bc.as_object().unwrap());
        debug!("biz_content: {:?}", bc);
        if params.get("needEncrypt") == Some(&Value::Bool(true)) {
            if config.encrypt_key.is_empty() {
                return Err(Error::Params("请设置encryptKey参数".to_owned()));
            }

            sign_params.insert("encryptType".to_owned(), Value::String("AES".to_owned()));
            sign_params.insert(
                "bizContent".to_owned(),
                Value::String(aes_encrypt(&bc, &config.encrypt_key)),
            );
        } else {
            let v = keys_to_snake_case(&bc);
            sign_params.insert("bizContent".to_owned(), Value::Object(v));
        }
    }

    // params key 驼峰转下划线
    let mut decamelize_params = keys_to_snake_case(&sign_params);
    debug!("decamelize params: {:?}", decamelize_params);

    // 排序
    let mut keys = decamelize_params.keys().collect::<Vec<&String>>();
    keys.sort();

    let mut queries = Vec::with_capacity(keys.len());
    for key in keys.iter() {
        let data = &decamelize_params[key.to_owned()];

        let v = match data {
            Value::Array(_) => return Err(Error::Sign("暂不支持处理数组".to_owned())),
            _ => value_to_string(data),
        };

        trace!("key={} value={}({})", key, v, v.len());

        let query = format!("{}={}", key, v);
        queries.push(query);
    }
    let sign_str = queries.join("&");
    debug!("sign str: {}", sign_str);

    let sign = sign_with_rsa(
        &config.key_type,
        &config.private_key,
        &sign_str,
        &config.sign_type,
    )?;
    debug!("sign: {:?}", sign);

    decamelize_params.insert("sign".to_owned(), serde_json::json!(base64_encode(&sign)));

    Ok(decamelize_params)
}

fn deserialize_rsa_public_key(public_key: &str) -> AlipayResult<RsaPublicKey> {
    RsaPublicKey::from_public_key_pem(public_key).map_err(|e| {
        error!("反序列化公钥出错: {}", e);
        Error::Sign(e.to_string())
    })
}

pub fn sign_with_rsa(
    key_type: &KeyType,
    private_key: &str,
    sign_str: &str,
    sign_type: &SignType,
) -> AlipayResult<Vec<u8>> {
    let private_key = key_type.deserialize_rsa_private_key(private_key)?;
    let digest = sign_type.digest(sign_str);

    let signature = private_key
        .sign(sign_type.signature(), &digest)
        .map_err(|e| Error::Sign(e.to_string()))?;

    Ok(signature)
}

/// 验签。
///
/// 需要注意，sign 应该是 base64 decode 后的数据，不要直接将`base64str.as_bytes()`作为 sign 传入
pub fn verify_with_rsa(
    data: &[u8],
    public_key: &str,
    sign: &[u8],
    sign_type: &SignType,
) -> AlipayResult<bool> {
    let public_key = deserialize_rsa_public_key(public_key)?;

    match public_key.verify(sign_type.signature(), &sign_type.hash(data), sign) {
        Ok(()) => Ok(true),
        Err(e) => {
            error!("验签错误: {}", e);
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;

    use crate::{
        alipay::{AlipaySdkBuilder, SignType},
        error::AlipayResult,
    };

    use super::{base64_decode, sign, verify_with_rsa};

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_sign() {
        init();

        let private_key =
            String::from_utf8(fs::read("examples/fixtures/app-private-key.pem").unwrap()).unwrap();

        let sdk = AlipaySdkBuilder::new("app111".to_owned(), private_key)
            .with_sign_type(SignType::RSA2)
            .build();

        debug!("alipay sdk config: {:?}", sdk.config);

        let data = sign(
            "alipay.security.risk.content.analyze",
            serde_json::json!({ "publicArgs": 1, "bizContent": { "a_b": 1, "aBc": "Ab" } })
                .as_object()
                .unwrap()
                .clone(),
            &sdk.config,
        )
        .unwrap();

        assert_eq!(data["method"], "alipay.security.risk.content.analyze");
        assert_eq!(data["app_id"], "app111");
        assert_eq!(data["charset"], "utf-8");
        assert_eq!(data["version"], "1.0.0");
        assert_eq!(data["sign_type"], "RSA2");
        assert_eq!(data["public_args"], 1);
        assert_eq!(data["biz_content"], json!({"a_b":1,"a_bc":"Ab"}));
        assert_ne!(data["sign"], "");

        let data2 = sign(
            "alipay.security.risk.content.analyze",
            serde_json::json!({ "publicArgs": 1, "biz_content": { "a_b": 1, "aBc": "Ab" } })
                .as_object()
                .unwrap()
                .clone(),
            &sdk.config,
        )
        .unwrap();

        assert_eq!(data2["biz_content"], json!({"a_b":1,"a_bc":"Ab"}));
        assert_eq!(data["sign"], data2["sign"]);
    }

    #[test]
    fn test_verify_sign_should_success() -> AlipayResult<()> {
        init();

        let alipay_public_key = AlipaySdkBuilder::format_key(
            include_str!("../examples/fixtures/alipay-public-key.pem"),
            "PUBLIC KEY",
        );
        let sign_type = SignType::default();

        let sign = "NNOVPB/nOWMbUHbpvk+8YNcdbnNz40GsMpU/5+KrGPIqXT8Fc//A/cXtgZbE914ERg3PCGIy5l4C7yKSNOu+7WRUFQwnSUz2LMMkDul3QnqDwLwPfzTXMoofGTxiNgG+lW0rZ64+HvMQAHx//+6DNLJxPey9xaIgNom3CEr1LzpVBmhYAI9vdYHHLyyQ0bUSxaUB7lPdNOJxmbMNyPZ4mNK0pJ7B/gDTlCeT8oqy3h8B80kSs8FnMyucHu01JoC9XAydeST0L/jJ0zCFrsIZpYdhfy9yTM52NH890MRbX3GXECECDsvAgCR8H/DHUfbP2mqG+W/6lnbRBpUnfuV4zQ==";
        let sign_content = r#"{"code":"40002","msg":"Invalid Arguments","sub_code":"isv.upload-fail","sub_msg":"文件上传失败"}"#;
        let result = verify_with_rsa(
            sign_content.as_bytes(),
            &alipay_public_key,
            &base64_decode(sign).unwrap(),
            &sign_type,
        )?;
        assert_eq!(result, true);

        Ok(())
    }
}
