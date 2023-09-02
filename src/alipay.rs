use std::{
    path::{Path, PathBuf},
    time,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use urlencoding::{decode, encode};

use crate::{
    antcertutil::{get_sn, get_sn_from_path, load_public_key, load_public_key_from_path},
    error::{AlipayResult, Error, HttpError},
    form::{AlipayForm, IField, IFile, Method},
    time::now,
    util::{aes_decrypt, base64_decode, keys_to_camel_case, sign, verify_with_rsa},
    ParamsMap,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
pub enum SignType {
    RSA,
    RSA2,
}

impl Default for SignType {
    fn default() -> Self {
        SignType::RSA
    }
}

impl SignType {
    pub fn as_str(&self) -> &str {
        match self {
            SignType::RSA => "RSA",
            SignType::RSA2 => "RSA2",
        }
    }

    pub fn as_string(&self) -> String {
        match self {
            SignType::RSA => String::from("RSA"),
            SignType::RSA2 => String::from("RSA2"),
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "RSA" => Self::RSA,
            _ => Self::RSA2,
        }
    }
}

#[derive(Debug)]
pub enum KeyType {
    PKCS1,
    PKCS8,
}

impl Default for KeyType {
    fn default() -> Self {
        KeyType::PKCS1
    }
}

impl KeyType {
    fn to_str(&self) -> &str {
        match self {
            KeyType::PKCS1 => "RSA PRIVATE KEY",
            KeyType::PKCS8 => "PRIVATE KEY",
        }
    }
}

/// AlipaySdkConfig SDK 配置
#[derive(Debug)]
pub struct AlipaySdkConfig {
    /// 应用 id
    pub app_id: String,
    /// 应用私钥字符串。RSA签名验签工具：https://docs.open.alipay.com/291/106097）
    pub private_key: String,
    /// 签名种类
    pub sign_type: SignType,
    /// 支付宝公钥（需要对返回值做验签时候必填）
    alipay_public_key: String,
    gateway: String,
    timeout: time::Duration,
    camelcase: bool,
    pub charset: String,
    pub version: String,
    pub key_type: KeyType,
    pub app_cert_sn: String,
    pub alipay_root_cert_sn: String,
    alipay_cert_sn: String,
    pub encrypt_key: String,
    pub ws_service_url: String,
}

impl AlipaySdkConfig {
    fn builder() -> AlipaySdkConfigBuilder {
        AlipaySdkConfigBuilder::default()
    }

    pub fn private_key(&self) -> &str {
        &self.private_key
    }

    pub fn alipay_public_key(&self) -> &str {
        &self.alipay_public_key
    }
}

#[derive(Default)]
pub struct AlipaySdkConfigBuilder {
    /// 应用 id
    app_id: String,
    /// 应用私钥字符串。RSA签名验签工具：https://docs.open.alipay.com/291/106097）
    private_key: String,
    /// 签名种类
    sign_type: SignType,
    /// 支付宝公钥（需要对返回值做验签时候必填）
    alipay_public_key: String,
    gateway: String,
    timeout: time::Duration,
    camelcase: bool,
    version: String,
    key_type: KeyType,
    app_cert_path: PathBuf,
    app_cert_content: String,
    app_cert_sn: String,
    alipay_root_cert_path: String,
    alipay_root_cert_content: String,
    alipay_root_cert_sn: String,
    alipay_public_cert_path: String,
    alipay_public_cert_content: String,
    alipay_cert_sn: String,
    encrypt_key: String,
    ws_service_url: String,
}

impl AlipaySdkConfigBuilder {
    pub fn new(app_id: String, private_key: String) -> Self {
        AlipaySdkConfigBuilder {
            app_id,
            private_key,
            sign_type: Default::default(),
            alipay_public_key: Default::default(),
            gateway: Default::default(),
            timeout: Default::default(),
            camelcase: Default::default(),
            version: Default::default(),
            key_type: Default::default(),
            app_cert_path: Default::default(),
            app_cert_content: Default::default(),
            app_cert_sn: Default::default(),
            alipay_root_cert_path: Default::default(),
            alipay_root_cert_content: Default::default(),
            alipay_root_cert_sn: Default::default(),
            alipay_public_cert_path: Default::default(),
            alipay_public_cert_content: Default::default(),
            alipay_cert_sn: Default::default(),
            encrypt_key: Default::default(),
            ws_service_url: Default::default(),
        }
    }

    pub fn with_app_cert_content<B: AsRef<[u8]>>(mut self, content: B) -> AlipayResult<Self> {
        self.app_cert_sn = get_sn(content, false)?;
        Ok(self)
    }

    pub fn with_app_cert_path<P: AsRef<Path>>(mut self, file_path: P) -> AlipayResult<Self> {
        self.app_cert_sn = get_sn_from_path(file_path, false)?;
        Ok(self)
    }

    pub fn with_alipay_public_cert_content<B: AsRef<[u8]>>(
        mut self,
        content: B,
    ) -> AlipayResult<Self> {
        self.alipay_cert_sn = get_sn(content.as_ref(), false)?;
        let alipay_public_key = load_public_key(content)?;
        self.alipay_public_key = Self::format_key(&alipay_public_key, "PUBLIC KEY");
        Ok(self)
    }

    pub fn with_alipay_public_cert_path<P: AsRef<Path>>(
        mut self,
        file_path: P,
    ) -> AlipayResult<Self> {
        self.alipay_cert_sn = get_sn_from_path(file_path.as_ref(), false)?;
        let alipay_public_key = load_public_key_from_path(file_path)?;
        self.alipay_public_key = Self::format_key(&alipay_public_key, "PUBLIC KEY");
        Ok(self)
    }

    pub fn with_alipay_root_cert_content<B: AsRef<[u8]>>(
        mut self,
        content: B,
    ) -> AlipayResult<Self> {
        self.alipay_root_cert_sn = get_sn(content, true)?;
        Ok(self)
    }

    pub fn with_alipay_root_cert_path<P: AsRef<Path>>(
        mut self,
        file_path: P,
    ) -> AlipayResult<Self> {
        self.alipay_root_cert_sn = get_sn_from_path(file_path, true)?;
        Ok(self)
    }

    pub fn with_alipay_public_key(mut self, alipay_public_key: String) -> Self {
        self.alipay_public_key = Self::format_key(&alipay_public_key, "PUBLIC KEY");
        self
    }

    pub fn with_key_type(mut self, key_type: KeyType) -> Self {
        self.key_type = key_type;
        self
    }

    pub fn with_sign_type(mut self, sign_type: SignType) -> Self {
        self.sign_type = sign_type;
        self
    }

    pub fn with_gateway(mut self, gateway: String) -> Self {
        self.gateway = gateway;
        self
    }

    pub fn with_timeout(mut self, timeout: time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn enable_camelcase(mut self) -> Self {
        self.camelcase = true;
        self
    }

    pub fn with_encrypt_key(mut self, encrypt_key: String) -> Self {
        self.encrypt_key = encrypt_key;
        self
    }

    /// 格式化 key
    pub fn format_key(key: &str, key_type: &str) -> String {
        let mut item: Vec<&str> = key.split("\n").into_iter().map(|s| s.trim()).collect();

        if item[0].contains(key_type) {
            item.remove(0);
        }

        if item[item.len() - 1].contains(key_type) {
            item.pop();
        }

        format!(
            "-----BEGIN {}-----\n{}\n-----END {}-----",
            key_type,
            item.join(""),
            key_type
        )
    }

    pub fn build(self) -> AlipaySdkConfig {
        // if self.alipay_public_key.is_empty() {
        //     return Err(Error::Config("alipay_public_key 不能为空".to_string()));
        // }

        let private_key = Self::format_key(&self.private_key, self.key_type.to_str());

        AlipaySdkConfig {
            app_id: self.app_id,
            private_key,
            sign_type: self.sign_type,
            alipay_public_key: self.alipay_public_key,
            gateway: self.gateway,
            timeout: self.timeout,
            camelcase: self.camelcase,
            charset: "utf-8".to_string(),
            version: "1.0".to_string(),
            key_type: self.key_type,
            app_cert_sn: self.app_cert_sn,
            alipay_root_cert_sn: self.alipay_root_cert_sn,
            alipay_cert_sn: self.alipay_cert_sn,
            encrypt_key: self.encrypt_key,
            ws_service_url: self.ws_service_url,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AlipaySdkCommonResult {
    code: String,
    msg: String,
    sub_code: Option<String>,
    sub_msg: Option<String>,
    // result: HashMap<>
}

#[derive(Debug)]
pub enum AlipaySdkResult {
    Common(AlipaySdkCommonResult),
    String(String),
}

pub struct AlipaySDK {
    sdk_version: String,
    config: AlipaySdkConfig,
}

impl AlipaySDK {
    pub fn new(config: AlipaySdkConfig) -> Self {
        Self {
            config,
            sdk_version: VERSION.to_string(),
        }
    }

    /// 格式化请求 url（按规范把某些固定的参数放入 url）
    fn format_url<'a>(url: &str, params: ParamsMap) -> (ParamsMap, String) {
        let mut request_url = url.to_string();

        let url_args = vec![
            "app_id",
            "method",
            "format",
            "charset",
            "sign_type",
            "sign",
            "timestamp",
            "version",
            "notify_url",
            "return_url",
            "auth_token",
            "app_auth_token",
            "app_cert_sn",
            "alipay_root_cert_sn",
            "ws_service_url",
        ];

        let keys_to_remove: Vec<&String> = params
            .keys()
            .filter(|&key| url_args.contains(&key.as_str()))
            .collect();

        let mut params = params.clone();

        for key in &keys_to_remove {
            let val = &params[key.to_owned()].to_string();
            let val = encode(val);

            if request_url.contains("?") {
                request_url += &format!("&{}={}", key, val);
            } else {
                request_url += &format!("?{}={}", key, val);
            }
        }

        params.retain(|key, _value| !keys_to_remove.contains(&key));

        (params, request_url)
    }

    /// 文件上传
    fn multipart_exec(
        &self,
        method: String,
        files: &[IFile],
        fields: &[IField],
    ) -> AlipayResult<AlipaySdkCommonResult> {
        // let sign_params = HashMap::<&str, &str>::new();
        // let form_data = HashMap::<&str, &str>::new();
        //
        // form.iter().map(|(k, v)| {
        //     let val = v.to_string();
        //     sign_params.insert(&k.to_case(Case::Camel), &val);
        //     form_data.insert(&k.to_case(Case::Snake), &val);
        // });
        //
        // let (_, url) = Self::format_url(self.config.gateway, sign_params);
        //
        // let mut req = ureq::post(url.as_str())
        //     .timeout(self.config.timeout)
        //     .set("user-agent", &self.sdk_version);

        Ok(AlipaySdkCommonResult {
            code: "".to_owned(),
            msg: "".to_owned(),
            sub_code: None,
            sub_msg: None,
        })
    }

    /// 生成请求字符串，用于客户端进行调用
    pub fn sdk_exec(&self, method: String, params: ParamsMap) -> AlipayResult<String> {
        let data = sign(method, params, &self.config)?;

        let sdk_str = data
            .iter()
            .map(|(k, v)| format!("{}={}", k, encode(&v.to_string())))
            .collect::<Vec<String>>()
            .join("&");

        Ok(sdk_str)
    }

    /// 生成网站接口请求链接或表单
    pub fn page_exec(method: String, params: ParamsMap) {
        let mut form_data = AlipayForm::new();
        for (k, v) in params.iter() {
            if k == "method" {
                form_data.set_method(Method::from_string(&v.to_string()));
            } else {
                form_data.add_field(k.clone(), v.clone());
            }
        }
    }

    /// page 类接口，兼容原来的 formData 格式
    fn _page_exec(&self, method: String, form_data: AlipayForm) -> AlipayResult<String> {
        let mut sign_params = ParamsMap::with_capacity(form_data.get_fields().len() + 1);
        sign_params.insert(
            "alipaySdk".to_owned(),
            Value::String(self.sdk_version.clone()),
        );

        for field in form_data.get_fields().iter() {
            sign_params.insert(field.name.clone(), field.value.clone());
        }

        // 签名方法中使用的 key 是驼峰
        let sign_params = keys_to_camel_case(&sign_params);

        let sign_data = sign(method, sign_params, &self.config)?;

        let (exec_params, url) = Self::format_url(&self.config.gateway, sign_data);

        if form_data.get_method() == &Method::GET {
            let query = exec_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, encode(&v.to_string())))
                .collect::<Vec<String>>()
                .join("&");

            return Ok(format!("{}&{}", url, query));
        }

        let form_name = format!("alipaySDKSubmit{}", now()?.as_millis());

        let inputs = exec_params
            .iter()
            .map(|(k, v)| {
                let value = v.to_string().replace("\"", "&quot;");
                format!(r#"<input type="hidden" name="{}" value="{}" />"#, k, value)
            })
            .collect::<Vec<String>>()
            .join("");
        let form_html = format!(
            r#"
      <form action="{}" method="post" name="{}" id="{}">
      {}
      </form>
      <script>document.forms["{}"].submit();</script>
        "#,
            url, form_name, form_name, inputs, form_name
        );

        Ok(form_html)
    }

    /// 消息验签
    fn notify_rsa_check(
        &self,
        sign_args: &ParamsMap,
        sign_str: &str,
        sign_type: &SignType,
        raw: bool,
    ) -> AlipayResult<()> {
        let mut keys = sign_args.keys().collect::<Vec<&String>>();
        keys.sort();

        let mut queries = Vec::with_capacity(keys.len());

        for key in keys.iter() {
            let value = &sign_args[&key.to_string()];

            // 如果 value 中包含了诸如 % 字符，decodeURIComponent 会报错
            // 而且 notify 消息大部分都是 post 请求，无需进行 decodeURIComponent 操作
            let v = if raw {
                value.to_string()
            } else {
                decode(&value.to_string())?.into_owned()
            };

            queries.push(format!("{}={}", key, v));
        }

        let sign_content = queries.join("&");

        verify_with_rsa(
            sign_content.as_bytes(),
            &self.config.alipay_public_key,
            &base64_decode(sign_str)?,
        )
    }

    pub fn get_sign_str(origin_str: &str, response_key: &str) -> String {
        // 待签名的字符串
        let mut validate_str = origin_str.trim();
        // 找到 xxx_response 开始的位置
        let start_index = origin_str
            .find(&(response_key.to_owned() + "\""))
            .map(|idx| idx as i32)
            .unwrap_or_else(|| -1);
        // 找到最后一个 “"sign"” 字符串的位置（避免）
        let last_index = origin_str
            .rfind("\"sign\"")
            .map(|idx| idx as i32)
            .unwrap_or_else(|| -1);

        // 删除 xxx_response 及之前的字符串
        // 假设原始字符串为
        //  {"xxx_response":{"code":"10000"},"sign":"jumSvxTKwn24G5sAIN"}
        // 删除后变为
        //  :{"code":"10000"},"sign":"jumSvxTKwn24G5sAIN"}
        validate_str = &validate_str[(start_index + response_key.len() as i32 + 1) as usize..];

        // 删除最后一个 "sign" 及之后的字符串
        // 删除后变为
        //  :{"code":"10000"},
        // {} 之间就是待验签的字符串
        validate_str = &validate_str[0..last_index as usize];

        // 删除第一个 { 之前的任何字符
        validate_str = &validate_str[validate_str.find("{").unwrap_or(0)..];

        // 删除最后一个 } 之后的任何字符
        validate_str = &validate_str[..validate_str.rfind("}").unwrap_or(0)];

        validate_str.to_owned()
    }

    pub fn exec(&self, method: String, params: ExecParams) -> AlipayResult<AlipaySdkResult> {
        if let Some(form) = params.form_data {
            if form.get_files().len() > 0 {
                let res = self.multipart_exec(method, form.get_files(), form.get_fields())?;

                return Ok(AlipaySdkResult::Common(res));
            }

            // fromData 中不包含文件时，认为是 page 类接口（返回 form 表单）
            // 比如 PC 端支付接口 alipay.trade.page.pay
            return Ok(AlipaySdkResult::String(self._page_exec(method, form)?));
        }

        // 计算签名
        let sign_data = sign(method.clone(), params.params, &self.config)?;
        let (exec_params, url) = Self::format_url(&self.config.gateway, sign_data);

        let resp = ureq::post(&url)
            .set("user-agent", &self.sdk_version)
            .timeout(self.config.timeout)
            .send_json(exec_params)?;

        if resp.status() != 200 {
            return Err(Error::Http(HttpError::new(
                &resp.into_string()?,
                "[AlipaySdk]HTTP 请求错误",
            )));
        }

        // let response_text = &resp.into_string()?;

        // 示例响应格式
        // {"alipay_trade_precreate_response":
        //  {"code": "10000","msg": "Success","out_trade_no": "111111","qr_code": "https:\/\/"},
        //  "sign": "abcde="
        // }
        // 或者
        // {"error_response":
        //  {"code":"40002","msg":"Invalid Arguments","sub_code":"isv.code-invalid","sub_msg":"授权码code无效"},
        // }
        let json = resp.into_json::<Value>()?;
        let result = if let Some(r) = json.as_object() {
            r
        } else {
            return Err(Error::Http(HttpError::new(
                &json.to_string(),
                "[AlipaySdk]响应体为空",
            )));
        };

        let response_key = method.replace(".", "_") + "_response";
        let mut data = match result.get(&response_key) {
            Some(d) => d.clone(),
            None => {
                return Err(Error::Http(HttpError::new(
                    &json.to_string(),
                    "[AlipaySdk]HTTP 请求错误",
                )))
            }
        };

        if params.need_encrypt {
            let data_str = data.to_string();
            data = aes_decrypt(&data_str, &self.config.encrypt_key)?;
        }

        // 按字符串验签
        let validate_success = if params.validate_sign {
            self.check_response_sign(&json.to_string(), &response_key)
        } else {
            true
        };

        if !validate_success {
            return Err(Error::Http(HttpError::new(
                &json.to_string(),
                "[AlipaySdk]验签失败",
            )));
        }

        let common: AlipaySdkCommonResult = if self.config.camelcase {
            serde_json::from_value(Value::Object(keys_to_camel_case(data.as_object().unwrap())))?
        } else {
            serde_json::from_value(data)?
        };

        Ok(AlipaySdkResult::Common(common))
    }

    // 结果验签
    fn check_response_sign(&self, sign_str: &str, response_key: &str) -> bool {
        if self.config.alipay_public_key.is_empty() {
            // 支付宝公钥不存在时不做验签
            return true;
        }

        // 带验签的参数不存在时返回失败
        if sign_str.is_empty() {
            return false;
        }

        // 根据服务端返回的结果截取需要验签的目标字符串
        let validate_str = Self::get_sign_str(sign_str, response_key);
        // 服务端返回的签名
        let sign_value = serde_json::from_str::<Value>(sign_str).unwrap();
        let server_sign = sign_value.get("sign").unwrap();

        // 参数存在，并且是正常的结果（不包含 sub_code）时才验签
        match verify_with_rsa(
            validate_str.as_bytes(),
            &self.config.alipay_public_key,
            server_sign.to_string().as_bytes(),
        ) {
            Ok(()) => true,
            Err(_) => false,
        }
    }

    fn check_notify_sign(&self, post_data: ParamsMap, raw: bool) -> bool {
        let sign_str = post_data["sign"].to_string();

        // 未设置“支付宝公钥”或签名字符串不存，验签不通过
        if self.config.alipay_public_key.is_empty() || sign_str.is_empty() {
            return false;
        }

        // 先从签名字符串中取 sign_type，再取配置项、都不存在时默认为 RSA2（RSA 已不再推荐使用）
        let sign_type = match post_data.get("sign_type") {
            Some(v) => v.clone(),
            None => match post_data.get("signType") {
                Some(v) => v.clone(),
                None => Value::String("RSA2".to_string()),
            },
        };

        let mut sign_args = post_data.clone();
        // 除去 sign
        sign_args.remove("sign");

        // 某些用户可能自己删除了 sign_type 后再验签
        // 为了保持兼容性临时把 sign_type 加回来
        // 因为下面的逻辑会验签 2 次所以不会存在验签不同过的情况
        sign_args.insert("sign_type".to_owned(), sign_type.clone());

        let sign_type = SignType::from_str(&sign_type.to_string());

        // 保留 sign_type 验证一次签名
        let verify_result = self.notify_rsa_check(&sign_args, &sign_str, &sign_type, raw);

        if verify_result.is_ok() {
            return true;
        }

        // 删除 sign_type 验一次
        // 因为“历史原因”需要用户自己判断是否需要保留 sign_type 验证签名
        // 这里是把其他 sdk 中的 rsaCheckV1、rsaCheckV2 做了合并
        sign_args.remove("sign_type");
        match self.notify_rsa_check(&sign_args, &sign_str, &sign_type, raw) {
            Ok(()) => true,
            Err(_) => false,
        }
    }
}

pub struct ExecParams {
    form_data: Option<AlipayForm>,
    params: ParamsMap,
    need_encrypt: bool,
    validate_sign: bool,
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Duration};

    use serde_json::json;

    use crate::error::Error;

    use super::{AlipaySDK, AlipaySdkConfigBuilder};

    const PRIVATE_KEY: &str = include_str!("../examples/fixtures/app-private-key.pem");
    const ALIPAY_PUBLIC_KEY: &str = include_str!("../examples/fixtures/app-public-key.pem");

    const APP_ID: &str = "2021000122671080";
    const GATE_WAY: &str = "https://openapi-sandbox.dl.alipaydev.com/gateway.do";

    // #[test]
    // fn builder() {
    //     let ab = AlipaySdkConfigBuilder::new("111".to_string(), PRIVATE_KEY.to_string());
    //     let config = ab.build();
    //     println!("{:?}", config);
    //     assert_eq!(config.is_err(), true);
    //
    //     let ab = AlipaySdkConfigBuilder::new("111".to_string(), PRIVATE_KEY.to_string())
    //         .with_alipay_public_key("alipay_public_key".to_owned());
    //     let config = ab.build();
    //     assert_eq!(config.is_ok(), true);
    // }

    #[test]
    fn format_key() {
        let no_wrapper_private_key =
            fs::read("examples/fixtures/app-private-key-no-wrapper.pem").unwrap();
        let no_wrapper_public_key =
            fs::read("examples/fixtures/app-public-key-no-wrapper.pem").unwrap();

        let public_key = String::from_utf8(no_wrapper_public_key).unwrap();

        let sdk_config = AlipaySdkConfigBuilder::new("111".to_string(), PRIVATE_KEY.to_string())
            .with_alipay_public_key(public_key.clone())
            .build();

        assert_eq!(
            sdk_config.private_key,
            format!(
                "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----",
                String::from_utf8(no_wrapper_private_key).unwrap()
            )
        );
        assert_eq!(
            sdk_config.alipay_public_key,
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
                public_key,
            ),
        )
    }

    #[test]
    fn format_key_with_pkcs8() {
        let pkcs8_private_key = String::from_utf8(
            fs::read("examples/fixtures/app-private-key-pkcs8-no-wrapper.pem").unwrap(),
        )
        .unwrap();

        let sdk_config = AlipaySdkConfigBuilder::new("111".to_string(), pkcs8_private_key.clone())
            .with_gateway(GATE_WAY.to_string())
            .with_key_type(super::KeyType::PKCS8)
            .with_alipay_public_key(ALIPAY_PUBLIC_KEY.to_string())
            .build();

        assert_eq!(
            sdk_config.private_key,
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
                pkcs8_private_key,
            )
        );
    }

    // #[test]
    // fn execute() {
    //     let sdk_config = AlipaySdkConfigBuilder::new(APP_ID.to_string(), PRIVATE_KEY.to_string())
    //         .with_gateway(GATE_WAY.to_string())
    //         .with_sign_type(super::SignType::RSA2)
    //         .with_alipay_public_key(ALIPAY_PUBLIC_KEY.to_string())
    //         .with_timeout(Duration::from_millis(10000))
    //         .with_encrypt_key("aYA0GP8JEW+D7/UFaskCWA==".to_string())
    //         .enable_camelcase()
    //         .build()
    //         .unwrap();
    //
    //     let sdk = AlipaySDK::new(sdk_config);
    //
    //     let res = sdk.exec(
    //         "alipay.security.risk.content.analyze".to_string(),
    //         super::ExecParams {
    //             form_data: None,
    //             params: json!({
    //                         "bizContent": {
    //               "account_type": "MOBILE_NO",
    //               "account": "13812345678",
    //               "version": "2.0",
    //             }
    //             })
    //             .as_object()
    //             .unwrap()
    //             .clone(),
    //             need_encrypt: false,
    //             validate_sign: false,
    //         },
    //     );
    //     assert_eq!(res.unwrap_err().to_string(), "");
    // }
}
