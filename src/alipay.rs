use std::{
    path::Path,
    time::{self, Duration},
};

use rsa::{
    pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey, sha2::Sha256, Pkcs1v15Sign, RsaPrivateKey,
};
use serde_json::Value;
use sha1::Sha1;
use urlencoding::{decode, encode};

use crate::{
    antcertutil::{get_sn, get_sn_from_path, load_public_key, load_public_key_from_path},
    error::{AlipayResult, Error, HttpError},
    form::{AlipayForm, IField, IFile, Method},
    time::now,
    util::{
        aes_decrypt, base64_decode, keys_to_camel_case, sign, value_to_string, verify_with_rsa,
    },
    AlipaySdkCommonResult, ParamsMap,
};

// const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
pub enum SignType {
    RSA,
    RSA2,
}

impl Default for SignType {
    fn default() -> Self {
        SignType::RSA2
    }
}

impl SignType {
    pub fn to_str(&self) -> &str {
        match self {
            SignType::RSA => "RSA",
            SignType::RSA2 => "RSA2",
        }
    }

    pub fn to_string(&self) -> String {
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

    pub fn signature(&self) -> Pkcs1v15Sign {
        match self {
            SignType::RSA => Pkcs1v15Sign::new::<Sha1>(),
            _ => Pkcs1v15Sign::new::<Sha256>(),
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

    pub fn deserialize_rsa_private_key(&self, private_key: &str) -> AlipayResult<RsaPrivateKey> {
        match self {
            KeyType::PKCS1 => RsaPrivateKey::from_pkcs1_pem(private_key).map_err(|e| {
                error!("反序列化私钥出错: {}", e);
                Error::Sign(e.to_string())
            }),
            KeyType::PKCS8 => RsaPrivateKey::from_pkcs8_pem(private_key).map_err(|e| {
                error!("反序列化私钥出错: {}", e);
                Error::Sign(e.to_string())
            }),
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
    alipay_public_key: Option<String>,
    gateway: String,
    timeout: time::Duration,
    camelcase: bool,
    pub charset: String,
    pub version: String,
    pub key_type: KeyType,
    pub app_cert_sn: String,
    pub alipay_root_cert_sn: String,
    // alipay_cert_sn: String,
    pub encrypt_key: String,
    pub ws_service_url: String,
}

impl AlipaySdkConfig {
    pub fn private_key(&self) -> &str {
        &self.private_key
    }

    pub fn alipay_public_key(&self) -> Option<&str> {
        self.alipay_public_key.as_deref()
    }
}

#[derive(Default)]
pub struct AlipaySdkBuilder {
    /// 应用 id
    app_id: String,
    /// 应用私钥字符串。RSA签名验签工具：https://docs.open.alipay.com/291/106097）
    private_key: String,
    /// 签名种类
    sign_type: SignType,
    /// 支付宝公钥（需要对返回值做验签时候必填）
    alipay_public_key: Option<String>,
    gateway: String,
    timeout: time::Duration,
    camelcase: bool,
    key_type: KeyType,
    app_cert_sn: String,
    alipay_root_cert_sn: String,
    alipay_cert_sn: String,
    encrypt_key: String,
    ws_service_url: String,
}

impl AlipaySdkBuilder {
    pub fn new(app_id: String, private_key: String) -> Self {
        AlipaySdkBuilder {
            app_id,
            private_key,
            sign_type: Default::default(),
            alipay_public_key: Default::default(),
            gateway: Default::default(),
            timeout: Default::default(),
            camelcase: Default::default(),
            key_type: Default::default(),
            app_cert_sn: Default::default(),
            alipay_root_cert_sn: Default::default(),
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
        self.alipay_public_key = Some(Self::format_key(&alipay_public_key, "PUBLIC KEY"));
        Ok(self)
    }

    pub fn with_alipay_public_cert_path<P: AsRef<Path>>(
        mut self,
        file_path: P,
    ) -> AlipayResult<Self> {
        self.alipay_cert_sn = get_sn_from_path(file_path.as_ref(), false)?;
        let alipay_public_key = load_public_key_from_path(file_path)?;
        self.alipay_public_key = Some(Self::format_key(&alipay_public_key, "PUBLIC KEY"));
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
        self.alipay_public_key = Some(Self::format_key(&alipay_public_key, "PUBLIC KEY"));
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

    fn split_string_into_chunks(input: &str, chunk_size: usize) -> Vec<String> {
        let mut chunks = Vec::new();
        let mut start = 0;

        while start < input.len() {
            let end = start + chunk_size;
            if end >= input.len() {
                chunks.push(input[start..].to_string());
            } else {
                chunks.push(input[start..end].to_string());
            }
            start = end;
        }

        chunks
    }

    /// 格式化 key
    pub fn format_key(key: &str, key_type: &str) -> String {
        let key = key.trim();

        if key.is_empty() {
            return key.to_string();
        }

        let mut item: Vec<&str> = key.split("\n").into_iter().map(|s| s.trim()).collect();

        if item[0].contains(key_type) {
            item.remove(0);
        }

        if item[item.len() - 1].contains(key_type) {
            item.pop();
        }

        let data = item[0];
        let lines = Self::split_string_into_chunks(data, 64);

        format!(
            "-----BEGIN {}-----\n{}\n-----END {}-----",
            key_type,
            lines.join("\n"),
            key_type
        )
    }

    pub fn build(self) -> AlipaySDK {
        // if self.alipay_public_key.is_empty() {
        //     return Err(Error::Config("alipay_public_key 不能为空".to_string()));
        // }

        let private_key = Self::format_key(&self.private_key, self.key_type.to_str());
        if self.timeout == Duration::new(0, 0) {}

        let config = AlipaySdkConfig {
            app_id: self.app_id,
            private_key,
            sign_type: self.sign_type,
            alipay_public_key: self.alipay_public_key,
            gateway: self.gateway,
            timeout: if self.timeout == Duration::new(0, 0) {
                Duration::new(5, 0)
            } else {
                self.timeout
            },
            camelcase: self.camelcase,
            charset: "utf-8".to_string(),
            version: "1.0.0".to_string(),
            key_type: self.key_type,
            app_cert_sn: self.app_cert_sn,
            alipay_root_cert_sn: self.alipay_root_cert_sn,
            // alipay_cert_sn: self.alipay_cert_sn,
            encrypt_key: self.encrypt_key,
            ws_service_url: self.ws_service_url,
        };

        AlipaySDK::new(config)
    }
}

#[derive(Debug)]
pub enum AlipaySdkResult {
    Common(AlipaySdkCommonResult),
    String(String),
}

#[derive(Debug)]
pub struct AlipaySDK {
    sdk_version: String,
    pub config: AlipaySdkConfig,
}

impl AlipaySDK {
    pub fn new(config: AlipaySdkConfig) -> Self {
        Self {
            config,
            sdk_version: "1.0.0".to_string(),
        }
    }

    /// 格式化请求 url（按规范把某些固定的参数放入 url）
    fn format_url(url: &str, params: ParamsMap) -> (ParamsMap, String) {
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
            let val = value_to_string(&params[key.to_owned()]);
            let val = encode(&val);

            if request_url.contains("?") {
                request_url += &format!("&{}={}", key, val);
            } else {
                request_url += &format!("?{}={}", key, val);
            }
        }

        params.retain(|key, _value| !keys_to_remove.contains(&key));

        (params, request_url)
    }

    pub fn set_alipay_public_key(&mut self, alipay_public_key: String) {
        self.config.alipay_public_key = Some(AlipaySdkBuilder::format_key(
            &alipay_public_key,
            "PUBLIC KEY",
        ));
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
        trace!("sdk request data: {:?}", data);

        let sdk_str = data
            .iter()
            .map(|(k, v)| format!("{}={}", k, encode(&v.to_string())))
            .collect::<Vec<String>>()
            .join("&");

        Ok(sdk_str)
    }

    /// 生成网站接口请求链接或表单
    pub fn page_exec(&self, method: String, params: ParamsMap) -> AlipayResult<String> {
        let mut form_data = AlipayForm::new();
        for (k, v) in params.iter() {
            if k == "method" {
                form_data.set_method(Method::from_string(&v.to_string()));
            } else {
                form_data.add_field(k.clone(), v.clone());
            }
        }

        self._page_exec(method, form_data)
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

            trace!("params: {}", query);

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
        alipay_public_key: &str,
        sign_args: &ParamsMap,
        sign_str: &str,
        sign_type: &SignType,
    ) -> AlipayResult<()> {
        let mut keys = sign_args.keys().collect::<Vec<&String>>();
        keys.sort();

        let mut queries = Vec::with_capacity(keys.len());

        for key in keys.iter() {
            let value = &sign_args[&key.to_string()];

            // js 中如果 value 中包含了诸如 % 字符，decodeURIComponent 会报错
            // 而且 notify 消息大部分都是 post 请求，无需进行 decodeURIComponent 操作，
            // rust 中无此问题，故不需要传入 raw 参数
            let v = decode(&value_to_string(value))?.into_owned();

            let query = format!("{}={}", key, v);

            trace!("query: {}", query);

            queries.push(query);
        }

        debug!("queries: {:?}", queries);

        let sign_content = queries.join("&");

        verify_with_rsa(
            sign_content.as_bytes(),
            alipay_public_key,
            &base64_decode(sign_str)?,
            sign_type.signature(),
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
        validate_str = &validate_str[..validate_str.rfind("}").unwrap_or(0) + 1];

        validate_str.to_owned()
    }

    pub fn exec(&self, method: String, params: ExecArgs) -> AlipayResult<AlipaySdkResult> {
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

        trace!("exec_params: {:?}", exec_params);
        trace!("url: {}", url);

        let resp = ureq::post(&url)
            .set("user-agent", &self.sdk_version)
            .timeout(self.config.timeout)
            .send_json(exec_params)?;

        if resp.status() != 200 {
            return Err(Error::Http(HttpError::new(
                resp.into_json()?,
                "[AlipaySdk]HTTP 请求错误",
            )));
        }

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
                serde_json::from_value(json).unwrap(),
                "[AlipaySdk]响应体为空",
            )));
        };

        let response_key = method.replace(".", "_") + "_response";
        let mut data = match result.get(&response_key) {
            Some(d) => d.clone(),
            None => {
                return Err(Error::Http(HttpError::new(
                    serde_json::from_value(json).unwrap(),
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
            self.check_response_sign(&json.to_string(), &response_key)?
        } else {
            true
        };

        if !validate_success {
            return Err(Error::Http(HttpError::new(
                serde_json::from_value(json).unwrap(),
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
    fn check_response_sign(&self, sign_str: &str, response_key: &str) -> AlipayResult<bool> {
        match &self.config.alipay_public_key {
            None => Ok(true), // 支付宝公钥不存在时不做验签
            Some(alipay_public_key) => {
                trace!("alipay public key :{}", alipay_public_key);
                if alipay_public_key.is_empty() {
                    // 支付宝公钥不存在时不做验签
                    return Ok(true);
                }
                // 带验签的参数不存在时返回失败
                if sign_str.is_empty() {
                    return Ok(false);
                }

                trace!("response key: {}", response_key);

                // 根据服务端返回的结果截取需要验签的目标字符串
                let validate_str = Self::get_sign_str(sign_str, response_key);
                debug!("validate str: {}", validate_str);

                // 服务端返回的签名
                let sign_value = serde_json::from_str::<Value>(sign_str).unwrap();
                let server_sign_base64 = sign_value.get("sign").unwrap();
                trace!("server sign: {}", server_sign_base64);

                let server_sign = base64_decode(&value_to_string(server_sign_base64))?;

                // 参数存在，并且是正常的结果（不包含 sub_code）时才验签
                match verify_with_rsa(
                    validate_str.as_bytes(),
                    &alipay_public_key,
                    &server_sign,
                    self.config.sign_type.signature(),
                ) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
        }
    }

    pub fn check_notify_sign(&self, post_data: &ParamsMap) -> bool {
        match &self.config.alipay_public_key {
            None => false, // 未设置“支付宝公钥”或签名字符串不存，验签不通过
            Some(alipay_public_key) => {
                // 未设置“支付宝公钥”或签名字符串不存，验签不通过
                if alipay_public_key.is_empty() {
                    return false;
                }

                let sign_str = match post_data.get("sign") {
                    Some(s) => value_to_string(s),
                    None => return false,
                };
                // 未设置“支付宝公钥”或签名字符串不存，验签不通过
                if sign_str.is_empty() {
                    return false;
                }

                trace!("sign str: {}", sign_str);

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

                let sign_type = SignType::from_str(&value_to_string(&sign_type));

                // 保留 sign_type 验证一次签名
                let verify_result =
                    self.notify_rsa_check(&alipay_public_key, &sign_args, &sign_str, &sign_type);

                if verify_result.is_ok() {
                    return true;
                }

                // 删除 sign_type 验一次
                // 因为“历史原因”需要用户自己判断是否需要保留 sign_type 验证签名
                // 这里是把其他 sdk 中的 rsaCheckV1、rsaCheckV2 做了合并
                sign_args.remove("sign_type");
                match self.notify_rsa_check(&alipay_public_key, &sign_args, &sign_str, &sign_type) {
                    Ok(()) => true,
                    Err(_) => false,
                }
            }
        }
    }
}

#[derive(Default)]
pub struct ExecArgs {
    form_data: Option<AlipayForm>,
    params: ParamsMap,
    need_encrypt: bool,
    validate_sign: bool,
}

impl ExecArgs {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_params(mut self, params: ParamsMap) -> Self {
        self.params = params;
        self
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;

    use super::{AlipaySDK, AlipaySdkBuilder};

    const PRIVATE_KEY: &str = include_str!("../examples/fixtures/app-private-key.pem");
    const ALIPAY_PUBLIC_KEY: &str = include_str!("../examples/fixtures/alipay-public-key.pem");

    const APP_ID: &str = "9021000126650292";
    const GATE_WAY: &str = "https://openapi-sandbox.dl.alipaydev.com/gateway.do";

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

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

    fn join_multilines(input: &str) -> String {
        input.split("\n").collect::<Vec<&str>>().join("")
    }

    #[test]
    fn format_key() {
        init();

        let no_wrapper_private_key =
            fs::read("examples/fixtures/app-private-key-no-wrapper.pem").unwrap();
        let no_wrapper_public_key =
            fs::read("examples/fixtures/app-public-key-no-wrapper.pem").unwrap();

        let public_key = String::from_utf8(no_wrapper_public_key).unwrap();

        let sdk = AlipaySdkBuilder::new("111".to_string(), PRIVATE_KEY.to_string())
            .with_alipay_public_key(public_key.clone())
            .build();

        assert_eq!(
            join_multilines(&sdk.config.private_key),
            join_multilines(&format!(
                "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----",
                String::from_utf8(no_wrapper_private_key).unwrap()
            ))
        );
        assert_eq!(
            join_multilines(&sdk.config.alipay_public_key.unwrap()),
            join_multilines(&format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
                public_key,
            )),
        )
    }

    #[test]
    fn format_key_with_pkcs8() {
        init();

        let pkcs8_private_key = String::from_utf8(
            fs::read("examples/fixtures/app-private-key-pkcs8-no-wrapper.pem").unwrap(),
        )
        .unwrap();

        let sdk = AlipaySdkBuilder::new("111".to_string(), pkcs8_private_key.clone())
            .with_gateway(GATE_WAY.to_string())
            .with_key_type(super::KeyType::PKCS8)
            .with_alipay_public_key(ALIPAY_PUBLIC_KEY.to_string())
            .build();

        assert_eq!(
            join_multilines(&sdk.config.private_key),
            join_multilines(&format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
                pkcs8_private_key,
            ))
        );
    }

    // fn new_sdk() -> AlipaySDK {
    //     let sdk = AlipaySdkBuilder::new(APP_ID.to_string(), PRIVATE_KEY.to_string())
    //         .with_gateway(GATE_WAY.to_string())
    //         .with_sign_type(super::SignType::RSA2)
    //         .with_alipay_public_key(ALIPAY_PUBLIC_KEY.to_string())
    //         .with_timeout(Duration::from_millis(10000))
    //         .with_encrypt_key("aYA0GP8JEW+D7/UFaskCWA==".to_string())
    //         .enable_camelcase()
    //         .build();
    //
    //     sdk
    // }

    // #[test]
    // fn test_camelcase() {
    //     init();
    //
    //     let sdk = new_sdk();
    //
    //     let res = sdk.exec(
    //         "alipay.security.risk.content.analyze".to_string(),
    //         super::ExecParams {
    //             form_data: None,
    //             params: json!({
    //               "bizContent": {
    //                 "account_type": "MOBILE_NO",
    //                 "account": "13812345678",
    //                 "version": "2.0",
    //               },
    //               "publicArgs": {}
    //             })
    //             .as_object()
    //             .unwrap()
    //             .clone(),
    //             need_encrypt: false,
    //             validate_sign: true,
    //         },
    //     );
    //     assert_eq!(res.unwrap_err().to_string(), "");
    // }

    #[test]
    fn test_check_response_sign_alipay_public_key_is_null() {
        init();

        let sdk = AlipaySdkBuilder::new(APP_ID.to_string(), PRIVATE_KEY.to_string())
            .with_gateway(GATE_WAY.to_string())
            // .with_alipay_public_key(ALIPAY_PUBLIC_KEY.to_string())
            .enable_camelcase()
            .build();

        let sign_str = r#"{"alipay_offline_material_image_upload_response":{"code":"10000","msg":"Success","image_id":"1ni-WScMQcWsJRE2AYCo9AAAACMAAQED","image_url":"http:\/\/oalipay-dl-django.alicdn.com\/rest\/1.0\/image?fileIds=1ni-WScMQcWsJRE2AYCo9AAAACMAAQED&zoom=original"},"sign":"K7s88WHQO91LPY+QGbdRtr3rXQWUxDEKvPrVsLfy+r9R4CSK1qbvHkrJ9DXwzm0pdTQPP8xbLl6rSsOiq33f32ZOhX/XzMbOfiC3OLnHHVaH7+rneNopUj1sZQDvz+dUoIMYSQHFLEECKADiJ66S8i5gXD1Hne7aj0b/1LYGPhtxbJdkT8OTDjxd/X/HmVy5xjZShOnM3WcwxUVNyqdOE2BEZbS8Q8P4W20PP/EhZ31N4mOIsCuUNiikhU0tnwjH2pHcv/fh7wzqkEhn1gIHc13o9O7xi4w1hHdQV811bn+n8d+98o+ETClebBQieqA+irBQaXvYTmZi3H+8RJiGwA=="}"#;

        let result =
            sdk.check_response_sign(sign_str, "alipay_offline_material_image_upload_response");

        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_check_response_sign_alipay_public_key_is_empty() {
        init();

        let sdk = AlipaySdkBuilder::new(APP_ID.to_string(), PRIVATE_KEY.to_string())
            .with_gateway(GATE_WAY.to_string())
            .with_alipay_public_key(String::new())
            .enable_camelcase()
            .build();

        let sign_str = r#"{"alipay_offline_material_image_upload_response":{"code":"10000","msg":"Success","image_id":"1ni-WScMQcWsJRE2AYCo9AAAACMAAQED","image_url":"http:\/\/oalipay-dl-django.alicdn.com\/rest\/1.0\/image?fileIds=1ni-WScMQcWsJRE2AYCo9AAAACMAAQED&zoom=original"},"sign":"K7s88WHQO91LPY+QGbdRtr3rXQWUxDEKvPrVsLfy+r9R4CSK1qbvHkrJ9DXwzm0pdTQPP8xbLl6rSsOiq33f32ZOhX/XzMbOfiC3OLnHHVaH7+rneNopUj1sZQDvz+dUoIMYSQHFLEECKADiJ66S8i5gXD1Hne7aj0b/1LYGPhtxbJdkT8OTDjxd/X/HmVy5xjZShOnM3WcwxUVNyqdOE2BEZbS8Q8P4W20PP/EhZ31N4mOIsCuUNiikhU0tnwjH2pHcv/fh7wzqkEhn1gIHc13o9O7xi4w1hHdQV811bn+n8d+98o+ETClebBQieqA+irBQaXvYTmZi3H+8RJiGwA=="}"#;

        let result =
            sdk.check_response_sign(sign_str, "alipay_offline_material_image_upload_response");

        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_check_response_sign_sign_str_is_empty() {
        init();

        let sdk = AlipaySdkBuilder::new(APP_ID.to_string(), PRIVATE_KEY.to_string())
            .with_gateway(GATE_WAY.to_string())
            .with_alipay_public_key(ALIPAY_PUBLIC_KEY.to_string())
            .enable_camelcase()
            .build();

        let sign_str = "";

        let result =
            sdk.check_response_sign(sign_str, "alipay_offline_material_image_upload_response");

        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_check_response_sign_normal() {
        init();

        let sdk = AlipaySdkBuilder::new(APP_ID.to_string(), PRIVATE_KEY.to_string())
            .with_gateway(GATE_WAY.to_string())
            .with_alipay_public_key(ALIPAY_PUBLIC_KEY.to_string())
            .enable_camelcase()
            .build();

        let sign_str = r#"{"alipay_open_file_upload_response":{"code":"10000","msg":"Success","file_id":"CAxAToWB1JsAAAAAAAAAAAAADgSLAQBr"},"sign":"F+LDzpTNiavn7xVZPGuPCSSVRSmWzJGgtuji6tVELGEaqMaNj0jRKXUEr5nloZJBBmwEnddOyCjjepMmrTKTvoOqQ0Efxpr/R1iEeHTHVbb/Q8TTh6Up5gHJDkILdaWS2q1cWeQ6VT+HQY9P3WRXS7uhILHuDODIhpAyCu5KhWGt0rMCIG+Im6NODJP2oohtSCtmTFXg58HH587Z2y2bdbjzOxLvzD9IrU1imghXQ2S/Q+wMIvRk9on6cWnBLkrNvJKapA2ReNGWOwyuASvB9zDVzhMPbR+3mfRGkVDxsq5HYLjBKGskJMXHw0HuugZij6ScRuaLPODhmHwr/pJ9yw=="}"#;

        let result = sdk.check_response_sign(sign_str, "alipay_open_file_upload_response");

        assert_eq!(result.unwrap(), true);
    }

    fn new_check_notify_sign_sdk() -> AlipaySDK {
        let notify_alipay_public_key_v2 = String::from_utf8(
            fs::read("examples/fixtures/alipay-notify-sign-public-key-v2.pem").unwrap(),
        )
        .unwrap();
        let sdk = AlipaySdkBuilder::new(APP_ID.to_string(), PRIVATE_KEY.to_string())
            .with_gateway(GATE_WAY.to_string())
            .with_alipay_public_key(notify_alipay_public_key_v2)
            .enable_camelcase()
            .build();
        sdk
    }

    #[test]
    fn test_check_notify_sign_alipay_public_key_is_null() {
        let mut sdk = new_check_notify_sign_sdk();
        sdk.config.alipay_public_key = None;

        let result = sdk.check_notify_sign(json!({}).as_object().unwrap());

        assert_eq!(result, false);
    }

    #[test]
    fn test_check_notify_sign_sign_is_null() {
        let sdk = new_check_notify_sign_sdk();

        let result = sdk.check_notify_sign(json!({}).as_object().unwrap());

        assert_eq!(result, false);
    }

    #[test]
    fn test_check_notify_sign_with_sign_type() {
        let sdk = new_check_notify_sign_sdk_should_delete_sign_type();

        let post_data = json!({"gmt_create":"2019-08-15 15:56:22","charset":"utf-8","seller_email":"z97-yuquerevenue@service.aliyun.com","subject":"语雀空间 500人规模","sign":"QfTb8tqE1BMhS5qAnXtvsF3/jBkEvu9q9en0pdbBUDDjvKycZhQb7h8GDs4FKfi049PynaNuatxSgLb/nLWZpXyyh0LEWdK2S6Ri7nPwrVgOs08zugLO20vOQz44y3ti2Ncm8/wZts1Fr2gZ7pShnVX3d1B50hbsXnObT1r/U8ONNQjWXd0HIul4TG+Q3fm3svmSvFEy0WnzuhcyHPX5Gm4ELNctL6Qd5YniGJFNcc7kopHYtI/XD9YCKCH6Ct02rzUs9i11C9CsadtZn+WhxF26Dqt9sGEFajkJ8cxUTLi8+VCpLHsgPE8P0y095uQcDdK0YjCh4x7wVSov+lrmOQ==","buyer_id":"2088102534368455","invoice_amount":"0.10","notify_id":"2019081500222155624068450559358070","fund_bill_list":[{"amount":"0.10","fundChannel":"ALIPAYACCOUNT"}],"notify_type":"trade_status_sync","trade_status":"TRADE_SUCCESS","receipt_amount":"0.10","buyer_pay_amount":"0.10","sign_type":"RSA2","app_id":"2019073166072302","seller_id":"2088531891668739","gmt_payment":"2019-08-15 15:56:24","notify_time":"2019-08-15 15:56:25","version":"1.0","out_trade_no":"20190815155618536-564-57","total_amount":"0.10","trade_no":"2019081522001468450512505578","auth_app_id":"2019073166072302","buyer_logon_id":"xud***@126.com","point_amount":"0.00"});

        let result = sdk.check_notify_sign(post_data.as_object().unwrap());

        assert_eq!(result, true);
    }

    fn new_check_notify_sign_sdk_should_delete_sign_type() -> AlipaySDK {
        let notify_alipay_public_key_v1 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqObrdC7hrgAVM98tK0nv3hSQRGGKT4lBsQjHiGjeYZjOPIPHR5knm2jnnz/YGIXIofVHkA/tAlBAd5DrY7YpvI4tP5EONLtZKC2ghBMx7McI2wRD0xiqzxOQr1FuhZGJ8/AUokBzJrzY+aGX2xcOrxFYRlFilvVLTXg4LWjR1tdPkO6+i7wQZAIVMClPkwVRZEbaERRHlKqTzv2gGv5rDU8gRoe1LeaN+6BlbTqHWkQcNCUNrA8C6l17XAXGKDsm/9TFWwO8EPHHHCaQdjtV5/FdcWIt+L8SR1ss7EXTjYDFtxcKVv9rEoY1lX8T4mX+GbXfZHraG5NCF1+XioL5JwIDAQAB";

        let mut sdk = new_check_notify_sign_sdk();
        sdk.set_alipay_public_key(notify_alipay_public_key_v1.to_string());

        sdk
    }

    #[test]
    fn test_check_notify_sign_without_sign_type() {
        let sdk = new_check_notify_sign_sdk_should_delete_sign_type();

        let post_data = json!({"gmt_create":"2019-08-15 15:56:22","charset":"utf-8","seller_email":"z97-yuquerevenue@service.aliyun.com","subject":"语雀空间 500人规模","sign":"QfTb8tqE1BMhS5qAnXtvsF3/jBkEvu9q9en0pdbBUDDjvKycZhQb7h8GDs4FKfi049PynaNuatxSgLb/nLWZpXyyh0LEWdK2S6Ri7nPwrVgOs08zugLO20vOQz44y3ti2Ncm8/wZts1Fr2gZ7pShnVX3d1B50hbsXnObT1r/U8ONNQjWXd0HIul4TG+Q3fm3svmSvFEy0WnzuhcyHPX5Gm4ELNctL6Qd5YniGJFNcc7kopHYtI/XD9YCKCH6Ct02rzUs9i11C9CsadtZn+WhxF26Dqt9sGEFajkJ8cxUTLi8+VCpLHsgPE8P0y095uQcDdK0YjCh4x7wVSov+lrmOQ==","buyer_id":"2088102534368455","invoice_amount":"0.10","notify_id":"2019081500222155624068450559358070","fund_bill_list":[{"amount":"0.10","fundChannel":"ALIPAYACCOUNT"}],"notify_type":"trade_status_sync","trade_status":"TRADE_SUCCESS","receipt_amount":"0.10","buyer_pay_amount":"0.10","app_id":"2019073166072302","seller_id":"2088531891668739","gmt_payment":"2019-08-15 15:56:24","notify_time":"2019-08-15 15:56:25","version":"1.0","out_trade_no":"20190815155618536-564-57","total_amount":"0.10","trade_no":"2019081522001468450512505578","auth_app_id":"2019073166072302","buyer_logon_id":"xud***@126.com","point_amount":"0.00"});

        let result = sdk.check_notify_sign(post_data.as_object().unwrap());

        assert_eq!(result, true);

        // let post_data = json!({"app_id":"2017122801303261","charset":"UTF-8","commodity_order_id":"2019030800000018079639","contactor":"技术支持测试的公司","merchant_pid":"2088721996721370","method":"alipay.open.servicemarket.order.notify","name":"技术支持测试的公司","notify_id":"2019030800222102023008121054923345","notify_time":"2019-03-08 10:20:23","notify_type":"servicemarket_order_notify","order_item_num":"1","order_ticket":"29b1c37d99ab48c5bd5bdaeaeaefbB37","order_time":"2019-03-08 10:20:08","phone":"17826894615","service_code":"58621634","sign":"MsK5SCw8oqLw4f0hiNSd5OVGXxBY3wnQeT8vn5PklJSZFWSZbK4hQbNvkp4ZezeXQH514cEv0ul6Qow8yh6e6yM06LfEL+EZjcpZ0nxzFGRNQ5qq2AUc1OaXQdk92AGvxh+Iq4NGpPQFBd4D8EBJa3NJd8+czMfQskceosOQFqUtLQMYa5DPs+VpN7VM5BdXjaVIuKn5d9Wm2B9dI9ObIM+YRySDkZZPv14DVmUvcrcqJfOR8aHvtSd7B4l92wUQPQgQKNcOQho7xOHS/Bk+Y74AZL2y7TkNmdDoq9OGsThuF5tDW9rI9nVwXxOtsuB+bstra+W7aw9x9DvkKgdSRw==","sign_type":"RSA2","timestamp":"2019-03-08 10:20:23","title":"麦禾商城模版","total_price":"0.00","version":"1.0"});
        //
        // let result = sdk.check_notify_sign(post_data.as_object().unwrap());
        //
        // assert_eq!(result, true);
    }

    #[test]
    fn test_check_notify_sign_verify_fail() {
        let sdk = new_check_notify_sign_sdk_should_delete_sign_type();

        let post_data = json!({"app_id":"2018121762595097","auth_app_id":"2false8121762595097","buyer_id":"2088512613526436","buyer_logon_id":"152****6706","buyer_pay_amount":"0.01","charset":"utf-8","fund_bill_list":[{"amount":"0.01","fundChannel":"PCREDIT"}],"gmt_create":"2019-05-23 14:13:56","gmt_payment":"2019-05-23 14:17:13","invoice_amount":"0.01","notify_id":"2019052300222141714026431019971405","notify_time":"2019-05-23 14:17:14","notify_type":"trade_status_sync","out_trade_no":"tpxy23962362669658","point_amount":"0.00","receipt_amount":"0.01","seller_email":"myapp@alitest.com","seller_id":"2088331578818800","sign":"T946S2qyNFAXLhAaRgNMmatxH6SO3MyWYFnTamQOgW1iAcheL/Zz+VoizwvEc6mTEwYewvvKS1wNkMQ1oEajMUHv9+cXQ9IFvU/qKS9Ktvw5xHvCaK0fj7LsVcQ7VxfyT3kSvXUDfKDP4cHSPuSZKwM2ybkzr53bIH9OUTpTQd2d3J0rbdf76OoUt+XF9vwqj7OVE7AGjH2HPWp842DgL/YVy4qeA9N2uFKRevT3YUskjaRxuI/E66reNjTMFhbjEqGLKvMcDD4BaQXnibq9ojAj60589fBwzKk3yWsVQmqGfksMQoheVMtZ3lAw4o2ty3TFngbVFFLwgx8FDpBZ9Q==","sign_type":"RSA2","subject":"tpxy2222896485","total_amount":"0.01","trade_no":"111111112019052322001426431037869358","trade_status":"TRADE_SUCCESS","version":"1.0"});

        let result = sdk.check_notify_sign(post_data.as_object().unwrap());

        assert_eq!(result, false);
    }

    // fn new_pkcs8_sdk() -> AlipaySDK {
    //     let pkcs8_private_key =
    //         String::from_utf8(fs::read("examples/fixtures/app-private-key-pkcs8.pem").unwrap())
    //             .unwrap();
    //     let sdk = AlipaySdkBuilder::new(APP_ID.to_string(), pkcs8_private_key)
    //         .with_gateway(GATE_WAY.to_string())
    //         .with_sign_type(super::SignType::RSA2)
    //         .with_alipay_public_key(ALIPAY_PUBLIC_KEY.to_string())
    //         .with_timeout(Duration::from_millis(10000))
    //         .with_key_type(super::KeyType::PKCS8)
    //         .enable_camelcase()
    //         .build();
    //
    //     sdk
    // }

    // #[test]
    // fn test_pkcs8_with_validate_sign_is_true() {
    //     let sdk = new_pkcs8_sdk();
    //
    //     let result = sdk
    //         .exec(
    //             "alipay.offline.market.shop.category.query".to_string(),
    //             ExecArgs::new().with_params(json!({"bizContent":{}}).as_object().unwrap().clone()),
    //         )
    //         .unwrap();
    //
    //     match result {
    //         AlipaySdkResult::Common(cr) => {
    //             debug!("response: {:?}", cr);
    //             assert_eq!(cr.code, "10000");
    //         }
    //         _ => {}
    //     }
    // }
}
