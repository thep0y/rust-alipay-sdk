use std::{fs, path::Path};
use x509_parser::pem::parse_x509_pem;

use crate::{
    error::{AlipayResult, Error},
    util::base64_encode,
};

/// 从公钥证书文件里读取支付宝公钥
pub(crate) fn load_public_key_from_path<P: AsRef<Path>>(file_path: P) -> AlipayResult<String> {
    let file_data = fs::read(file_path)?;
    load_public_key(file_data)
}

/// 从公钥证书内容或buffer读取支付宝公钥
pub(crate) fn load_public_key<B: AsRef<[u8]>>(content: B) -> AlipayResult<String> {
    let (_, cert) = parse_x509_pem(content.as_ref()).map_err(|e| {
        error!("{}", e);
        Error::X509(e.to_string())
    })?;

    let x509 = cert.parse_x509().map_err(|e| {
        error!("{}", e);
        Error::X509(e.to_string())
    })?;

    Ok(base64_encode(x509.public_key().raw))
}

pub(crate) fn get_sn_from_path<P: AsRef<Path>>(
    file_path: P,
    is_root: bool,
) -> AlipayResult<String> {
    let file_data = fs::read(file_path)?;
    get_sn(file_data, is_root)
}

/// 从上传的证书内容或Buffer读取序列号
pub(crate) fn get_sn(file_data: impl AsRef<[u8]>, is_root: bool) -> AlipayResult<String> {
    if is_root {
        return get_root_cert_sn(file_data.as_ref());
    }

    get_cert_sn(file_data)
}

/// 读取序列号
pub fn get_cert_sn(cert_content: impl AsRef<[u8]>) -> AlipayResult<String> {
    let cert_data = cert_content.as_ref();

    let (_, cert) = parse_x509_pem(cert_data).map_err(|e| Error::X509(e.to_string()))?;

    let x509 = cert.parse_x509().map_err(|e| Error::X509(e.to_string()))?;

    let mut name = x509.tbs_certificate.issuer().to_string();
    //提取出的证书的issuer本身是以CN开头的，则无需逆序，直接返回
    if !name.starts_with("CN") {
        let mut attributes: Vec<&str> = name.split(", ").collect();
        attributes.reverse();
        name = attributes.join(",");
    }
    let serial_number = x509.serial.to_str_radix(10);

    Ok(format!("{:x}", md5::compute(name + &serial_number)))
}

/// 读取根证书序列号
fn get_root_cert_sn(root_content: impl AsRef<[u8]>) -> AlipayResult<String> {
    let cert_end = "-----END CERTIFICATE-----";
    let certs_str = String::from_utf8(root_content.as_ref().to_vec())?;

    let pems = certs_str.split(cert_end);

    let mut root_cert_sn = String::new();

    for pem in pems.into_iter() {
        let cert_data = pem.to_owned() + cert_end;

        match parse_x509_pem(cert_data.as_bytes()) {
            Err(_) => continue,
            Ok((_, cert)) => {
                let x509 = cert.parse_x509().map_err(|e| Error::X509(e.to_string()))?;
                if !x509
                    .signature_algorithm
                    .algorithm
                    .to_id_string()
                    .starts_with("1.2.840.113549.1.1")
                {
                    continue;
                }

                let sn = get_cert_sn(&cert_data)?;

                if root_cert_sn.is_empty() {
                    root_cert_sn += &sn;
                } else {
                    root_cert_sn += &format!("_{}", sn);
                }
            }
        };
    }

    if root_cert_sn.is_empty() {
        return Err(Error::X509("无法获取证书序号，请检查证书".to_owned()));
    }

    Ok(root_cert_sn)
}

#[cfg(test)]
mod tests {
    use crate::error::AlipayResult;

    use super::{load_public_key, load_public_key_from_path};

    const ALIPAY_PUBLIC_CERT_PATH: &str = "examples/fixtures/alipayCertPublicKey_RSA2.crt";
    const PUBLIC_KEY_VAL: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhoVesfcGvUv1XvUndmX0rmSZ/2posJBCooySbSVFpV79RtHMzrVz2aKkC3WvOXeT5iNeQK4mK8gp3vNkWrHTkQGx5BcmkeO1WS384CQde7dAS0gmxeFs5bs+cCQqV2A2c2R9/5rJMtFtp1Ot/rIiMBUn6Ei0UoztM7AneavqQEzSwYlCKNhPFFtHCiz7u4O5R9CIyvUmYr+zpem2HXBN9ygPAZ0aXBQipGbc45+G07ZCNsmY4hV/Igya1aBf+Ye8p10Ew8uBBri0sIknhSC2LqKKy2IH1fO6q1d1jhN240QRHvbpRNv60kAfZsEulBASBrCMBi49NiJyr5nre7SNywIDAQAB";

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_load_public_key_from_path() -> AlipayResult<()> {
        init();

        let public_key = load_public_key_from_path(ALIPAY_PUBLIC_CERT_PATH)?;

        assert_eq!(public_key, PUBLIC_KEY_VAL);

        Ok(())
    }

    #[test]
    fn test_load_public_key() -> AlipayResult<()> {
        let cert = include_str!("../examples/fixtures/alipayCertPublicKey_RSA2.crt");

        let public_key = load_public_key(cert)?;

        assert_eq!(public_key, PUBLIC_KEY_VAL);

        Ok(())
    }
}
