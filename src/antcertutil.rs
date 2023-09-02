use base64::{engine::general_purpose, Engine};
use std::{fs, path::Path};
use x509_parser::prelude::*;

use crate::error::{AlipayResult, Error};

/// 从公钥证书文件里读取支付宝公钥
pub(crate) fn load_public_key_from_path<P: AsRef<Path>>(file_path: P) -> AlipayResult<String> {
    let file_data = fs::read(file_path)?;
    let (_, cert) =
        X509Certificate::from_der(&file_data).map_err(|e| Error::X509(e.to_string()))?;
    let encoded: String = general_purpose::STANDARD_NO_PAD.encode(cert.public_key().raw);

    Ok(encoded)
}

/// 从公钥证书内容或buffer读取支付宝公钥
pub(crate) fn load_public_key<B: AsRef<[u8]>>(content: B) -> AlipayResult<String> {
    let (_, cert) =
        X509Certificate::from_der(content.as_ref()).map_err(|e| Error::X509(e.to_string()))?;
    let encoded: String = general_purpose::STANDARD_NO_PAD.encode(cert.public_key().raw);

    Ok(encoded)
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
