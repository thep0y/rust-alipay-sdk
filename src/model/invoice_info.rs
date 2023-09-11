use serde::{Deserialize, Serialize};

use super::invoice_key_info::InvoiceKeyInfo;

/// 开票信息
#[derive(Serialize, Deserialize, Debug)]
pub struct InvoiceInfo {
    /// 开票关键信息
    key_info: InvoiceKeyInfo,
    /// 开票内容。json数组格式
    details: String,
}

impl InvoiceInfo {
    pub fn new<S: Into<String>>(key_info: InvoiceKeyInfo, details: S) -> Self {
        Self {
            key_info,
            details: details.into(),
        }
    }
}
