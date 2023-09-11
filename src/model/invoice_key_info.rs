use serde::{Deserialize, Serialize};

/// 开票关键信息
#[derive(Serialize, Deserialize, Debug)]
pub struct InvoiceKeyInfo {
    /// 该交易是否支持开票
    is_support_invoice: bool,
    /// 开票商户名称：商户品牌简称|商户门店简称
    invoice_merchant_name: String,
    /// 税号
    tax_num: String,
}

impl InvoiceKeyInfo {
    pub fn new<S: Into<String>>(
        is_support_invoice: bool,
        invoice_merchant_name: S,
        tax_num: S,
    ) -> Self {
        Self {
            is_support_invoice,
            invoice_merchant_name: invoice_merchant_name.into(),
            tax_num: tax_num.into(),
        }
    }
}
