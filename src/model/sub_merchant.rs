use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SubMerchant {
    merchant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    merchant_type: Option<String>,
}

impl SubMerchant {
    pub fn new() -> Self {
        SubMerchant::default()
    }

    pub fn get_merchant_id(&self) -> &str {
        self.merchant_id.as_ref()
    }

    pub fn set_merchant_id<S: Into<String>>(&mut self, merchant_id: S) {
        self.merchant_id = merchant_id.into();
    }

    pub fn get_merchant_type(&self) -> Option<&str> {
        return self.merchant_type.as_deref();
    }

    pub fn set_merchant_type<S: Into<String>>(&mut self, merchant_type: S) {
        self.merchant_type = Some(merchant_type.into());
    }
}
