use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct PromoParam {
    #[serde(skip_serializing_if = "Option::is_none")]
    actual_order_time: Option<String>,
}

impl PromoParam {
    pub fn new() -> Self {
        PromoParam::default()
    }

    pub fn get_actual_order_time(&self) -> Option<&str> {
        return self.actual_order_time.as_deref();
    }

    pub fn set_actual_order_time<S: Into<String>>(&mut self, actual_order_time: S) {
        self.actual_order_time = Some(actual_order_time.into());
    }
}
