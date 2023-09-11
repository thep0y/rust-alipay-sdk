use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct BusinessParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    actual_order_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    campus_card: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    card_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enterprise_pay_amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enterprise_pay_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    good_taxes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mc_create_trade_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tiny_app_merchant_biz_type: Option<String>,
}

impl BusinessParams {
    pub fn new() -> Self {
        BusinessParams::default()
    }

    pub fn get_actual_order_time(&self) -> Option<&str> {
        return self.actual_order_time.as_deref();
    }

    pub fn set_actual_order_time<S: Into<String>>(&mut self, actual_order_time: S) {
        self.actual_order_time = Some(actual_order_time.into());
    }

    pub fn get_campus_card(&self) -> Option<&str> {
        return self.campus_card.as_deref();
    }

    pub fn set_campus_card<S: Into<String>>(&mut self, campus_card: S) {
        self.campus_card = Some(campus_card.into());
    }

    pub fn get_card_type(&self) -> Option<&str> {
        return self.card_type.as_deref();
    }

    pub fn set_card_type<S: Into<String>>(&mut self, card_type: S) {
        self.card_type = Some(card_type.into());
    }

    pub fn get_enterprise_pay_amount(&self) -> Option<&str> {
        return self.enterprise_pay_amount.as_deref();
    }

    pub fn set_enterprise_pay_amount<S: Into<String>>(&mut self, enterprise_pay_amount: S) {
        self.enterprise_pay_amount = Some(enterprise_pay_amount.into());
    }

    pub fn get_enterprise_pay_info(&self) -> Option<&str> {
        return self.enterprise_pay_info.as_deref();
    }

    pub fn set_enterprise_pay_info<S: Into<String>>(&mut self, enterprise_pay_info: S) {
        self.enterprise_pay_info = Some(enterprise_pay_info.into());
    }

    pub fn get_good_taxes(&self) -> Option<&str> {
        return self.good_taxes.as_deref();
    }

    pub fn set_good_taxes<S: Into<String>>(&mut self, good_taxes: S) {
        self.good_taxes = Some(good_taxes.into());
    }

    pub fn get_mc_create_trade_ip(&self) -> Option<&str> {
        return self.mc_create_trade_ip.as_deref();
    }

    pub fn set_mc_create_trade_ip<S: Into<String>>(&mut self, mc_create_trade_ip: S) {
        self.mc_create_trade_ip = Some(mc_create_trade_ip.into());
    }

    pub fn get_tiny_app_merchant_biz_type(&self) -> Option<&str> {
        return self.tiny_app_merchant_biz_type.as_deref();
    }

    pub fn set_tiny_app_merchant_biz_type<S: Into<String>>(
        &mut self,
        tiny_app_merchant_biz_type: S,
    ) {
        self.tiny_app_merchant_biz_type = Some(tiny_app_merchant_biz_type.into());
    }
}
