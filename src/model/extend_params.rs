use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ExtendParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    card_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hb_fq_num: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hb_fq_seller_percent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    industry_reflux_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    royalty_freeze: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    specified_seller_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sys_service_provider_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trade_component_order_id: Option<String>,
}

impl ExtendParams {
    pub fn new() -> Self {
        ExtendParams::default()
    }

    pub fn get_card_type(&self) -> Option<&str> {
        return self.card_type.as_deref();
    }

    pub fn set_card_type<S: Into<String>>(&mut self, card_type: S) {
        self.card_type = Some(card_type.into());
    }

    pub fn get_hb_fq_num(&self) -> Option<&str> {
        return self.hb_fq_num.as_deref();
    }

    pub fn set_hb_fq_num<S: Into<String>>(&mut self, hb_fq_num: S) {
        self.hb_fq_num = Some(hb_fq_num.into());
    }

    pub fn get_hb_fq_seller_percent(&self) -> Option<&str> {
        return self.hb_fq_seller_percent.as_deref();
    }

    pub fn set_hb_fq_seller_percent<S: Into<String>>(&mut self, hb_fq_seller_percent: S) {
        self.hb_fq_seller_percent = Some(hb_fq_seller_percent.into());
    }

    pub fn get_industry_reflux_info(&self) -> Option<&str> {
        return self.industry_reflux_info.as_deref();
    }

    pub fn set_industry_reflux_info<S: Into<String>>(&mut self, industry_reflux_info: S) {
        self.industry_reflux_info = Some(industry_reflux_info.into());
    }

    pub fn get_royalty_freeze(&self) -> Option<&str> {
        return self.royalty_freeze.as_deref();
    }

    pub fn set_royalty_freeze<S: Into<String>>(&mut self, royalty_freeze: S) {
        self.royalty_freeze = Some(royalty_freeze.into());
    }

    pub fn get_specified_seller_name(&self) -> Option<&str> {
        return self.specified_seller_name.as_deref();
    }

    pub fn set_specified_seller_name<S: Into<String>>(&mut self, specified_seller_name: S) {
        self.specified_seller_name = Some(specified_seller_name.into());
    }

    pub fn get_sys_service_provider_id(&self) -> Option<&str> {
        return self.sys_service_provider_id.as_deref();
    }

    pub fn set_sys_service_provider_id<S: Into<String>>(&mut self, sys_service_provider_id: S) {
        self.sys_service_provider_id = Some(sys_service_provider_id.into());
    }

    pub fn get_trade_component_order_id(&self) -> Option<&str> {
        return self.trade_component_order_id.as_deref();
    }

    pub fn set_trade_component_order_id<S: Into<String>>(&mut self, trade_component_order_id: S) {
        self.trade_component_order_id = Some(trade_component_order_id.into());
    }
}
