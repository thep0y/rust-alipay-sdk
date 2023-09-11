use serde_json::json;

use crate::{
    error::{AlipayResult, Error},
    form::AlipayForm,
    model::alipay_trade_pay_model::AlipayTradePayModel,
};

use super::Method;

/// 统一收单下单并支付页面接口
pub const ALIPAY_TRADE_PAGE_PAY: &str = "alipay.trade.page.pay";

pub struct AlipayTradePagePayRequest {
    model: AlipayTradePayModel,
    method: Method,
    return_url: Option<String>,
    notify_url: Option<String>,
}

impl AlipayTradePagePayRequest {
    pub fn new(method: Method, model: AlipayTradePayModel) -> Self {
        Self {
            method,
            model,
            return_url: Default::default(),
            notify_url: Default::default(),
        }
    }

    pub fn set_return_url<S: Into<String>>(&mut self, return_url: S) -> AlipayResult<()> {
        if self.method == Method::POST {
            return Err(Error::Params("POST 请求不能设置 return_url".to_owned()));
        }

        self.return_url = Some(return_url.into());

        Ok(())
    }

    pub fn set_notify_url<S: Into<String>>(&mut self, notify_url: S) -> AlipayResult<()> {
        if self.method == Method::GET {
            return Err(Error::Params("GET 请求不能设置 notify_url".to_owned()));
        }

        self.return_url = Some(notify_url.into());

        Ok(())
    }

    pub fn create_form(self) -> AlipayResult<AlipayForm> {
        let mut form = AlipayForm::new();

        form.add_object_field("bizContent", &json!(self.model));

        match self.method {
            Method::GET => {
                form.set_method(Method::GET);
                match &self.return_url {
                    Some(url) => form.add_field("return_url", &url),
                    None => {
                        return Err(Error::Params(
                            "使用 GET 请求时 return_url 不能为空".to_string(),
                        ))
                    }
                }
            }
            Method::POST => {
                form.set_method(Method::POST);
                match &self.notify_url {
                    Some(url) => form.add_field("notify_url", &url),
                    None => {
                        return Err(Error::Params(
                            "使用 POST 请求时 notify_url 不能为空".to_string(),
                        ))
                    }
                }
            }
        }

        Ok(form)
    }
}
