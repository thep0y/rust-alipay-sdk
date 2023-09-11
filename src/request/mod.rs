pub mod alipay_trade_pay_request;

#[derive(PartialEq)]
pub enum Method {
    GET,
    POST,
}

impl Method {
    pub fn from_string(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "get" => Method::GET,
            _ => Method::POST,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            Method::GET => String::from("GET"),
            Method::POST => String::from("POST"),
        }
    }
}
