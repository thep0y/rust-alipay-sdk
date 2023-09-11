use serde::Serialize;

/// 售产品码，商家和支付宝签约的产品码
#[derive(Serialize, Debug)]
pub enum ProductCode {
    /// app支付
    #[serde(rename(serialize = "QUICK_MSECURITY_PAY"))]
    QuickMsecurityPay,
    /// 手机网站支付
    #[serde(rename(serialize = "QUICK_WAP_WAY"))]
    QuickWapWay,
    /// 电脑网站支付
    #[serde(rename(serialize = "FAST_INSTANT_TRADE_PAY"))]
    FastInstantTradePay,
    /// 统一收单交易支付接口
    #[serde(rename(serialize = "FACE_TO_FACE_PAYMENT"))]
    FaceToFacePayment,
    /// 周期扣款签约
    #[serde(rename(serialize = "CYCLE_PAY_AUTH"))]
    CyclePayAuth,
}

impl Default for ProductCode {
    fn default() -> Self {
        ProductCode::FastInstantTradePay
    }
}
