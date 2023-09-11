use serde::Serialize;

use crate::product_code::ProductCode;

use super::business_params::BusinessParams;
use super::extend_params::ExtendParams;
use super::goods_detail::GoodsDetail;
use super::invoice_info::InvoiceInfo;
use super::promo_param::PromoParam;
use super::sub_merchant::SubMerchant;

/// alipay.trade.page.pay(统一收单下单并支付页面接口)。
/// 字段参考官方文档：https://opendocs.alipay.com/open/028r8t?pathHash=8e24911d&scene=22
#[derive(Serialize, Debug, Default)]
pub struct AlipayTradePayModel {
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    /// 商户传入业务信息。
    /// 具体值要和支付宝约定，应用于安全，营销等参数直传场景。
    #[serde(skip_serializing_if = "Option::is_none")]
    business_params: Option<BusinessParams>,
    /// 业务扩展参数
    #[serde(skip_serializing_if = "Option::is_none")]
    extend_params: Option<ExtendParams>,
    /// 订单包含的商品列表信息
    #[serde(skip_serializing_if = "Option::is_none")]
    goods_detail: Option<Vec<GoodsDetail>>,
    /// 请求后页面的集成方式。
    /// 枚举值：
    /// ALIAPP：支付宝钱包内
    /// PCWEB：PC端访问
    /// 默认值为PCWEB。
    #[serde(skip_serializing_if = "Option::is_none")]
    integration_type: Option<String>,
    /// 开票信息
    #[serde(skip_serializing_if = "Option::is_none")]
    invoice_info: Option<InvoiceInfo>,
    /// 商户原始订单号，最大长度限制 32 位
    #[serde(skip_serializing_if = "Option::is_none")]
    merchant_order_no: Option<String>,
    /// 商户订单号。
    /// 由商家自定义，64个字符以内，仅支持字母、数字、下划线且需保证在商户端不重复。
    out_trade_no: String,
    /// 销售产品码，与支付宝签约的产品码名称。
    /// 注：目前电脑支付场景下仅支持FAST_INSTANT_TRADE_PAY
    product_code: ProductCode,
    /// 优惠参数。仅与支付宝协商后可用。
    #[serde(skip_serializing_if = "Option::is_none")]
    promo_params: Option<PromoParam>,
    /// PC扫码支付的方式。
    /// 支持前置模式和跳转模式。
    /// 前置模式是将二维码前置到商户的订单确认页的模式。
    /// 需要商户在自己的页面中以 iframe 方式请求支付宝页面。
    /// 具体支持的枚举值有以下几种：
    /// 0：订单码-简约前置模式，对应 iframe 宽度不能小于600px，高度不能小于300px；
    /// 1：订单码-前置模式，对应iframe 宽度不能小于 300px，高度不能小于600px；
    /// 3：订单码-迷你前置模式，对应 iframe 宽度不能小于 75px，高度不能小于75px；
    /// 4：订单码-可定义宽度的嵌入式二维码，商户可根据需要设定二维码的大小。
    ///
    /// 跳转模式下，用户的扫码界面是由支付宝生成的，不在商户的域名下。支持传入的枚举值有：
    /// 2：订单码-跳转模式
    /// 枚举值
    /// 订单码-简约前置模式: 0
    /// 订单码-前置模式: 1
    /// 订单码-迷你前置模式: 3
    /// 订单码-可定义宽度的嵌入式二维码: 4
    #[serde(skip_serializing_if = "Option::is_none")]
    qr_pay_mode: Option<String>,
    /// 商户自定义二维码宽度。
    /// 注：`qr_pay_mode=4`时该参数有效
    #[serde(skip_serializing_if = "Option::is_none")]
    qrcode_width: Option<u8>,
    /// 请求来源地址。
    /// 如果使用ALIAPP的集成方式，用户中途取消支付会返回该地址。
    #[serde(skip_serializing_if = "Option::is_none")]
    request_from_url: Option<String>,
    /// 商户门店编号。
    /// 指商户创建门店时输入的门店编号。
    #[serde(skip_serializing_if = "Option::is_none")]
    store_id: Option<String>,
    /// 二级商户信息。
    /// 直付通模式和机构间连模式下必传，其它场景下不需要传入。
    #[serde(skip_serializing_if = "Option::is_none")]
    sub_merchant: Option<SubMerchant>,
    /// 订单标题。
    /// 注意：不可使用特殊字符，如 /，=，& 等。
    subject: String,
    /// 订单绝对超时时间。
    /// 格式为`yyyy-MM-dd HH:mm:ss`。超时时间范围：1m~15d。
    /// `time_expire`和`timeout_express`两者只需传入一个或者都不传，
    /// 两者均传入时，优先使用`time_expire`。
    #[serde(skip_serializing_if = "Option::is_none")]
    time_expire: Option<String>,
    /// 订单总金额，单位为元，精确到小数点后两位，取值范围为 [0.01,100000000]。
    /// 金额不能为0。
    total_amount: f64,
}

impl AlipayTradePayModel {
    pub fn new() -> Self {
        AlipayTradePayModel::default()
    }

    pub fn get_body(&self) -> Option<&str> {
        return self.body.as_deref();
    }

    pub fn set_body<S: Into<String>>(&mut self, body: S) {
        self.body = Some(body.into());
    }

    pub fn get_business_params(&self) -> Option<&BusinessParams> {
        return self.business_params.as_ref();
    }

    pub fn set_business_params(&mut self, business_params: BusinessParams) {
        self.business_params = Some(business_params);
    }

    pub fn get_extend_params(&self) -> Option<&ExtendParams> {
        return self.extend_params.as_ref();
    }

    pub fn set_extend_params(&mut self, extend_params: ExtendParams) {
        self.extend_params = Some(extend_params);
    }

    pub fn get_goods_detail(&self) -> Option<&[GoodsDetail]> {
        return self.goods_detail.as_deref();
    }

    pub fn set_goods_detail(&mut self, goods_detail: Vec<GoodsDetail>) {
        self.goods_detail = Some(goods_detail);
    }

    pub fn get_merchant_order_no(&self) -> Option<&str> {
        return self.merchant_order_no.as_deref();
    }

    pub fn set_merchant_order_no<S: Into<String>>(&mut self, merchant_order_no: S) {
        self.merchant_order_no = Some(merchant_order_no.into());
    }

    pub fn get_out_trade_no(&self) -> &str {
        return self.out_trade_no.as_ref();
    }

    pub fn set_out_trade_no<S: Into<String>>(&mut self, out_trade_no: S) {
        self.out_trade_no = out_trade_no.into();
    }

    pub fn get_product_code(&self) -> &ProductCode {
        &self.product_code
    }

    pub fn set_product_code(&mut self, product_code: ProductCode) {
        self.product_code = product_code;
    }

    pub fn get_promo_params(&self) -> Option<&PromoParam> {
        return self.promo_params.as_ref();
    }

    pub fn set_promo_params(&mut self, promo_params: PromoParam) {
        self.promo_params = Some(promo_params);
    }

    pub fn get_store_id(&self) -> Option<&str> {
        return self.store_id.as_deref();
    }

    pub fn set_store_id<S: Into<String>>(&mut self, store_id: S) {
        self.store_id = Some(store_id.into());
    }

    pub fn get_sub_merchant(&self) -> Option<&SubMerchant> {
        return self.sub_merchant.as_ref();
    }

    pub fn set_sub_merchant<S: Into<String>>(&mut self, sub_merchant: SubMerchant) {
        self.sub_merchant = Some(sub_merchant);
    }

    pub fn get_subject(&self) -> &str {
        return self.subject.as_ref();
    }

    pub fn set_subject<S: Into<String>>(&mut self, subject: S) {
        self.subject = subject.into();
    }

    pub fn get_time_expire(&self) -> Option<&str> {
        self.time_expire.as_deref()
    }

    pub fn set_time_expire<S: Into<String>>(&mut self, time_expire: S) {
        self.time_expire = Some(time_expire.into());
    }

    pub fn get_total_amount(&self) -> f64 {
        return self.total_amount;
    }

    pub fn set_total_amount(&mut self, total_amount: f64) {
        self.total_amount = total_amount;
    }
}
