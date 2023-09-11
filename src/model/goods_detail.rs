use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct GoodsDetail {
    #[serde(skip_serializing_if = "Option::is_none")]
    alipay_goods_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    categories_tree: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    goods_category: Option<String>,
    goods_id: String,
    goods_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    out_item_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    out_sku_id: Option<String>,
    price: f64,
    quantity: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    show_url: Option<String>,
}

impl GoodsDetail {
    pub fn new() -> Self {
        GoodsDetail::default()
    }

    pub fn get_alipay_goods_id(&self) -> Option<&str> {
        return self.alipay_goods_id.as_deref();
    }

    pub fn set_alipay_goods_id<S: Into<String>>(&mut self, alipay_goods_id: S) {
        self.alipay_goods_id = Some(alipay_goods_id.into());
    }

    pub fn get_body(&self) -> Option<&str> {
        return self.body.as_deref();
    }

    pub fn set_body<S: Into<String>>(&mut self, body: S) {
        self.body = Some(body.into());
    }

    pub fn get_categories_tree(&self) -> Option<&str> {
        return self.categories_tree.as_deref();
    }

    pub fn set_categories_tree<S: Into<String>>(&mut self, categories_tree: S) {
        self.categories_tree = Some(categories_tree.into());
    }

    pub fn get_goods_category(&self) -> Option<&str> {
        return self.goods_category.as_deref();
    }

    pub fn set_goods_category<S: Into<String>>(&mut self, goods_category: S) {
        self.goods_category = Some(goods_category.into());
    }

    pub fn get_goods_id(&self) -> &str {
        return self.goods_id.as_ref();
    }

    pub fn set_goods_id<S: Into<String>>(&mut self, goods_id: S) {
        self.goods_id = goods_id.into();
    }

    pub fn get_goods_name(&self) -> &str {
        return self.goods_name.as_ref();
    }

    pub fn set_goods_name<S: Into<String>>(&mut self, goods_name: S) {
        self.goods_name = goods_name.into();
    }

    pub fn get_out_item_id(&self) -> Option<&str> {
        return self.out_item_id.as_deref();
    }

    pub fn set_out_item_id<S: Into<String>>(&mut self, out_item_id: S) {
        self.out_item_id = Some(out_item_id.into());
    }

    pub fn get_out_sku_id(&self) -> Option<&str> {
        return self.out_sku_id.as_deref();
    }

    pub fn set_out_sku_id<S: Into<String>>(&mut self, out_sku_id: S) {
        self.out_sku_id = Some(out_sku_id.into());
    }

    pub fn get_price(&self) -> f64 {
        self.price
    }

    pub fn set_price(&mut self, price: f64) {
        self.price = price;
    }

    pub fn get_quantity(&self) -> u64 {
        self.quantity
    }

    pub fn set_quantity(&mut self, quantity: u64) {
        self.quantity = quantity;
    }

    pub fn get_show_url(&self) -> Option<&str> {
        return self.show_url.as_deref();
    }

    pub fn set_show_url<S: Into<String>>(&mut self, show_url: S) {
        self.show_url = Some(show_url.into());
    }
}
