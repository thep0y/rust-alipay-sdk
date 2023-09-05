pub mod alipay;
pub mod antcertutil;
pub mod error;
pub mod form;
pub mod multipart;
pub mod time;
pub mod util;

#[macro_use]
extern crate log;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub type ParamsMap = Map<String, Value>;

#[derive(Serialize, Deserialize, Debug)]
pub struct AlipaySdkCommonResult {
    code: String,
    msg: String,
    sub_code: Option<String>,
    sub_msg: Option<String>,
    // result: HashMap<>
}
