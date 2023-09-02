pub mod alipay;
pub mod antcertutil;
pub mod error;
pub mod form;
pub mod time;
pub mod util;

#[macro_use]
extern crate log;

use serde_json::{Map, Value};

pub type ParamsMap = Map<String, Value>;
