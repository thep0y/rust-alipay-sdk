use serde_json::Value;
use std::convert::Into;

use crate::request::Method;

pub struct IFile {
    pub(crate) path: String,
    pub(crate) field_name: String,
}

pub struct IField {
    pub(crate) name: String,
    pub(crate) value: Value,
}

pub struct AlipayForm {
    method: Method,
    files: Vec<IFile>,
    fields: Vec<IField>,
}

impl AlipayForm {
    pub fn new() -> Self {
        Self {
            method: Method::POST,
            fields: vec![],
            files: vec![],
        }
    }

    pub fn get_fields(&self) -> &[IField] {
        &self.fields
    }

    pub fn get_files(&self) -> &[IFile] {
        &self.files
    }

    pub fn get_method(&self) -> &Method {
        &self.method
    }

    /// 设置 method
    /// post、get 的区别在于 post 会返回 form 表单，get 返回 url
    pub fn set_method(&mut self, method: Method) {
        self.method = method;
    }

    /// 增加字段
    pub fn add_field<I: Into<String>>(&mut self, field_name: I, field_value: I) {
        self.fields.push(IField {
            name: field_name.into(),
            value: Value::String(field_value.into()),
        })
    }

    pub fn add_object_field<I: Into<String>>(&mut self, field_name: I, value: &Value) {
        self.fields.push(IField {
            name: field_name.into(),
            value: value.clone(),
        })
    }

    /// 增加文件
    pub fn add_file<S: Into<String>>(&mut self, field_name: S, file_path: S) {
        self.files.push(IFile {
            path: file_path.into(),
            field_name: field_name.into(),
        })
    }
}
