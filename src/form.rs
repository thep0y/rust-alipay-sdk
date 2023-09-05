use serde_json::Value;

pub struct IFile {
    pub(crate) name: String,
    pub(crate) path: String,
    field_name: String,
}

pub struct IField {
    pub(crate) name: String,
    pub(crate) value: Value,
}

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
    ///
    /// post、get 的区别在于 post 会返回 form 表单，get 返回 url
    pub fn set_method(&mut self, method: Method) {
        self.method = method;
    }

    /// 增加字段
    pub fn add_field(&mut self, field_name: String, field_value: Value) {
        self.fields.push(IField {
            name: field_name,
            value: field_value,
        })
    }

    /// 增加文件
    pub fn add_file(&mut self, field_name: String, file_name: String, file_path: String) {
        self.files.push(IFile {
            name: file_name,
            path: file_path,
            field_name,
        })
    }
}
