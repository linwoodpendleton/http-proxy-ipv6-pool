// src/forward/curl_ffi.rs

use libc::{c_char, c_int, c_long, c_void};
use std::ffi::CString;
use std::fmt;
use std::error::Error;
use std::sync::{Arc, Mutex};

// 定义 CURL 类型为不透明类型
pub type CURL = c_void;

// 定义 CURLINFO 类型
pub type CURLINFO = c_int;

// 定义 CURLcode 类型为 c_int，并使用常量代替枚举
pub type CURLcode = c_int;

// 定义 CURLcode 常量
pub const CURLE_OK: CURLcode = 0;
pub const CURLE_UNSUPPORTED_PROTOCOL: CURLcode = 1;
pub const CURLE_FAILED_INIT: CURLcode = 2;
// 根据需要添加更多的 CURLcode 常量
// 参考 curl.h 中的定义，例如:
// pub const CURLE_URL_MALFORMAT: CURLcode = 3;
// ...

// 实现 Display trait 用于 CURLcode
impl fmt::Display for CURLcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            CURLE_OK => "CURLE_OK",
            CURLE_UNSUPPORTED_PROTOCOL => "CURLE_UNSUPPORTED_PROTOCOL",
            CURLE_FAILED_INIT => "CURLE_FAILED_INIT",
            // 根据需要为其他 CURLcode 提供描述
            _ => "Unknown CURLcode",
        };
        write!(f, "{}", description)
    }
}

// 实现 Error trait 用于 CURLcode
impl Error for CURLcode {}

/// FFI 绑定到 libcurl 和 libcurl-impersonate 的函数
extern "C" {
    /// 通过 libcurl-impersonate 模拟浏览器
    pub fn curl_easy_impersonate(
        data: *mut c_void,
        target: *const c_char,
        default_headers: c_int,
    ) -> CURLcode;

    /// 初始化 CURL easy handle
    pub fn curl_easy_init() -> *mut c_void;

    /// 清理 CURL easy handle
    pub fn curl_easy_cleanup(handle: *mut c_void);

    /// 设置 CURL easy handle 的选项
    pub fn curl_easy_setopt(handle: *mut c_void, option: c_int, param: *const c_void) -> CURLcode;

    /// 执行 CURL 请求
    pub fn curl_easy_perform(handle: *mut c_void) -> CURLcode;

    /// 获取 CURL 请求的信息
    pub fn curl_easy_getinfo(handle: *mut c_void, info: c_int, param: *mut c_long) -> CURLcode;

    /// 获取 CURL 错误描述
    pub fn curl_easy_strerror(code: CURLcode) -> *const c_char;

    /// 追加一个 HTTP 头部到 curl_slist
    pub fn curl_slist_append(list: *mut c_void, header: *const c_char) -> *mut c_void;

    /// 释放 curl_slist
    pub fn curl_slist_free_all(list: *mut c_void);

    /// 包装函数，用于获取响应码
    pub fn get_response_code(curl: *mut CURL, response_code: *mut c_long) -> CURLcode;
}

/// 定义 curl_easy_setopt 的选项常量
pub const CURLOPT_URL: c_int = 10002;
pub const CURLOPT_CUSTOMREQUEST: c_int = 10036;
pub const CURLOPT_POSTFIELDS: c_int = 10015;
pub const CURLOPT_HTTPHEADER: c_int = 10023;
pub const CURLOPT_WRITEFUNCTION: c_int = 20011;
pub const CURLOPT_WRITEDATA: c_int = 10001;
pub const CURLOPT_HEADERFUNCTION: c_int = 20079;
pub const CURLOPT_HEADERDATA: c_int = 10029;

/// 定义 curl_easy_getinfo 的选项常量
pub const CURLINFO_RESPONSE_CODE: c_int = 2097164; // 请根据实际情况确认值

/// 定义一个结构体来存储响应头部和响应体
pub struct CurlResponse {
    pub headers: Arc<Mutex<Vec<String>>>,
    pub body: Arc<Mutex<Vec<u8>>>,
}

/// 头回调函数
pub(crate) extern "C" fn header_callback(
    ptr: *const c_char,
    size: usize,
    nmemb: usize,
    userdata: *mut c_void,
) -> usize {
    let real_size = size * nmemb;
    if userdata.is_null() {
        return 0;
    }

    // 将 userdata 转换为 Arc<Mutex<Vec<String>>>
    let headers = unsafe { &*(userdata as *const Arc<Mutex<Vec<String>>>) };

    // 从 ptr 创建 slice
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, real_size) };
    if let Ok(s) = std::str::from_utf8(slice) {
        let header = s.trim_end_matches("\r\n").to_string();
        let mut headers_lock = headers.lock().unwrap();
        headers_lock.push(header);
    }

    real_size
}

/// 写回调函数
pub(crate) extern "C" fn write_callback(
    ptr: *const c_char,
    size: usize,
    nmemb: usize,
    userdata: *mut c_void,
) -> usize {
    let real_size = size * nmemb;
    if userdata.is_null() {
        return 0;
    }

    // 将 userdata 转换为 Arc<Mutex<Vec<u8>>>
    let body = unsafe { &*(userdata as *const Arc<Mutex<Vec<u8>>>) };

    // 从 ptr 创建 slice
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, real_size) };

    let mut body_lock = body.lock().unwrap();
    body_lock.extend_from_slice(slice);

    real_size
}

/// 定义一个辅助函数，用于设置字符串类型的 curl 选项
pub fn set_curl_option_string(handle: *mut c_void, option: c_int, value: &str) -> Result<(), Box<dyn Error>> {
    let c_value = CString::new(value)?;
    let res = unsafe { curl_easy_setopt(handle, option, c_value.as_ptr() as *const c_void) };
    if res != CURLE_OK {
        return Err(format!("curl_easy_setopt failed: {}", res).into());
    }
    Ok(())
}

/// 定义一个辅助函数，用于设置 void 指针类型的 curl 选项
pub fn set_curl_option_void(handle: *mut c_void, option: c_int, value: *const c_void) -> Result<(), Box<dyn Error>> {
    let res = unsafe { curl_easy_setopt(handle, option, value) };
    if res != CURLE_OK {
        return Err(format!("curl_easy_setopt failed: {}", res).into());
    }
    Ok(())
}
