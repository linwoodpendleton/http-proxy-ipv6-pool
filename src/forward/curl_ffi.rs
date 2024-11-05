// src/forward/curl_ffi.rs

use libc::{c_char, c_int, c_void, c_long};
use std::ffi::CString;
use std::fmt;
use std::error::Error;
pub type CURL = c_void;

pub type CURLINFO = c_int;
/// 定义 CURLcode 类型
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CURLcode {
    CURLE_OK = 0,
    CURLE_UNSUPPORTED_PROTOCOL = 1,
    CURLE_FAILED_INIT = 2,
    // 根据需要添加更多的 CURLcode
    // 参考 curl.h 中的定义
}

// 实现 Display trait
impl fmt::Display for CURLcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            CURLcode::CURLE_OK => "CURLE_OK",
            CURLcode::CURLE_UNSUPPORTED_PROTOCOL => "CURLE_UNSUPPORTED_PROTOCOL",
            CURLcode::CURLE_FAILED_INIT => "CURLE_FAILED_INIT",
            // 根据需要为其他 CURLcode 提供描述
            _ => "Unknown CURLcode",
        };
        write!(f, "{}", description)
    }
}

// 实现 Error trait
impl Error for CURLcode {}

/// FFI 绑定到 libcurl 和 libcurl-impersonate 的函数
extern "C" {
    pub fn curl_easy_impersonate(
        data: *mut c_void,
        target: *const c_char,
        default_headers: c_int,
    ) -> CURLcode;

    pub fn curl_easy_init() -> *mut c_void;
    pub fn curl_easy_cleanup(handle: *mut c_void);
    pub fn curl_easy_setopt(handle: *mut c_void, option: c_int, param: *const c_void) -> CURLcode;
    pub fn curl_easy_perform(handle: *mut c_void) -> CURLcode;
    pub fn curl_easy_getinfo(handle: *mut c_void, info: c_int, param: *mut c_void) -> CURLcode;
    pub fn curl_easy_strerror(code: CURLcode) -> *const c_char;

    pub fn curl_slist_append(list: *mut c_void, header: *const c_char) -> *mut c_void;
    pub fn curl_slist_free_all(list: *mut c_void);
    pub fn get_response_code(curl: *mut CURL, response_code: *mut c_void) -> CURLcode;

}

/// 定义 curl_easy_setopt 的选项常量
pub const CURLOPT_URL: c_int = 10002;
pub const CURLOPT_CUSTOMREQUEST: c_int = 10036;
pub const CURLOPT_POSTFIELDS: c_int = 10015; // CURLOPT_POSTFIELDS = 10015
pub const CURLOPT_HTTPHEADER: c_int = 10023;
pub const CURLOPT_WRITEFUNCTION: c_int = 20011;
pub const CURLOPT_WRITEDATA: c_int = 10001;
pub const CURLINFO_RESPONSE_CODE: c_int = 2097164;
