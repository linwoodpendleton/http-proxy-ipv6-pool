// src/forward/curl_ffi.rs

use libc::{c_char, c_int, c_long, c_void};
use std::ffi::{CStr, CString};
use std::fmt;
use std::error::Error;
use std::sync::{Arc, Mutex};

// 定义 CURL 类型为不透明类型
#[repr(C)]
#[derive(Debug)]
pub struct CURL(c_void);

// 定义 CURLINFO 类型
pub type CURLINFO = c_int;

// 定义 CURLcode 类型为新的元组结构体
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CURLcode(pub c_int);

// 定义 CURLcode 常量
pub const CURLE_OK: CURLcode = CURLcode(0);
pub const CURLE_UNSUPPORTED_PROTOCOL: CURLcode = CURLcode(1);
pub const CURLE_FAILED_INIT: CURLcode = CURLcode(2);
// 根据需要添加更多的 CURLcode 常量

// 实现 Display trait for CURLcode
impl fmt::Display for CURLcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self.0 {
            0 => "CURLE_OK",
            1 => "CURLE_UNSUPPORTED_PROTOCOL",
            2 => "CURLE_FAILED_INIT",
            // 根据需要为其他 CURLcode 提供描述
            _ => "Unknown CURLcode",
        };
        write!(f, "{}", description)
    }
}

// 实现 Error trait for CURLcode
impl Error for CURLcode {}

// FFI 绑定到 libcurl 和 libcurl-impersonate 的函数
extern "C" {
    /// 通过 libcurl-impersonate 模拟浏览器
    pub fn curl_easy_impersonate(
        data: *mut CURL,
        target: *const c_char,
        default_headers: c_int,
    ) -> CURLcode;

    /// 初始化 CURL easy handle
    pub fn curl_easy_init() -> *mut CURL;

    /// 清理 CURL easy handle
    pub fn curl_easy_cleanup(handle: *mut CURL);

    /// 设置 CURL easy handle 的选项
    pub fn curl_easy_setopt(handle: *mut CURL, option: c_int, param: *const c_void) -> CURLcode;

    /// 执行 CURL 请求
    pub fn curl_easy_perform(handle: *mut CURL) -> CURLcode;

    /// 获取 CURL 请求的信息
    pub fn curl_easy_getinfo(handle: *mut CURL, info: c_int, param: *mut c_long) -> CURLcode;

    /// 获取 CURL 错误描述
    pub fn curl_easy_strerror(code: CURLcode) -> *const c_char;

    /// 追加一个 HTTP 头部到 curl_slist
    pub fn curl_slist_append(list: *mut c_void, header: *const c_char) -> *mut c_void;

    /// 释放 curl_slist
    pub fn curl_slist_free_all(list: *mut c_void);

    /// 包装函数，用于获取响应码
    pub fn get_response_code(curl: *mut CURL, response_code: *mut c_long) -> CURLcode;
    pub fn init_memory() -> *mut MemoryStruct;
    pub fn init_headers() -> *mut HeaderStruct;
    pub fn free_memory(mem: *mut MemoryStruct);
    pub fn free_headers(headers: *mut HeaderStruct);

    // 声明回调函数
    pub fn write_callback(ptr: *mut c_char, size: usize, nmemb: usize, userdata: *mut c_void) -> usize;
    pub fn header_callback(ptr: *mut c_char, size: usize, nmemb: usize, userdata: *mut c_void) -> usize;



}

// 定义 curl_easy_setopt 的选项常量
pub const CURLOPT_URL: c_int = 10002;
pub const CURLOPT_CUSTOMREQUEST: c_int = 10036;
pub const CURLOPT_POSTFIELDS: c_int = 10015;
pub const CURLOPT_HTTPHEADER: c_int = 10023;
pub const CURLOPT_WRITEFUNCTION: c_int = 20011;
pub const CURLOPT_WRITEDATA: c_int = 10001;
pub const CURLOPT_HEADERFUNCTION: c_int = 20079;
pub const CURLOPT_HEADERDATA: c_int = 10029;

pub const CURLOPT_PROXY: c_int = 10004;
pub const CURLOPT_PROXYTYPE: c_int = 101;

pub const CURLPROXY_HTTP: c_int = 0;
pub const CURLPROXY_SOCKS5: c_int = 5;



// 定义 curl_easy_getinfo 的选项常量
pub const CURLINFO_RESPONSE_CODE: c_int = 2097164; // 通常为 CURLINFO_RESPONSE_CODE

// 定义一个结构体来存储响应头部和响应体
// **建议**：将 `CurlResponse` 结构体移出 FFI 绑定文件，放到主代码模块中（例如 `forward.rs`）
pub struct CurlResponse {
    pub headers: Arc<Mutex<Vec<String>>>,
    pub body: Arc<Mutex<Vec<u8>>>,
}
// 定义 C 结构体
#[repr(C)]
pub struct MemoryStruct {
    pub data: *mut c_char,
    pub size: usize,
}

#[repr(C)]
pub struct HeaderStruct {
    pub headers: *mut *mut c_char,
    pub count: usize,
}


/// 定义一个辅助函数，用于设置字符串类型的 curl 选项
pub fn set_curl_option_string(handle: *mut c_void, option: c_int, value: &str) -> Result<(), Box<dyn Error>> {
    let c_value = CString::new(value)?;
    let res = unsafe { curl_easy_setopt(handle, option, c_value.as_ptr() as *const c_void) };
    if res.0 != CURLE_OK.0 {
        return Err(format!("curl_easy_setopt failed: {}", res).into());
    }
    Ok(())
}

/// 定义一个辅助函数，用于设置 void 指针类型的 curl 选项
pub fn set_curl_option_void(handle: *mut c_void, option: c_int, value: *const c_void) -> Result<(), Box<dyn Error>> {
    let res = unsafe { curl_easy_setopt(handle, option, value) };
    if res.0 != CURLE_OK.0 {
        return Err(format!("curl_easy_setopt failed: {}", res).into());
    }
    Ok(())
}
