// src/forward/curl_wrapper.rs

use super::curl_ffi::*; // 使用相对路径导入 curl_ffi
use libc::{c_int, c_void};
use std::ffi::CString;

/// 设置 CURL 选项，适用于需要 `*const c_char` 的选项
pub fn set_curl_option_string(handle: *mut c_void, option: c_int, value: &str) -> Result<(), CURLcode> {
    let c_string = CString::new(value).expect("CString::new failed");
    let res = unsafe {
        curl_easy_setopt(handle, option, c_string.as_ptr() as *const c_void)
    };
    if res == CURLE_OK {
        Ok(())
    } else {
        Err(res)
    }
}

/// 设置 CURL 选项，适用于需要 `*const c_void` 的选项（如请求体）
pub fn set_curl_option_void(handle: *mut c_void, option: c_int, value: *const c_void) -> Result<(), CURLcode> {
    let res = unsafe {
        curl_easy_setopt(handle, option, value)
    };
    if res == CURLE_OK {
        Ok(())
    } else {
        Err(res)
    }
}
