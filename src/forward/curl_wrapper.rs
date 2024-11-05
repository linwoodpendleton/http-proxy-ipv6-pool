// src/forward/curl_wrapper.rs

use std::error::Error;
use super::curl_ffi::*; // 使用相对路径导入 curl_ffi
use libc::{c_int, c_void};
use std::ffi::CString;

/// 设置 CURL 选项，适用于需要 `*const c_char` 的选项
pub fn set_curl_option_string(handle: *mut c_void, option: c_int, value: &str) -> Result<(), Box<dyn Error>> {
    let c_value = CString::new(value)?;
    let res = unsafe { curl_easy_setopt(handle, option, c_value.as_ptr() as *const c_void) };
    eprintln!("set_curl_option_string: res = {:?}", res);
    if res.0 != CURLE_OK.0 {
        return Err(format!("curl_easy_setopt failed: {}", res).into());
    }
    Ok(())
}

pub fn set_curl_option_void(handle: *mut c_void, option: c_int, value: *const c_void) -> Result<(), Box<dyn Error>> {
    let res = unsafe { curl_easy_setopt(handle, option, value) };
    eprintln!("set_curl_option_void: res = {:?}", res);
    if res.0 != CURLE_OK.0 {
        return Err(format!("curl_easy_setopt failed: {}", res).into());
    }
    Ok(())
}