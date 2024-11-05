// src/forward/forward.rs

use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // 导入 AsyncReadExt 和 AsyncWriteExt
use super::curl_wrapper::{set_curl_option_string, set_curl_option_void};
use super::curl_ffi::*;
use libc::{c_char, c_int};
use std::ffi::{c_long, c_void, CStr, CString};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use httparse::Response;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use crate::forward::curl_ffi::CurlResponse;
use tokio_socks::tcp::Socks5Stream;
use std::ptr;
use rand::seq::SliceRandom;
use scopeguard::defer;
use crate::forward::curl_ffi::CURLE_OK;

/// 定义 ForwardMapping 结构体和 ProxyType 枚举
#[derive(Clone)]
pub struct ForwardMapping {
    pub local_addr: SocketAddr,
    pub remote_addr: String,
    pub sni_host: String,
    pub proxy_addrs: Vec<String>,
    pub proxy_type: ProxyType,
}

#[derive(Clone)]
pub enum ProxyType {
    None,
    Http,
    Socks5,
}

/// 解析命令行参数中的 forward 映射
pub fn parse_forward_mapping(mapping_str: &str) -> Option<ForwardMapping> {
    let parts: Vec<&str> = mapping_str.split(',').collect();
    if parts.len() < 3 || parts.len() > 5 {
        eprintln!("Invalid forward mapping: {}", mapping_str);
        return None;
    }

    let local_addr = match parts[0].parse::<SocketAddr>() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("Invalid local address in mapping '{}': {}", mapping_str, e);
            return None;
        }
    };

    let remote_addr = parts[1].to_string();
    let sni_host = parts[2].to_string();

    let proxy_addrs = if parts.len() >= 4 {
        // 分割代理地址列表
        let proxy_addr_list: Vec<String> = parts[3]
            .split('|')
            .filter(|addr_str| {
                if addr_str.contains(':') {
                    true
                } else {
                    eprintln!("Invalid proxy address format '{}'", addr_str);
                    false
                }
            })
            .map(|s| s.to_string())  // 将 &str 转换为 String
            .collect();


        if proxy_addr_list.is_empty() {
            eprintln!("No valid proxy addresses in mapping '{}'", mapping_str);
            return None;
        }

        proxy_addr_list
    } else {
        Vec::new()
    };

    let proxy_type = if parts.len() == 5 {
        match parts[4].to_lowercase().as_str() {
            "http" => ProxyType::Http,
            "socks5" => ProxyType::Socks5,
            _ => {
                eprintln!("Invalid proxy type in mapping '{}'", mapping_str);
                return None;
            }
        }
    } else if !proxy_addrs.is_empty() {
        // 默认代理类型为 HTTP
        ProxyType::Http
    } else {
        ProxyType::None
    };

    Some(ForwardMapping {
        local_addr,
        remote_addr,
        sni_host,
        proxy_addrs,
        proxy_type,
    })
}

/// 检查客户端 IP 是否在允许的范围内
fn is_allowed_ip(
    ip: &IpAddr,
    ipv6_subnets: &Vec<Ipv6Cidr>,
    ipv4_subnets: &Vec<Ipv4Cidr>,
    allowed_ips: &Option<Vec<IpAddr>>,
) -> bool {
    if let Some(allowed_ips) = allowed_ips {
        if allowed_ips.contains(ip) {
            return true;
        }
    }

    match ip {
        IpAddr::V4(ipv4) => ipv4_subnets.iter().any(|subnet| subnet.contains(ipv4)),
        IpAddr::V6(ipv6) => ipv6_subnets.iter().any(|subnet| subnet.contains(ipv6)),
    }
}

/// 启动转发代理的异步函数
pub async fn start_forward_proxy(
    mapping: ForwardMapping,
    ipv6_subnets: Arc<Vec<Ipv6Cidr>>,
    ipv4_subnets: Arc<Vec<Ipv4Cidr>>,
    allowed_ips: Option<Vec<IpAddr>>,
    timeout_duration: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(mapping.local_addr).await?;
    println!("Listening on {}", mapping.local_addr);

    loop {
        let (local_stream, client_addr) = listener.accept().await?;
        let mapping = mapping.clone();
        let ipv6_subnets = Arc::clone(&ipv6_subnets);
        let ipv4_subnets = Arc::clone(&ipv4_subnets);
        let allowed_ips = allowed_ips.clone();

        // 检查客户端 IP 是否在允许的范围内
        if !is_allowed_ip(
            &client_addr.ip(),
            &*ipv6_subnets, // 解引用 Arc 并获取引用
            &*ipv4_subnets,
            &allowed_ips,
        ) {
            eprintln!("Connection from {} is not allowed", client_addr);
            continue;
        }

        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                local_stream,
                mapping,
                timeout_duration,
            ).await {
                eprintln!("Error handling connection from {}: {}", client_addr, e);
            }
        });
    }
}

pub async fn handle_connection(
    mut local_stream: TcpStream,
    mapping: ForwardMapping,
    _timeout_duration: Duration,
) -> Result<(), Box<dyn Error>> {
    let client_addr = local_stream.peer_addr()?;
    eprintln!("处理来自 {} 的连接", client_addr);

    // 读取完整的 HTTP 请求（头部和请求体）
    let mut buffer = Vec::new();
    loop {
        let mut temp_buf = [0u8; 1024];
        let n = local_stream.read(&mut temp_buf).await?;
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&temp_buf[..n]);

        // 检查是否已经读取到请求头的结束（\r\n\r\n）
        if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    // 解析 HTTP 请求头
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let status = req.parse(&buffer)?;

    if !matches!(status, httparse::Status::Complete(_)) {
        eprintln!("不完整的 HTTP 请求");
        return Err("Incomplete HTTP request".into());
    }

    let method = req.method.unwrap_or("");
    let path = req.path.unwrap_or("");
    let mut host = "";
    let mut headers_map = std::collections::HashMap::new();

    for header in req.headers.iter() {
        headers_map.insert(
            header.name.to_lowercase(),
            String::from_utf8_lossy(header.value).to_string(),
        );
    }

    if let Some(h) = headers_map.get("host") {
        host = h;
    }

    let target_url = if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!("https://{}{}", host, path)
    };

    eprintln!("请求方法: {}, URL: {}", method, target_url);

    // 提取请求体（如果存在）
    let body_start = buffer.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
    let body = if body_start < buffer.len() {
        &buffer[body_start..]
    } else {
        &[]
    };

    // 初始化 MemoryStruct 和 HeaderStruct
    let mem_ptr = unsafe { init_memory() };
    if mem_ptr.is_null() {
        return Err("Failed to initialize MemoryStruct".into());
    }

    let headers_ptr = unsafe { init_headers() };
    if headers_ptr.is_null() {
        unsafe { free_memory(mem_ptr) };
        return Err("Failed to initialize HeaderStruct".into());
    }

    // 使用 libcurl-impersonate 发起请求并收集响应数据
    let (response_code, response_headers, response_data) = tokio::task::spawn_blocking(move || -> Result<(u32, Vec<String>, Vec<u8>), Box<dyn std::error::Error + Send + Sync + 'static>> {
        // 初始化 CURL easy handle
        let easy_handle = unsafe { curl_easy_init() };
        if easy_handle.is_null() {
            eprintln!("Failed to initialize CURL easy handle");
            unsafe { free_memory(mem_ptr) };
            unsafe { free_headers(headers_ptr) };
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "CURL initialization failed")));
        }

        // 使用 `scopeguard` 确保在函数结束时清理 CURL handle
        defer! {
        unsafe { curl_easy_cleanup(easy_handle); }
    }

        // 设置 URL
        let target_url_c = CString::new(target_url).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        let res = unsafe { curl_easy_setopt(easy_handle, CURLOPT_URL, target_url_c.as_ptr() as *const c_void) };
        if res.0 != CURLE_OK.0 {
            eprintln!("curl_easy_setopt CURLOPT_URL failed: {}", res);
            unsafe { free_memory(mem_ptr) };
            unsafe { free_headers(headers_ptr) };
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("curl_easy_setopt CURLOPT_URL failed: {}", res))));
        }

        // 设置代理（如果存在）
        unsafe {
            if !mapping.proxy_addrs.is_empty() {
                let mut rng = rand::thread_rng();
                let proxy_addr = mapping.proxy_addrs.choose(&mut rng)
                    .expect("No proxy addresses available")
                    .to_string();
                let proxy_c = CString::new(proxy_addr).unwrap();
                let res = curl_easy_setopt(easy_handle, CURLOPT_PROXY, proxy_c.as_ptr() as *const c_void);
                if res.0 != CURLE_OK.0 {
                    eprintln!("curl_easy_setopt CURLOPT_PROXY failed: {}", res);
                    unsafe { free_memory(mem_ptr) };
                    unsafe { free_headers(headers_ptr) };
                    return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Failed to set proxy")));
                }

                // 设置代理类型
                match mapping.proxy_type {
                    ProxyType::Http => {
                        let proxy_type = CURLPROXY_HTTP;
                        let res = curl_easy_setopt(easy_handle, CURLOPT_PROXYTYPE, proxy_type as c_long as *const c_void);
                        if res.0 != CURLE_OK.0 {
                            eprintln!("curl_easy_setopt CURLOPT_PROXYTYPE (HTTP) failed: {}", res);
                            unsafe { free_memory(mem_ptr) };
                            unsafe { free_headers(headers_ptr) };
                            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Failed to set proxy type (HTTP)")));
                        }
                    },
                    ProxyType::Socks5 => {
                        let proxy_type = CURLPROXY_SOCKS5;
                        let res = curl_easy_setopt(easy_handle, CURLOPT_PROXYTYPE, proxy_type as c_long as *const c_void);
                        if res.0 != CURLE_OK.0 {
                            eprintln!("curl_easy_setopt CURLOPT_PROXYTYPE (SOCKS5) failed: {}", res);
                            unsafe { free_memory(mem_ptr) };
                            unsafe { free_headers(headers_ptr) };
                            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Failed to set proxy type (SOCKS5)")));
                        }
                    },
                    ProxyType::None => {},
                }
            }
        }

        // 设置 HTTP 方法
        unsafe {
            if method.to_uppercase() != "GET" {
                let method_c = CString::new(method).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
                let res = curl_easy_setopt(easy_handle, CURLOPT_CUSTOMREQUEST, method_c.as_ptr() as *const c_void);
                if res.0 != CURLE_OK.0 {
                    eprintln!("curl_easy_setopt CURLOPT_CUSTOMREQUEST failed: {}", res);
                    unsafe { free_memory(mem_ptr) };
                    unsafe { free_headers(headers_ptr) };
                    return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("curl_easy_setopt CURLOPT_CUSTOMREQUEST failed: {}", res))));
                }
            }
        }

        // 设置请求体（仅当存在时）
        unsafe {
            if !body.is_empty() {
                eprintln!("请求体大小: {}", body.len());
                let res = curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDS, body.as_ptr() as *const c_void);
                if res.0 != CURLE_OK.0 {
                    eprintln!("curl_easy_setopt CURLOPT_POSTFIELDS failed: {}", res);
                    unsafe { free_memory(mem_ptr) };
                    unsafe { free_headers(headers_ptr) };
                    return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("curl_easy_setopt CURLOPT_POSTFIELDS failed: {}", res))));
                }

                let res = curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDSIZE, body.len() as c_long as *const c_void);
                if res.0 != CURLE_OK.0 {
                    eprintln!("curl_easy_setopt CURLOPT_POSTFIELDSIZE failed: {}", res);
                    unsafe { free_memory(mem_ptr) };
                    unsafe { free_headers(headers_ptr) };
                    return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("curl_easy_setopt CURLOPT_POSTFIELDSIZE failed: {}", res))));
                }
            }
        }

        // 模拟浏览器
        let target_browser = CString::new("chrome116").unwrap();
        let result = unsafe { curl_easy_impersonate(easy_handle, target_browser.as_ptr(), 1) };
        if result.0 != CURLE_OK.0 {
            eprintln!("Failed to impersonate browser: {}", result);
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Impersonation failed")));
        }

        // 设置请求头
        let mut header_list = ptr::null_mut();
        for (key, value) in headers_map.iter() {
            let header = format!("{}: {}", key, value);
            let c_header = CString::new(header).unwrap();
            unsafe { header_list = curl_slist_append(header_list, c_header.as_ptr()); }
        }
        unsafe {
            if !header_list.is_null() {
                let res = curl_easy_setopt(easy_handle, CURLOPT_HTTPHEADER, header_list as *const c_void);
                if res.0 != CURLE_OK.0 {
                    eprintln!("curl_easy_setopt CURLOPT_HTTPHEADER failed: {}", res);
                    curl_slist_free_all(header_list);
                    unsafe { free_memory(mem_ptr) };
                    unsafe { free_headers(headers_ptr) };
                    return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("curl_easy_setopt CURLOPT_HTTPHEADER failed: {}", res))));
                }
            }
        }

        // 设置写回调
        let res = unsafe { curl_easy_setopt(easy_handle, CURLOPT_WRITEFUNCTION, write_callback as *const c_void) };
        if res.0 != CURLE_OK.0 {
            eprintln!("curl_easy_setopt CURLOPT_WRITEFUNCTION failed: {}", res);
            if !header_list.is_null() {
                unsafe { curl_slist_free_all(header_list); }
            }
            unsafe { free_memory(mem_ptr) };
            unsafe { free_headers(headers_ptr) };
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("curl_easy_setopt CURLOPT_WRITEFUNCTION failed: {}", res))));
        }

        let res = unsafe { curl_easy_setopt(easy_handle, CURLOPT_WRITEDATA, mem_ptr as *mut c_void) };
        if res.0 != CURLE_OK.0 {
            eprintln!("curl_easy_setopt CURLOPT_WRITEDATA failed: {}", res);
            if !header_list.is_null() {
                unsafe { curl_slist_free_all(header_list); }
            }
            unsafe { free_memory(mem_ptr) };
            unsafe { free_headers(headers_ptr) };
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("curl_easy_setopt CURLOPT_WRITEDATA failed: {}", res))));
        }

        // 设置头回调
        let res = unsafe { curl_easy_setopt(easy_handle, CURLOPT_HEADERFUNCTION, header_callback as *const c_void) };
        if res.0 != CURLE_OK.0 {
            eprintln!("curl_easy_setopt CURLOPT_HEADERFUNCTION failed: {}", res);
            if !header_list.is_null() {
                unsafe { curl_slist_free_all(header_list); }
            }
            unsafe { free_memory(mem_ptr) };
            unsafe { free_headers(headers_ptr) };
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("curl_easy_setopt CURLOPT_HEADERFUNCTION failed: {}", res))));
        }

        let res = unsafe { curl_easy_setopt(easy_handle, CURLOPT_HEADERDATA, headers_ptr as *mut c_void) };
        if res.0 != CURLE_OK.0 {
            eprintln!("curl_easy_setopt CURLOPT_HEADERDATA failed: {}", res);
            if !header_list.is_null() {
                unsafe { curl_slist_free_all(header_list); }
            }
            unsafe { free_memory(mem_ptr) };
            unsafe { free_headers(headers_ptr) };
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("curl_easy_setopt CURLOPT_HEADERDATA failed: {}", res))));
        }

        // 执行请求
        let res = unsafe { curl_easy_perform(easy_handle) };
        unsafe {
            if res.0 != CURLE_OK.0 {
                let error_str = if !curl_easy_strerror(res).is_null() {
                    let c_str = CStr::from_ptr(curl_easy_strerror(res));
                    c_str.to_string_lossy().into_owned()
                } else {
                    "Unknown CURL error".to_string()
                };
                eprintln!("CURL request failed: {}", error_str);
                if !header_list.is_null() {
                    curl_slist_free_all(header_list);
                }
                unsafe { free_memory(mem_ptr) };
                unsafe { free_headers(headers_ptr) };
                return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("CURL request failed: {}", error_str))));
            }
        }

        // 获取响应码
        let mut response_code: c_long = 0;
        let res = unsafe {
            get_response_code(
                easy_handle as *mut CURL,
                &mut response_code as *mut c_long,
            )
        };
        if res.0 != CURLE_OK.0 {
            eprintln!("Failed to get response code: {}", res);
            if !header_list.is_null() {
                unsafe { curl_slist_free_all(header_list); }
            }
            unsafe { free_memory(mem_ptr) };
            unsafe { free_headers(headers_ptr) };
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "CURL get info failed")));
        }

        eprintln!("响应码: {}", response_code);
        unsafe {
            // 读取响应头部
            let mut response_headers = Vec::new();
            for i in 0..(*headers_ptr).count {
                let header_ptr = (*headers_ptr).headers.offset(i as isize);
                let header = CStr::from_ptr(*header_ptr).to_string_lossy().into_owned();
                response_headers.push(header);
            }

            // 读取响应体
            let response_body = if (*mem_ptr).size > 0 {
                std::str::from_utf8(std::slice::from_raw_parts((*mem_ptr).data as *const u8, (*mem_ptr).size))
                    .unwrap_or("")
                    .as_bytes()
                    .to_vec()
            } else {
                Vec::new()
            };

            // 释放 C 结构体内存
            curl_slist_free_all(header_list);
            free_memory(mem_ptr);
            free_headers(headers_ptr);

            Ok((response_code as u32, response_headers, response_body))
        }
    }).await??;




    // // 构建状态行
    let status_text = get_status_text(response_code);
    let status_line = format!("HTTP/1.1 {} {}", response_code, status_text);

    // 合并所有部分，并确保有一个空行分隔头部和体
    let full_response = format!(
        "{}{}",
        status_line,
        ""
    );
    // 发送响应头部
    local_stream.write_all(full_response.as_bytes()).await?;

    for header in response_headers.iter() {
        if header.starts_with("HTTP/1.1") || header.starts_with("HTTP/2") || header.starts_with("Date")|| header.starts_with("content-encoding") {
            continue;
        }
        // 合并所有部分，并确保有一个空行分隔头部和体
        let head_response = format!(
            "{}{}",
            header,
            ""
        );
        local_stream.write_all(head_response.as_bytes()).await?;

    }



    // 发送响应体
    local_stream.write_all(&response_data).await?;

    // 在函数末尾添加 Ok(())
    Ok(())
}

/// 根据响应码获取状态文本
fn get_status_text(code: u32) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown Status",
    }
}