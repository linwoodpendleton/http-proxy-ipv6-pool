// src/forward/forward.rs

use std::collections::HashMap;
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // 导入 AsyncReadExt 和 AsyncWriteExt
use super::curl_wrapper::{set_curl_option_string, set_curl_option_void};
use super::curl_ffi::*;
use libc::{c_char, c_int};
use std::ffi::{c_long, c_void, CStr, CString};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use httparse::{Request, Response};
use cidr::{Ipv4Cidr, Ipv6Cidr};
use std::sync::{Arc};
use tokio::sync::Mutex;
use tokio::net::{TcpListener, TcpStream};
use crate::forward::curl_ffi::CurlResponse;
use tokio_socks::tcp::Socks5Stream;
use std::ptr;
use rand::seq::SliceRandom;
use scopeguard::defer;
use tokio::task;
use regex::Regex;
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
        let local_stream = Arc::new(Mutex::new(local_stream));

        if !is_allowed_ip(
            &client_addr.ip(),
            &*ipv6_subnets,
            &*ipv4_subnets,
            &allowed_ips,
        ) {
            eprintln!("Connection from {} is not allowed", client_addr);
            continue;
        }
        fn assert_send<T: Send>(_: T) {}
        // 在 `tokio::spawn` 外部引用 `client_addr`
        let client_address = client_addr.clone();
        tokio::spawn({
            let local_stream = local_stream.clone();
            let mapping = mapping.clone();
            let timeout_duration = timeout_duration.clone();
            let client_address = client_address.clone();

            assert_send(&local_stream);
            assert_send(&mapping);
            assert_send(timeout_duration);

            async move {
                if let Err(e) = handle_connection(local_stream, mapping, timeout_duration).await {
                    eprintln!("Error handling connection from {}: {}", client_address, e);
                }
            }
        });
    }
}


fn parse_http_request(buffer: Vec<u8>) -> Result<(String, String, HashMap<String, String>,Vec<u8>,String), Box<dyn Error + Send + Sync>> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    // Parse the request
    let status = req.parse(&buffer)?;
    if !matches!(status, httparse::Status::Complete(_)) {
        return Err("Incomplete HTTP request".into());
    }

    // Extract method, path, and headers into owned types
    let method = req.method.unwrap_or("").to_string();
    let path = req.path.unwrap_or("").to_string();
    let mut headers_map = HashMap::new();

    for header in req.headers.iter() {
        headers_map.insert(
            header.name.to_lowercase(),
            String::from_utf8_lossy(header.value).to_string(),
        );
    }
    let mut host = "";


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
        buffer[body_start..].to_vec() // 创建一个新的 Vec<u8>
    } else {
        Vec::new()
    };

    Ok((method, path, headers_map,body,target_url))
}
pub async fn handle_connection(
    local_stream: Arc<Mutex<TcpStream>>,
    mapping: ForwardMapping,
    _timeout_duration: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client_addr = local_stream.lock().await.peer_addr()?;
    eprintln!("处理来自 {} 的连接", client_addr);

    let mut buffer = Vec::new();
    loop {
        let n = {
            let mut locked_stream = local_stream.lock().await; // 将锁定的流的作用域缩小到只包含此块
            let mut temp_buf = [0u8; 1024];
            let n = locked_stream.read(&mut temp_buf).await?;
            if n > 0 {
                buffer.extend_from_slice(&temp_buf[..n]);
            }
            n
        }; // `locked_stream` 在这里被释放

        if n == 0 {
            break;
        }

        // 检查请求头是否读取完成
        if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    // 解析 HTTP 请求头
    let mut headers = [httparse::EMPTY_HEADER; 64];

    // 解析 HTTP 请求头部，缩小 `buffer` 的借用范围
    let status = {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = Request::new(&mut headers);
        req.parse(&buffer)?
    };

    if !matches!(status, httparse::Status::Complete(_)) {
        eprintln!("不完整的 HTTP 请求");
        return Err("Incomplete HTTP request".into());
    }
    let (method,path,headers_map,body,target_url) =  parse_http_request(buffer)?;;






    // 使用 libcurl-impersonate 发起请求并收集响应数据
    let (status_line, response_headers, response_body) = task::spawn_blocking(move || -> Result<(String, Vec<String>, Vec<u8>), Box<dyn Error + Send + Sync>> {
        unsafe {
            // 初始化 MemoryStruct 和 HeaderStruct
            let mem_ptr =  init_memory() ;
            if mem_ptr.is_null() {
                return Err("Failed to initialize MemoryStruct".into());
            }

            let headers_ptr = init_headers() ;
            if headers_ptr.is_null() {
                unsafe { free_memory(mem_ptr) };
                return Err("Failed to initialize HeaderStruct".into());
            }
            // 初始化 CURL easy handle
            let easy_handle = curl_easy_init();
            if easy_handle.is_null() {
                eprintln!("Failed to initialize CURL easy handle");
                unsafe { free_memory(mem_ptr) };
                unsafe { free_headers(headers_ptr) };
                return Err("CURL initialization failed".into());
            }

            // 使用 `scopeguard` 确保在函数结束时清理 CURL handle
            defer! {
                curl_easy_cleanup(easy_handle);
            }

            // 设置 URL
            let target_url_c = CString::new(target_url)?;
            let res = curl_easy_setopt(easy_handle, CURLOPT_URL, target_url_c.as_ptr() as *const c_void);
            if res.0 != CURLE_OK.0 {
                eprintln!("curl_easy_setopt CURLOPT_URL failed: {}", res);
                unsafe { free_memory(mem_ptr) };
                unsafe { free_headers(headers_ptr) };
                return Err(format!("curl_easy_setopt CURLOPT_URL failed: {}", res).into());
            }
            // 设置代理（如果存在）
            if !mapping.proxy_addrs.is_empty() {
                // 设置代理地址
                let mut rng = rand::thread_rng();
                let proxy_addr = mapping.proxy_addrs.choose(&mut rng)
                    .expect("No proxy addresses available")
                    .to_string(); // 随机选择一个代理地址并转换为字符串
                let proxy_c = CString::new(proxy_addr).unwrap();
                let res = curl_easy_setopt(easy_handle, CURLOPT_PROXY, proxy_c.as_ptr() as *const c_void);
                if res.0 != CURLE_OK.0 {
                    eprintln!("curl_easy_setopt CURLOPT_PROXY failed: {}", res);
                    unsafe { free_memory(mem_ptr) };
                    unsafe { free_headers(headers_ptr) };
                    return Err("Failed to set proxy".into());
                }

                // 设置代理类型
                match mapping.proxy_type {
                    ProxyType::Http => {
                        let proxy_type = CURLPROXY_HTTP;
                        let res = curl_easy_setopt(easy_handle, CURLOPT_PROXYTYPE, proxy_type as  c_long as *const c_void);
                        if res.0 != CURLE_OK.0 {
                            eprintln!("curl_easy_setopt CURLOPT_PROXYTYPE (HTTP) failed: {}", res);
                            unsafe { free_memory(mem_ptr) };
                            unsafe { free_headers(headers_ptr) };
                            return Err("Failed to set proxy type (HTTP)".into());
                        }
                    },
                    ProxyType::Socks5 => {
                        let proxy_type = CURLPROXY_SOCKS5 ;
                        let res = curl_easy_setopt(easy_handle, CURLOPT_PROXYTYPE, proxy_type as c_long as *const c_void);
                        if res.0 != CURLE_OK.0 {
                            eprintln!("curl_easy_setopt CURLOPT_PROXYTYPE (SOCKS5) failed: {}", res);
                            unsafe { free_memory(mem_ptr) };
                            unsafe { free_headers(headers_ptr) };
                            return Err("Failed to set proxy type (SOCKS5)".into());
                        }
                    },
                    ProxyType::None => {
                        // 不使用代理
                    },
                }

                // 如果需要代理认证，设置用户名和密码
                // let proxy_user = CString::new("your_proxy_username").unwrap();
                // let res = curl_easy_setopt(easy_handle, CURLOPT_PROXYUSERNAME, proxy_user.as_ptr() as *const c_void);
                // if res.0 != CURLE_OK.0 {
                //     eprintln!("curl_easy_setopt CURLOPT_PROXYUSERNAME failed: {}", res);
                //     unsafe { free_memory(mem_ptr) };
                //     unsafe { free_headers(headers_ptr) };
                //     return Err("Failed to set proxy username".into());
                // }

                // let proxy_pass = CString::new("your_proxy_password").unwrap();
                // let res = curl_easy_setopt(easy_handle, CURLOPT_PROXYPASSWORD, proxy_pass.as_ptr() as *const c_void);
                // if res.0 != CURLE_OK.0 {
                //     eprintln!("curl_easy_setopt CURLOPT_PROXYPASSWORD failed: {}", res);
                //     unsafe { free_memory(mem_ptr) };
                //     unsafe { free_headers(headers_ptr) };
                //     return Err("Failed to set proxy password".into());
                // }
            }
            // 设置 HTTP 方法
            if method.to_uppercase() != "GET" {
                let method_c = CString::new(method)?;
                let res = curl_easy_setopt(easy_handle, CURLOPT_CUSTOMREQUEST, method_c.as_ptr() as *const c_void);
                if res.0 != CURLE_OK.0 {
                    eprintln!("curl_easy_setopt CURLOPT_CUSTOMREQUEST failed: {}", res);
                    unsafe { free_memory(mem_ptr) };
                    unsafe { free_headers(headers_ptr) };
                    return Err(format!("curl_easy_setopt CURLOPT_CUSTOMREQUEST failed: {}", res).into());
                }

            }

            // 设置请求体（仅当存在时）
            if !body.is_empty() {

                eprintln!("请求体大小: {}", body.len());

                // 设置二进制数据为请求体
                let res = curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDS, body.as_ptr() as *const c_void);
                if res.0 != CURLE_OK.0 {
                    eprintln!("curl_easy_setopt CURLOPT_POSTFIELDS failed: {}", res);
                    unsafe { free_memory(mem_ptr) };
                    unsafe { free_headers(headers_ptr) };
                    return Err(format!("curl_easy_setopt CURLOPT_POSTFIELDS failed: {}", res).into());
                }

                // 设置请求体的大小
                let res = curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDSIZE, body.len() as c_long as *const c_void);
                if res.0 != CURLE_OK.0 {
                    eprintln!("curl_easy_setopt CURLOPT_POSTFIELDSIZE failed: {}", res);
                    unsafe { free_memory(mem_ptr) };
                    unsafe { free_headers(headers_ptr) };
                    return Err(format!("curl_easy_setopt CURLOPT_POSTFIELDSIZE failed: {}", res).into());
                }
            }
            let target_browser = CString::new("chrome124").unwrap(); // 选择要模拟的浏览器
            let result = curl_easy_impersonate(easy_handle, target_browser.as_ptr(), 1);
            if result.0 != CURLE_OK.0 {
                eprintln!("Failed to impersonate browser: {}", result);
                return Err("Impersonation failed".into());
            }
            // 设置请求头
            let mut header_list = ptr::null_mut();
            for (key, value) in headers_map.iter() {
                // 忽略一些自动设置的头部
                if key.to_lowercase().starts_with("x-forwarded") || key.to_lowercase().starts_with("connection") || key.to_lowercase().starts_with("x-gt") {
                    continue;
                }
                if key.to_lowercase().starts_with("referer"){
                    let re = Regex::new(r"https://[^/]+").unwrap();
                    let result = re.replace(value, "https://test.com");
                    let header = format!("{}: {}", key, result);
                    eprintln!("header {}",header);
                    let c_header = CString::new(header).unwrap();
                    header_list = curl_slist_append(header_list, c_header.as_ptr());
                    continue
                }


                let header = format!("{}: {}", key, value);
                eprintln!("header {}",header);
                let c_header = CString::new(header).unwrap();
                header_list = curl_slist_append(header_list, c_header.as_ptr());
            }
            if !header_list.is_null() {
                let res = curl_easy_setopt(easy_handle, CURLOPT_HTTPHEADER, header_list as *const c_void);
                if res.0 != CURLE_OK.0 {
                    eprintln!("curl_easy_setopt CURLOPT_HTTPHEADER failed: {}", res);
                    curl_slist_free_all(header_list);
                    unsafe { free_memory(mem_ptr) };
                    unsafe { free_headers(headers_ptr) };
                    return Err(format!("curl_easy_setopt CURLOPT_HTTPHEADER failed: {}", res).into());
                }
            }

            // 设置写回调
            // eprintln!("设置回调1");
            let res = curl_easy_setopt(easy_handle, CURLOPT_WRITEFUNCTION, write_callback as *const c_void);
            if res.0 != CURLE_OK.0 {
                eprintln!("curl_easy_setopt CURLOPT_WRITEFUNCTION failed: {}", res);
                if !header_list.is_null() {
                    curl_slist_free_all(header_list);
                }
                unsafe { free_memory(mem_ptr) };
                unsafe { free_headers(headers_ptr) };
                return Err(format!("curl_easy_setopt CURLOPT_WRITEFUNCTION failed: {}", res).into());
            }
            // eprintln!("设置回调2");
            let res = curl_easy_setopt(easy_handle, CURLOPT_WRITEDATA, mem_ptr as *mut c_void);
            if res.0 != CURLE_OK.0 {
                eprintln!("curl_easy_setopt CURLOPT_WRITEDATA failed: {}", res);
                if !header_list.is_null() {
                    curl_slist_free_all(header_list);
                }
                unsafe { free_memory(mem_ptr) };
                unsafe { free_headers(headers_ptr) };
                return Err(format!("curl_easy_setopt CURLOPT_WRITEDATA failed: {}", res).into());
            }

            // 设置头回调
            // eprintln!("设置回调3");
            let res = curl_easy_setopt(easy_handle, CURLOPT_HEADERFUNCTION, header_callback as *const c_void);
            if res.0 != CURLE_OK.0 {
                eprintln!("curl_easy_setopt CURLOPT_HEADERFUNCTION failed: {}", res);
                if !header_list.is_null() {
                    curl_slist_free_all(header_list);
                }
                unsafe { free_memory(mem_ptr) };
                unsafe { free_headers(headers_ptr) };
                return Err(format!("curl_easy_setopt CURLOPT_HEADERFUNCTION failed: {}", res).into());
            }
            // eprintln!("设置回调4");
            let res = curl_easy_setopt(easy_handle, CURLOPT_HEADERDATA, headers_ptr as *mut c_void);
            if res.0 != CURLE_OK.0 {
                eprintln!("curl_easy_setopt CURLOPT_HEADERDATA failed: {}", res);
                if !header_list.is_null() {
                    curl_slist_free_all(header_list);
                }
                unsafe { free_memory(mem_ptr) };
                unsafe { free_headers(headers_ptr) };
                return Err(format!("curl_easy_setopt CURLOPT_HEADERDATA failed: {}", res).into());
            }

            // 执行请求
            let res = curl_easy_perform(easy_handle);
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
                return Err(format!("CURL request failed: {}", error_str).into());
            }

            // 获取响应码
            let mut response_code: c_long = 0;
            let res = get_response_code(
                easy_handle as *mut CURL,
                &mut response_code as *mut c_long,
            );
            if res.0 != CURLE_OK.0 {
                eprintln!("Failed to get response code: {}", res);
                if !header_list.is_null() {
                    curl_slist_free_all(header_list);
                }
                unsafe { free_memory(mem_ptr) };
                unsafe { free_headers(headers_ptr) };
                return Err("CURL get info failed".into());
            }

            eprintln!("响应码: {}", response_code);

            // 读取响应头部
            let headers_lock = (*headers_ptr).count;
            let mut response_headers = Vec::new();
            for i in 0..(*headers_ptr).count {
                let header_ptr = (*headers_ptr).headers.offset(i as isize);
                let header = CStr::from_ptr(*header_ptr).to_string_lossy().into_owned();
                response_headers.push(header);
            }

            // 读取响应体
            eprintln!("响应体大小2: {}", (*mem_ptr).size);
            let response_body = if (*mem_ptr).size > 0 {
                std::slice::from_raw_parts((*mem_ptr).data as *const u8, (*mem_ptr).size).to_vec()
            } else {
                Vec::new()
            };

            // 释放 C 结构体内存
            curl_slist_free_all(header_list);
            free_memory(mem_ptr);
            free_headers(headers_ptr);
            let status_code: i64 = response_code as i64;
            let status_line = format!("HTTP/1.1 {}", status_code);
            Ok((status_line, response_headers, response_body))
        }

    }).await??;






    // 合并所有部分，并确保有一个空行分隔头部和体
    let full_response = format!(
        "{}{}",
        status_line,
        ""
    );
    let mut locked_stream = local_stream.lock().await; // 将锁定的流的作用域缩小到只包含此块
    // 发送响应头部
    locked_stream.write_all(full_response.as_bytes()).await?;

    // Calculate the length of the response body
    let content_length = response_body.len();
    // eprintln!("响应体大小: {}", content_length);



    for header in response_headers.iter() {
        if header.starts_with("HTTP/1") || header.starts_with("HTTP/2") || header.starts_with("Date")|| header.starts_with("content-encoding") {
            continue;
        }
        // 合并所有部分，并确保有一个空行分隔头部和体
        let head_response = format!(
            "{}{}",
            header,
            ""
        );
        if header.to_lowercase().starts_with("content-length:") {
            let contentLength = format!("Content-Length: {}\r\n", content_length);
            locked_stream.write_all(contentLength.as_bytes()).await?;
        }else {
            locked_stream.write_all(head_response.as_bytes()).await?;
        }


    }



    // 发送响应体
    locked_stream.write_all(&response_body).await?;

    locked_stream.flush().await?;
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