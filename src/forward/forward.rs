// src/forward/forward.rs

use tokio::io::{AsyncReadExt, AsyncWriteExt}; // 导入 AsyncReadExt 和 AsyncWriteExt
use super::curl_wrapper::{set_curl_option_string, set_curl_option_void};
use crate::forward::curl_ffi::*;
use libc::{c_char, c_int};
use std::ffi::{c_long, c_void, CString};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use httparse::Response;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use rand::seq::SliceRandom;

use tokio::net::{TcpListener, TcpStream};
use tokio_native_tls::TlsConnector;
use native_tls::{TlsConnector as NativeTlsConnector};
use tokio_socks::tcp::Socks5Stream;
use std::ptr;

/// 定义 ForwardMapping 结构体和 ProxyType 枚举
#[derive(Clone)]
pub struct ForwardMapping {
    pub local_addr: SocketAddr,
    pub remote_addr: String,
    pub sni_host: String,
    pub proxy_addrs: Vec<SocketAddr>,
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
        let proxy_addr_list = parts[3]
            .split('|')
            .filter_map(|addr_str| {
                match addr_str.parse::<SocketAddr>() {
                    Ok(addr) => Some(addr),
                    Err(e) => {
                        eprintln!("Invalid proxy address '{}': {}", addr_str, e);
                        None
                    }
                }
            })
            .collect::<Vec<_>>();

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

/// 处理单个连接的异步函数
async fn handle_connection(
    mut local_stream: TcpStream,
    mapping: ForwardMapping,
    _timeout_duration: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let client_addr = local_stream.peer_addr()?;
    eprintln!("处理来自 {} 的连接", client_addr);

    // 读取完整的 HTTP 请求（头部和请求体）
    let mut buffer = Vec::new();
    loop {
        let mut temp_buf = [0u8; 1024];
        let n = local_stream.read(&mut temp_buf).await?; // 使用 read 方法
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
        headers_map.insert(header.name.to_lowercase(), String::from_utf8_lossy(header.value).to_string());
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

    // 使用 libcurl-impersonate 发起请求并收集响应数据
    let (response_code, response_data) = unsafe {
        // 初始化 CURL easy handle
        let easy_handle = curl_easy_init();
        if easy_handle.is_null() {
            eprintln!("Failed to initialize CURL easy handle");
            return Err("CURL initialization failed".into());
        }

        // 使用 `scopeguard` 确保在函数结束时清理 CURL handle
        scopeguard::defer! {
        curl_easy_cleanup(easy_handle);
    }

        // 设置 URL
        set_curl_option_string(easy_handle, CURLOPT_URL, &target_url)?;

        // 设置 HTTP 方法
        if method.to_uppercase() != "GET" {
            set_curl_option_string(easy_handle, CURLOPT_CUSTOMREQUEST, method)?;
        }

        // 设置请求体（仅当存在时）
        if !body.is_empty() {
            let body_str = match std::str::from_utf8(body) {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("Invalid UTF-8 sequence in request body");
                    return Err("Invalid request body".into());
                }
            };
            set_curl_option_string(easy_handle, CURLOPT_POSTFIELDS, body_str)?;
        }

        // 设置模拟浏览器
        let target_browser = CString::new("chrome116").unwrap(); // 选择要模拟的浏览器
        let result = curl_easy_impersonate(easy_handle, target_browser.as_ptr(), 1);
        if result != CURLcode::CURLE_OK {
            eprintln!("Failed to impersonate browser: {:?}", result);
            return Err("Impersonation failed".into());
        }

        // 设置请求头
        let mut header_list = ptr::null_mut();
        for (key, value) in headers_map.iter() {
            // 忽略一些自动设置的头部
            if key == "host" || key == "user-agent" || key == "accept" {
                continue;
            }
            let header = format!("{}: {}", key, value);
            let c_header = CString::new(header).unwrap();
            header_list = curl_slist_append(header_list, c_header.as_ptr());
        }
        if !header_list.is_null() {
            set_curl_option_void(easy_handle, CURLOPT_HTTPHEADER, header_list as *const c_void)?;
        }

        // 设置写回调
        let mut response_data = Vec::new();
        let write_callback = write_function; // 移除 Option

        // 设置回调函数
        set_curl_option_void(easy_handle, CURLOPT_WRITEFUNCTION, write_callback as *const c_void)?;

        // 设置回调数据
        let response_ptr: *mut Vec<u8> = &mut response_data as *mut _;
        set_curl_option_void(easy_handle, CURLOPT_WRITEDATA, response_ptr as *mut c_void)?;

        // 执行请求
        let res = curl_easy_perform(easy_handle);
        if res != CURLcode::CURLE_OK {
            let error_str = if !curl_easy_strerror(res).is_null() {
                let c_str = std::ffi::CStr::from_ptr(curl_easy_strerror(res) as *const c_char);
                c_str.to_string_lossy().into_owned()
            } else {
                "Unknown CURL error".to_string()
            };
            eprintln!("CURL request failed: {}", error_str);
            if !header_list.is_null() {
                curl_slist_free_all(header_list);
            }
            return Err(format!("CURL request failed: {}", error_str).into());
        }

        // 获取响应码
        let mut response_code: c_long = 0;
        let res = get_response_code(
            easy_handle,
            &mut response_code as *mut _ as *mut c_void,
        );
        if res != CURLcode::CURLE_OK {
            eprintln!("Failed to get response code: {:?}", res);
            if !header_list.is_null() {
                curl_slist_free_all(header_list);
            }
            return Err("CURL get info failed".into());
        }

        eprintln!("响应码: {}", response_code);

        // 关闭 CURL
        if !header_list.is_null() {
            curl_slist_free_all(header_list);
        }

        // 返回响应码和数据
        (response_code as u32, response_data)
    };
    let status_text = get_status_text(response_code);
    let response_headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response_code,
        status_text,
        response_data.len()
    );

    // 发送 HTTP 响应头部
    local_stream.write_all(response_headers.as_bytes()).await?;

    // 发送响应体
    local_stream.write_all(&response_data).await?;


    // 在函数末尾添加 Ok(())
    Ok(())
}
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

/// 定义写回调函数
extern "C" fn write_function(ptr: *mut u8, size: usize, nmemb: usize, userdata: *mut c_void) -> usize {
    let real_size = size * nmemb;
    if userdata.is_null() {
        return 0;
    }
    let buffer = unsafe { &mut *(userdata as *mut Vec<u8>) };
    let data = unsafe { std::slice::from_raw_parts(ptr, real_size) };
    buffer.extend_from_slice(data);
    real_size
}

/// 通过 HTTP 代理建立连接的函数
async fn connect_via_http_proxy(
    proxy_addr: SocketAddr,
    target_addr: &str,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = TcpStream::connect(proxy_addr).await?;

    let connect_request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        target_addr, target_addr
    );

    stream.write_all(connect_request.as_bytes()).await?;

    let mut buf = [0u8; 4096];
    let mut pos = 0;

    // 读取代理服务器的响应
    loop {
        let n = stream.read(&mut buf[pos..]).await?;
        if n == 0 {
            return Err("Proxy server closed connection".into());
        }
        pos += n;

        // 解析 HTTP 响应
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut res = Response::new(&mut headers);
        let status = res.parse(&buf[..pos]);

        match status {
            Ok(httparse::Status::Complete(_)) => {
                if let Some(code) = res.code {
                    if 200 <= code && code < 300 {
                        // 连接成功
                        return Ok(stream);
                    } else {
                        let response_str = String::from_utf8_lossy(&buf[..pos]);
                        return Err(format!("Proxy returned error status {}: {}", code, response_str).into());
                    }
                } else {
                    return Err("Failed to get response code from proxy".into());
                }
            }
            Ok(httparse::Status::Partial) => {
                // 继续读取
                if pos >= buf.len() {
                    return Err("Proxy response too large".into());
                }
                continue;
            }
            Err(e) => {
                return Err(format!("Failed to parse proxy response: {}", e).into());
            }
        }
    }
}

/// 通过 SOCKS5 代理建立连接的函数
async fn connect_via_socks5_proxy(
    proxy_addr: SocketAddr,
    target_addr: &str,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let stream = Socks5Stream::connect(proxy_addr, target_addr).await?;
    Ok(stream.into_inner())
}
