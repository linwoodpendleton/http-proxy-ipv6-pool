// forward.rs

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use cidr::{Ipv4Cidr, Ipv6Cidr};
use rand::seq::SliceRandom;

use tokio::net::{TcpListener, TcpStream};
use tokio_native_tls::TlsConnector;
use native_tls::{ TlsConnector as NativeTlsConnector};
use tokio_socks::tcp::Socks5Stream;
// 定义 ForwardMapping 结构体和 ProxyType 枚举

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

// 解析命令行参数中的 forward 映射

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

// 启动转发代理的异步函数

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
            )
                .await
            {
                eprintln!("Error handling connection from {}: {}", client_addr, e);
            }
        });
    }
}

// 处理单个连接的异步函数
async fn handle_connection(
    local_stream: TcpStream,
    mapping: ForwardMapping,
    _timeout_duration: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    // 创建原生 TLS 连接器
    let mut builder = NativeTlsConnector::builder();

    // 安全警告：在生产环境中，请正确验证证书
    builder.danger_accept_invalid_certs(true);

    let native_connector = builder.build()?;
    let connector = TlsConnector::from(native_connector);

    // 建立到远程服务器的 TCP 连接（可能通过代理）
    let remote_tcp_stream = match mapping.proxy_type {
        ProxyType::None => {
            // 直接连接
            TcpStream::connect(&mapping.remote_addr).await?
        }
        _ => {
            // 通过代理连接
            if mapping.proxy_addrs.is_empty() {
                return Err("Proxy addresses not specified".into());
            }

            // 在这里限制 rng 的作用域
            let proxy_addr = {
                let mut rng = rand::thread_rng();
                *mapping.proxy_addrs.choose(&mut rng).unwrap()
            };

            // rng 在此作用域结束后被释放

            match mapping.proxy_type {
                ProxyType::Http => {
                    connect_via_http_proxy(proxy_addr, &mapping.remote_addr).await?
                }
                ProxyType::Socks5 => {
                    connect_via_socks5_proxy(proxy_addr, &mapping.remote_addr).await?
                }
                _ => unreachable!(),
            }
        }
    };

    // 通过 TLS Connector 建立 TLS 连接，并指定 SNI
    let domain = mapping.sni_host.as_str();
    let remote_stream = connector.connect(domain, remote_tcp_stream).await?;

    // 在本地连接和远程连接之间转发数据
    let (mut rl, mut wl) = tokio::io::split(local_stream);
    let (mut rr, mut wr) = tokio::io::split(remote_stream);

    let client_to_server = tokio::io::copy(&mut rl, &mut wr);
    let server_to_client = tokio::io::copy(&mut rr, &mut wl);

    tokio::try_join!(client_to_server, server_to_client)?;

    Ok(())
}


// 通过 HTTP 代理建立连接的函数
async fn connect_via_http_proxy(
    proxy_addr: SocketAddr,
    target_addr: &str,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = TcpStream::connect(proxy_addr).await?;

    let connect_request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", target_addr, target_addr);

    stream.write_all(connect_request.as_bytes()).await?;

    let mut response = Vec::new();
    let mut buf = [0u8; 1024];

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err("Proxy server closed connection".into());
        }
        response.extend_from_slice(&buf[..n]);

        // 使用 windows 方法检查是否包含 \r\n\r\n
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    let response_str = String::from_utf8_lossy(&response);

    if response_str.contains("200") {
        Ok(stream)
    } else {
        Err(format!("Failed to establish connection via HTTP proxy: {}", response_str).into())
    }
}


// 通过 SOCKS5 代理建立连接的函数

async fn connect_via_socks5_proxy(
    proxy_addr: SocketAddr,
    target_addr: &str,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let stream = Socks5Stream::connect(proxy_addr, target_addr).await?;
    Ok(stream.into_inner())
}

// 检查客户端 IP 是否在允许的范围内

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
