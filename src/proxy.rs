use hyper::{
    client::HttpConnector,
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Client, Method, Request, Response, Server, StatusCode,
};
use rand::{random, Rng};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use tokio::{ net::TcpSocket, task};
use std::sync::{Arc};
use tokio::process::Command;
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::time::Duration;
use tokio::sync::Mutex;
use lazy_static::lazy_static;
use tokio::time::timeout;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use hyper::upgrade::OnUpgrade;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use rand::seq::SliceRandom;
use socket2::{Socket, Domain, Type};
use std::os::unix::io::{AsRawFd, FromRawFd};
use get_if_addrs::{get_if_addrs, IfAddr};
use crate::Socket2Connector::Socket2Connector;

const MAX_ADDRESSES: usize = 1000;

lazy_static! {
    static ref IP_MAP: Mutex<HashMap<String, IpAddr>> = Mutex::new(HashMap::new());
    static ref GLOBAL_ADDRESS_QUEUE: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
}

pub async fn start_proxy(
    listen_addr: SocketAddr,
    is_system_route: bool,
    gateway: String,
    interface: String,
    ipv6_subnets: Arc<Vec<Ipv6Cidr>>,
    ipv4_subnets: Arc<Vec<Ipv4Cidr>>,
    allowed_ips: Option<Vec<IpAddr>>,
    username: String,  // 新增用户名参数
    password: String,  // 新增密码参数
    timeout_duration: Duration, // 新增timeout_duration参数
    bind_interface: Option<String>, // 新增参数：指定绑定的网络接口
) -> Result<(), Box<dyn std::error::Error>> {
    let interface_arc = Arc::new(interface);
    let gateway_arc = Arc::new(gateway);
    let allowed_ips_arc = allowed_ips.map(Arc::new);
    let username_arc = Arc::new(username);  // 用 Arc 包装用户名
    let password_arc = Arc::new(password);  // 用 Arc 包装密码
    let bind_interface_arc = bind_interface.map(Arc::new); // 包装成 Arc
    let make_service = make_service_fn(move |conn: &AddrStream| {
        let remote_addr = conn.remote_addr();
        let interface_clone = Arc::clone(&interface_arc);
        let gateway_clone = Arc::clone(&gateway_arc);
        let ipv6_subnets_clone = Arc::clone(&ipv6_subnets);  // 使用 Arc 克隆引用
        let ipv4_subnets_clone = Arc::clone(&ipv4_subnets);
        let allowed_ips_clone = allowed_ips_arc.clone();
        let username_clone = Arc::clone(&username_arc);  // 克隆用户名
        let password_clone = Arc::clone(&password_arc);  // 克隆密码

        let bind_interface_clone = bind_interface_arc.clone(); // 克隆 Arc
        async move {
            let service = service_fn(move |mut req: Request<Body>| {
                req.extensions_mut().insert(remote_addr);
                let bind_interface_inner = bind_interface_clone.clone(); // 再次克隆供内部使用
                Proxy {
                    ipv6_subnets: Arc::clone(&ipv6_subnets_clone),  // 直接使用 Arc::clone
                    ipv4_subnets: Arc::clone(&ipv4_subnets_clone),  // 直接使用 Arc::clone
                    address_queue: GLOBAL_ADDRESS_QUEUE.clone(),
                    allowed_ips: allowed_ips_clone.clone(),
                    username: username_clone.clone(),  // 传递用户名
                    password: password_clone.clone(),  // 传递密码
                    bind_interface: bind_interface_inner, // 传递给 Proxy 结构体
                }
                    .proxy(req, is_system_route, (*interface_clone).clone(), (*gateway_clone).clone(), timeout_duration)
            });

            Ok::<_, hyper::Error>(service)
        }
    });

    Server::bind(&listen_addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service)
        .await
        .map_err(|err| err.into())
}

#[derive(Clone)]
pub(crate) struct Proxy {
    pub ipv6_subnets: Arc<Vec<Ipv6Cidr>>,
    pub ipv4_subnets: Arc<Vec<Ipv4Cidr>>,
    address_queue: Arc<Mutex<VecDeque<String>>>,
    allowed_ips: Option<Arc<Vec<IpAddr>>>,
    username: Arc<String>,  // 添加用户名字段
    password: Arc<String>,  // 添加密码字段
    pub bind_interface: Option<Arc<String>>,
}

impl Proxy {
    pub(crate) async fn proxy(
        self,
        req: Request<Body>,
        is_system_route: bool,
        interface: String,
        gateway: String,
        timeout_duration: Duration,
    ) -> Result<Response<Body>, hyper::Error> {
        let auth_enabled = !self.username.is_empty() && !self.password.is_empty();
        if auth_enabled {
            if !self.is_authorized(&req) {
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("WWW-Authenticate", r#"Basic realm="User Visible Realm""#)
                    .body(Body::from("Unauthorized"))
                    .unwrap());
            }
        }

        let client_ip: Option<IpAddr> = if let Some(remote_addr) = req.extensions().get::<SocketAddr>() {
            Some(remote_addr.ip())
        } else if let Some(forwarded_for) = req.headers().get("x-forwarded-for") {
            forwarded_for.to_str().ok().and_then(|ip_str| ip_str.parse().ok())
        } else if let Some(real_ip) = req.headers().get("x-real-ip") {
            real_ip.to_str().ok().and_then(|ip_str| ip_str.parse().ok())
        } else {
            None
        };

        if let Some(client_ip) = client_ip {
            println!("Client IP: {}", client_ip);

            // 如果设置了 allowed_ips 列表，则检查客户端 IP 是否在列表中
            if let Some(allowed_ips) = &self.allowed_ips {
                let ip_allowed = allowed_ips.iter().any(|allowed_ip| match (allowed_ip, client_ip) {
                    (IpAddr::V4(allowed_ip), IpAddr::V4(client_ip)) => {
                        // 使用包含关系判断 IPv4 子网
                        Ipv4Cidr::new(*allowed_ip, 32).unwrap().contains(&client_ip)
                    }
                    (IpAddr::V6(allowed_ip), IpAddr::V6(client_ip)) => {
                        // 使用包含关系判断 IPv6 子网
                        Ipv6Cidr::new(*allowed_ip, 128).unwrap().contains(&client_ip)
                    }
                    _ => false,
                });

                if !ip_allowed {
                    println!("Access denied for IP: {}", client_ip);
                    return Ok(Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Body::from("Access denied"))
                        .unwrap());
                }
            }
        } else {
            println!("Failed to get client IP address");
        }




        match timeout(timeout_duration, async {
            if req.method() == Method::CONNECT {
                self.process_connect(req, is_system_route, interface.clone(), gateway.clone(), timeout_duration).await
            } else {
                self.process_request(req, is_system_route, interface.clone(), gateway.clone(), timeout_duration).await
            }
        })
            .await
        {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // Timeout occurred
                println!("Request timed out");
                Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service Unavailable"))
                    .unwrap())
            }
        }
    }

    fn is_authorized(&self, req: &Request<Body>) -> bool {
        if let Some(auth_header) = req.headers().get("Proxy-Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Basic ") {
                    let encoded_credentials = &auth_str[6..];
                    if let Ok(decoded_credentials) = STANDARD.decode(encoded_credentials) {
                        let decoded_str = String::from_utf8(decoded_credentials).unwrap_or_default();
                        let credentials: Vec<&str> = decoded_str.splitn(2, ':').collect();
                        if credentials.len() == 2 {
                            let (username, password) = (credentials[0], credentials[1]);
                            return username == self.username.as_str() && password == self.password.as_str();
                        }
                    }
                }
            }
        }
        false
    }

    async fn process_connect(
        self,
        mut req: Request<Body>,
        is_system_route: bool,
        interface: String,
        gateway: String,
        timeout_duration: Duration,
    ) -> Result<Response<Body>, hyper::Error> {
        let remote_addr = match req.uri().authority().map(|auth| auth.to_string()) {
            Some(addr) => addr,
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Missing remote address"))
                    .unwrap());
            }
        };

        let client_upgrade = match req.extensions_mut().remove::<OnUpgrade>() {
            Some(upgrade) => upgrade,
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Connection not upgradeable"))
                    .unwrap());
            }
        };



        let addrs = match remote_addr.to_socket_addrs() {
            Ok(addrs) => addrs.collect::<Vec<_>>(),
            Err(e) => {
                println!("Invalid address: {}: {:?}", remote_addr, e);
                return Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service Unavailable"))
                    .unwrap());
            }
        };

        if addrs.is_empty() {
            println!("No valid addresses resolved");
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from("Service Unavailable"))
                .unwrap());
        }

        let addr = addrs[0];
        // 替换原有的 TcpSocket 创建代码
        let socket = match addr {
            SocketAddr::V4(_) => TcpSocket::new_v4().unwrap(),
            SocketAddr::V6(_) => TcpSocket::new_v6().unwrap(),
        };



        let bind_addr = match addr {
            SocketAddr::V4(_) => {

                get_rand_ipv4_socket_addr(&self.ipv4_subnets)

            },
            SocketAddr::V6(_) => {

                get_rand_ipv6_socket_addr(&self.ipv6_subnets)

            },
        };

        // 如果指定了接口，则绑定到接口
        if let Some(ref bind_iface) = self.bind_interface {
            println!("Binding to interface {}", bind_iface);

            // 将TcpSocket转换为socket2::Socket以使用bind_device
            let interface_name = bind_iface.as_str();
            let socket_fd = socket.as_raw_fd();
            let socket2 = unsafe { socket2::Socket::from_raw_fd(socket_fd) };

            // 绑定到指定接口
            if let Err(e) = socket2.bind_device(Some(interface_name.as_bytes())) {
                println!("Failed to bind to interface {}: {:?}", interface_name, e);
                // 不要退出，继续尝试连接
            }

            // 重要：防止socket关闭（转移所有权但不关闭原始fd）
            std::mem::forget(socket2);

            // 不需要再绑定IP地址，因为我们已经绑定了接口
        } else {
            // 如果没有指定接口，则继续使用原来的IP绑定方式
            println!("Binding to address {}", bind_addr);
            if socket.bind(bind_addr).is_err() {
                println!("Failed to bind to address {}", bind_addr);
                return Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service Unavailable"))
                    .unwrap());
            }
        }



        println!("Binding to address {}", bind_addr);

        if is_system_route {
            let cmd_str = format!(
                "ip addr add {}/{} dev {}",
                bind_addr.ip(),
                if bind_addr.is_ipv6() {
                    128
                } else {
                    32
                },
                interface
            );
            self.execute_command(cmd_str).await;

            if !gateway.is_empty() {
                let cmd_traceroute_str = format!("traceroute -m 10 -s {} {}", bind_addr.ip(), gateway);
                self.execute_command(cmd_traceroute_str).await;
            }

            {
                let mut queue = self.address_queue.lock().await;
                queue.push_back(bind_addr.ip().to_string());
            }

            self.manage_address_count(&interface,timeout_duration).await;
        }



        let connect_result = timeout(timeout_duration, socket.connect(addr)).await;
        let mut server = match connect_result {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                println!("Failed to connect to server: {:?}", e);
                return Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service Unavailable"))
                    .unwrap());
            }
            Err(_) => {
                println!("Connection to {} timed out", remote_addr);
                return Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service Unavailable"))
                    .unwrap());
            }
        };
        tokio::spawn(async move {
            match timeout(timeout_duration, tokio::io::copy_bidirectional(&mut client_upgrade.await.unwrap(), &mut server)).await {
                Ok(Ok((client_bytes, server_bytes))) => {
                    println!("Client wrote {} bytes, server wrote {} bytes", client_bytes, server_bytes);

                }
                Ok(Err(err)) => {
                    println!("Tunnel error: {:?}", err);

                }
                Err(_) => {
                    println!("Tunnel timed out");
                }
            }
        });
        Ok(Response::new(Body::empty()))

    }


    async fn process_request(
        self,
        req: Request<Body>,
        is_system_route: bool,
        interface: String,
        gateway: String,
        timeout_duration: Duration,
    ) -> Result<Response<Body>, hyper::Error> {


        let bind_addr = if let Some(host) = req.uri().host() {
            let addr_str = format!("{}:{}", host, req.uri().port_u16().unwrap_or(80));

            match tokio::net::lookup_host(addr_str).await {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        match addr {
                            SocketAddr::V4(_) => {
                                // Host resolves to an IPv4 address, select from IPv4 subnets
                                if let Some(ipv4_cidr) = self.ipv4_subnets.choose(&mut rand::thread_rng()) {
                                    get_rand_ipv4_socket_addr(std::slice::from_ref(ipv4_cidr)).ip()
                                } else {
                                    IpAddr::V4(Ipv4Addr::LOCALHOST) // Fallback to IPv4 loopback address (127.0.0.1)
                                }
                            }
                            SocketAddr::V6(_) => {
                                // Host resolves to an IPv6 address, select from IPv6 subnets
                                if let Some(ipv6_cidr) = self.ipv6_subnets.choose(&mut rand::thread_rng()) {
                                    get_rand_ipv6_socket_addr(std::slice::from_ref(ipv6_cidr)).ip()
                                } else {
                                    IpAddr::V6(Ipv6Addr::LOCALHOST) // Fallback to IPv6 loopback address (::1)
                                }
                            }
                        }
                    } else {
                        // No valid address found, fallback to loopback
                        if self.ipv6_subnets.is_empty() {
                            IpAddr::V4(Ipv4Addr::LOCALHOST) // Default to IPv4 loopback
                        } else {
                            IpAddr::V6(Ipv6Addr::LOCALHOST) // Default to IPv6 loopback
                        }
                    }
                }
                Err(_) => {
                    // Error during lookup, fallback to loopback
                    if self.ipv6_subnets.is_empty() {
                        IpAddr::V4(Ipv4Addr::LOCALHOST) // Default to IPv4 loopback
                    } else {
                        IpAddr::V6(Ipv6Addr::LOCALHOST) // Default to IPv6 loopback
                    }
                }
            }
        } else {
            // Fallback if there is no host in the URI
            if self.ipv6_subnets.is_empty() {
                IpAddr::V4(Ipv4Addr::LOCALHOST) // Default to IPv4 loopback
            } else {
                IpAddr::V6(Ipv6Addr::LOCALHOST) // Default to IPv6 loopback
            }
        };
        let local_ip = match self.bind_interface {
            Some(ref bind_iface) => {
                // 尝试获取接口 IP
                if let Some(interface_ip) = get_interface_ip(bind_iface.as_str()) {
                    println!("Using IP {} from interface {} for HTTP connection",
                             interface_ip, bind_iface);
                    interface_ip
                } else {
                    // println!("Could not get IP for interface {}, using fallback IP", bind_iface);
                    // 设置为127.0.0.1
                    if bind_addr.is_ipv4() {
                        IpAddr::V4(Ipv4Addr::LOCALHOST)
                    } else {
                        IpAddr::V6(Ipv6Addr::LOCALHOST)
                    }

                }
            }
            None => bind_addr,
        };


        let http = match self.bind_interface {
            Some(ref bind_iface) => {
                println!("Creating custom connector with interface binding to {}", bind_iface);

                // 创建一个自定义连接器
                let mut connector = hyper::client::HttpConnector::new();
                connector.set_local_address(Some(local_ip));

                // 创建一个Socket2连接器包装器
                Socket2Connector::new(connector, Some(bind_iface.as_str()))
            }
            None => {
                // 如果没有指定接口，就使用标准HttpConnector
                let mut connector = hyper::client::HttpConnector::new();
                connector.set_local_address(Some(local_ip));
                Socket2Connector::new(connector, None)
            }
        };



        // let mut http = HttpConnector::new();

        // http.set_local_address(Some(local_ip));
        println!("{} via {}", req.uri().host().unwrap_or_default(), local_ip);

        if is_system_route {
            let cmd_str = format!(
                "ip addr add {}/{} dev {}",
                bind_addr,
                if bind_addr.is_ipv6() { 128 } else { 32 },
                interface
            );
            self.execute_command(cmd_str).await;

            if !gateway.is_empty() {
                let cmd_traceroute_str = format!("traceroute -m 10 -s {} {}", bind_addr, gateway);
                self.execute_command(cmd_traceroute_str).await;
            }

            {
                let mut queue = self.address_queue.lock().await;
                queue.push_back(bind_addr.to_string());
            }

            self.manage_address_count(&interface, timeout_duration).await;
        }

        // Apply timeout to the HTTP request process
        match timeout(timeout_duration, async {
            // println!("Building HTTP client...");
            let client = Client::builder()
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .build(http);

            // println!("Sending request to {}...", req.uri());
            let response_result = client.request(req).await;

            match &response_result {
                Ok(res) => println!("Received response with status: {}", res.status()),
                Err(e) => println!("Error sending request: {:?}", e),
            }

            response_result
        })
            .await
        {
            Ok(Ok(res)) => {
                // println!("Successfully processed request");
                Ok(res)
            },
            Ok(Err(e)) => {
                println!("HTTP error: {:?}", e);
                Err(e)
            },
            Err(_) => {
                println!("Request processing timed out");
                Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service Unavailable"))
                    .unwrap())
            }
        }
    }

    async fn manage_address_count(&self, interface: &str, timeout_duration: Duration) {


        match timeout(timeout_duration, self.address_queue.lock()).await {
            Ok(mut queue) => {
                eprintln!("Acquired lock {}", queue.len());
                if queue.len() > MAX_ADDRESSES {
                    let addresses_to_remove = queue.len() - MAX_ADDRESSES;

                    for _ in 0..addresses_to_remove {
                        if let Some(addr) = queue.pop_front() {
                            let cmd_str = format!("ip addr del {}/{} dev {}", addr, if addr.contains(":") { 128 } else { 32 }, interface);
                            if let Err(e) = self.execute_command_del(cmd_str.clone()).await {
                                eprintln!("Failed to execute command {}: {:?}", cmd_str, e);
                            }
                        }
                    }
                }
            }
            Err(_) => {
                eprintln!("Failed to acquire lock within timeout period");
            }
        }
    }

    async fn execute_command_del(&self, cmd_str: String) -> Result<(), Box<dyn Error>> {
        let output = Command::new("sh")
            .arg("-c")
            .arg(cmd_str)
            .output()
            .await?;

        if output.status.success() {
            Ok(())
        } else {
            Err(format!("Command failed with status: {:?}", output.status).into())
        }
    }

    async fn execute_command(&self, cmd_str: String) {
        println!("{cmd_str} ");
        task::spawn(async move {
            let _result = Command::new("sh")
                .arg("-c")
                .arg(&cmd_str)
                .status()
                .await
                .map_err(|e| eprintln!("Failed to execute command: {}. Error: {}", cmd_str, e))
                .ok();
        });
    }
}

fn get_rand_ipv4_socket_addr(ipv4_subnets: &[Ipv4Cidr]) -> SocketAddr {
    let mut rng = rand::thread_rng();
    let ipv4_cidr_result = ipv4_subnets.choose(&mut rng); // 从列表中随机选择一个子网
    let ipv4_cidr = match ipv4_cidr_result {
        Some(cidr) => cidr,
        None => return SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rng.gen::<u16>()), // 如果没有子网，返回本地地址
    };
    SocketAddr::new(get_rand_ipv4(ipv4_cidr), rng.gen::<u16>())
}

fn get_rand_ipv6_socket_addr(ipv6_subnets: &[Ipv6Cidr]) -> SocketAddr {
    let mut rng = rand::thread_rng();
    let ipv6_cidr_result = ipv6_subnets.choose(&mut rng); // 从列表中随机选择一个子网
    let ipv6_cidr = match ipv6_cidr_result {
        Some(cidr) => cidr,
        None => return SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), rng.gen::<u16>()), // 如果没有子网，返回本地地址
    };
    SocketAddr::new(get_rand_ipv6(ipv6_cidr), rng.gen::<u16>())
}

fn get_rand_ipv4(ipv4_cidr: &Ipv4Cidr) -> IpAddr {
    let mut ipv4 = u32::from(ipv4_cidr.first_address());  // 使用 first_address() 获取网络地址
    if ipv4_cidr.network_length() != 32 {
        let rand: u32 = random();
        let net_part = (ipv4 >> (32 - ipv4_cidr.network_length())) << (32 - ipv4_cidr.network_length());
        let host_part = (rand << ipv4_cidr.network_length()) >> ipv4_cidr.network_length();
        ipv4 = net_part | host_part;
    }
    IpAddr::V4(ipv4.into())
}

fn get_rand_ipv6(ipv6_cidr: &Ipv6Cidr) -> IpAddr {
    let mut ipv6 = u128::from(ipv6_cidr.first_address());  // 使用 first_address() 获取网络地址
    if ipv6_cidr.network_length() != 128 {
        let rand: u128 = random();
        let net_part = (ipv6 >> (128 - ipv6_cidr.network_length())) << (128 - ipv6_cidr.network_length());
        let host_part = (rand << ipv6_cidr.network_length()) >> ipv6_cidr.network_length();
        ipv6 = net_part | host_part;
    }
    IpAddr::V6(ipv6.into())
}

fn get_interface_ip(interface_name: &str) -> Option<IpAddr> {
    match get_if_addrs() {
        Ok(if_addrs) => {
            for if_addr in if_addrs {
                if if_addr.name == interface_name {
                    match if_addr.addr {
                        IfAddr::V4(addr) => return Some(IpAddr::V4(addr.ip)),
                        IfAddr::V6(addr) => {
                            // 过滤掉链路本地地址
                            if !addr.ip.segments()[0..2].eq(&[0xfe80, 0]) {
                                return Some(IpAddr::V6(addr.ip));
                            }
                        }
                    }
                }
            }
            None
        },
        Err(_) => None,
    }
}
