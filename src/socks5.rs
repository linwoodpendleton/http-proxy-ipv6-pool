use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::error::Error;
use std::net::{SocketAddr, IpAddr};
use rand::random;
use rand::seq::SliceRandom;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;
use lazy_static::lazy_static;
use std::io;
use cidr::{Ipv4Cidr, Ipv6Cidr};

lazy_static! {
    static ref SOCKS5_ADDRESS_QUEUE: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
}

const SOCKS_VERSION: u8 = 0x05;
const RESERVED: u8 = 0x00;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERNAME_PASSWORD: u8 = 0x02;

const AUTH_VERSION: u8 = 0x01;
const AUTH_SUCCESS: u8 = 0x00;
const AUTH_FAILURE: u8 = 0x01;

pub async fn start_socks5_proxy(
    listen_addr: SocketAddr,
    ipv6_subnets: Arc<Vec<Ipv6Cidr>>,
    ipv4_subnets: Arc<Vec<Ipv4Cidr>>,
    allowed_ips: Option<Vec<IpAddr>>,
    username: String,
    password: String,
) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(listen_addr).await?;
    println!("SOCKS5 proxy listening on {}", listen_addr);

    let auth_enabled = !username.is_empty() && !password.is_empty();

    loop {
        let (mut socket, addr) = listener.accept().await?;

        if let Some(ref allowed_ips) = allowed_ips {
            let ip_allowed = allowed_ips.iter().any(|allowed_ip| match (allowed_ip, addr.ip()) {
                (IpAddr::V4(allowed_ip), IpAddr::V4(client_ip)) => {
                    Ipv4Cidr::new(*allowed_ip, 32).unwrap().contains(&client_ip)
                }
                (IpAddr::V6(allowed_ip), IpAddr::V6(client_ip)) => {
                    Ipv6Cidr::new(*allowed_ip, 128).unwrap().contains(&client_ip)
                }
                _ => false,
            });

            if !ip_allowed {
                eprintln!("Access denied for IP: {}", addr.ip());
                continue;
            }
        }

        let ipv6_subnets = Arc::clone(&ipv6_subnets);
        let ipv4_subnets = Arc::clone(&ipv4_subnets);

        let username = username.clone();
        let password = password.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_socks5_connection(&mut socket, &ipv6_subnets, &ipv4_subnets, &username, &password, auth_enabled).await {
                eprintln!("Failed to handle SOCKS5 connection: {}", e);
            }
        });
    }
}

async fn handle_socks5_connection(
    socket: &mut TcpStream,
    ipv6_subnets: &[Ipv6Cidr],
    ipv4_subnets: &[Ipv4Cidr],
    expected_username: &str,
    expected_password: &str,
    auth_enabled: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0; 2];
    socket.read_exact(&mut buf).await?;

    if buf[0] != SOCKS_VERSION {
        return Err("Unsupported SOCKS version".into());
    }

    let nmethods = buf[1] as usize;
    let mut methods = vec![0; nmethods];
    socket.read_exact(&mut methods).await?;

    let selected_method = if auth_enabled {
        if methods.contains(&METHOD_USERNAME_PASSWORD) {
            METHOD_USERNAME_PASSWORD
        } else {
            0xFF  // No acceptable method if auth is enabled but username/password is not supported
        }
    } else if methods.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else {
        0xFF  // No acceptable method if only no auth is supported but no auth method is provided
    };

    socket.write_all(&[SOCKS_VERSION, selected_method]).await?;

    if selected_method == METHOD_USERNAME_PASSWORD {
        if !authenticate(socket, expected_username, expected_password).await? {
            socket.write_all(&[AUTH_VERSION, AUTH_FAILURE]).await?;
            return Err("Authentication failed".into());
        }
        socket.write_all(&[AUTH_VERSION, AUTH_SUCCESS]).await?;
    } else if selected_method == 0xFF {
        return Err("No acceptable authentication method".into());
    }

    let mut buf = [0; 4];
    socket.read_exact(&mut buf).await?;

    let (addr, bind_addr) = match buf[3] {
        0x01 => {
            let mut ipv4 = [0; 4];
            socket.read_exact(&mut ipv4).await?;
            let port = read_port(socket).await?;
            let addr = SocketAddr::new(IpAddr::V4(ipv4.into()), port);
            let bind_addr = get_rand_ipv4_socket_addr(ipv4_subnets);
            (addr, bind_addr)
        }
        0x03 => {
            let mut domain_len = [0; 1];
            socket.read_exact(&mut domain_len).await?;
            let mut domain = vec![0; domain_len[0] as usize];
            socket.read_exact(&mut domain).await?;
            let port = read_port(socket).await?;
            let domain = String::from_utf8(domain)?;
            let addr_str = format!("{}:{}", domain, port);

            let addr = tokio::net::lookup_host(addr_str).await?.next().ok_or("Invalid domain name")?;

            let bind_addr = match addr {
                SocketAddr::V4(_) => get_rand_ipv4_socket_addr(ipv4_subnets),
                SocketAddr::V6(_) => get_rand_ipv6_socket_addr(ipv6_subnets),
            };
            (addr, bind_addr)
        }
        0x04 => {
            let mut ipv6 = [0; 16];
            socket.read_exact(&mut ipv6).await?;
            let port = read_port(socket).await?;
            let addr = SocketAddr::new(IpAddr::V6(ipv6.into()), port);
            let bind_addr = get_rand_ipv6_socket_addr(ipv6_subnets);
            (addr, bind_addr)
        }
        _ => return Err("Unsupported address type".into()),
    };

    let socket_type = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };

    socket_type.bind(bind_addr)?;

    let mut remote = socket_type.connect(addr).await?;

    let reply = SocksReply::new(ResponseCode::Success);
    reply.send(socket).await?;

    tokio::io::copy_bidirectional(socket, &mut remote).await?;
    Ok(())
}

async fn authenticate(socket: &mut TcpStream, expected_username: &str, expected_password: &str) -> Result<bool, Box<dyn Error>> {
    let mut version = [0; 1];
    socket.read_exact(&mut version).await?;
    if version[0] != AUTH_VERSION {
        return Ok(false);
    }

    let mut ulen = [0; 1];
    socket.read_exact(&mut ulen).await?;
    let mut uname = vec![0; ulen[0] as usize];
    socket.read_exact(&mut uname).await?;

    let mut plen = [0; 1];
    socket.read_exact(&mut plen).await?;
    let mut passwd = vec![0; plen[0] as usize];
    socket.read_exact(&mut passwd).await?;

    if &uname == expected_username.as_bytes() && &passwd == expected_password.as_bytes() {
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn read_port(socket: &mut TcpStream) -> Result<u16, Box<dyn Error>> {
    let mut buf = [0; 2];
    socket.read_exact(&mut buf).await?;
    Ok(u16::from_be_bytes(buf))
}

fn get_rand_ipv4_socket_addr(ipv4_subnets: &[Ipv4Cidr]) -> SocketAddr {
    let mut rng = rand::thread_rng();
    let ipv4_cidr = ipv4_subnets.choose(&mut rng).unwrap();
    let ip_addr = get_rand_ipv4(ipv4_cidr);
    SocketAddr::new(ip_addr, random::<u16>())
}

fn get_rand_ipv6_socket_addr(ipv6_subnets: &[Ipv6Cidr]) -> SocketAddr {
    let mut rng = rand::thread_rng();
    let ipv6_cidr = ipv6_subnets.choose(&mut rng).unwrap();
    let ip_addr = get_rand_ipv6(ipv6_cidr);
    SocketAddr::new(ip_addr, random::<u16>())
}

fn get_rand_ipv4(ipv4_cidr: &Ipv4Cidr) -> IpAddr {
    let mut ipv4 = u32::from(ipv4_cidr.first_address());
    if ipv4_cidr.network_length() != 32 {
        let rand: u32 = random();
        let net_part = (ipv4 >> (32 - ipv4_cidr.network_length())) << (32 - ipv4_cidr.network_length());
        let host_part = (rand << ipv4_cidr.network_length()) >> ipv4_cidr.network_length();
        ipv4 = net_part | host_part;
    }
    IpAddr::V4(ipv4.into())
}

fn get_rand_ipv6(ipv6_cidr: &Ipv6Cidr) -> IpAddr {
    let mut ipv6 = u128::from(ipv6_cidr.first_address());
    if ipv6_cidr.network_length() != 128 {
        let rand: u128 = random();
        let net_part = (ipv6 >> (128 - ipv6_cidr.network_length())) << (128 - ipv6_cidr.network_length());
        let host_part = (rand << ipv6_cidr.network_length()) >> ipv6_cidr.network_length();
        ipv6 = net_part | host_part;
    }
    IpAddr::V6(ipv6.into())
}

struct SocksReply {
    buf: [u8; 10],
}

impl SocksReply {
    pub fn new(status: ResponseCode) -> Self {
        let buf = [
            SOCKS_VERSION,
            status as u8,
            RESERVED,
            0x01,
            0, 0, 0, 0,
            0, 0,
        ];
        Self { buf }
    }

    pub async fn send<T>(&self, stream: &mut T) -> io::Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        stream.write_all(&self.buf).await?;
        Ok(())
    }
}

#[derive(Debug)]
enum ResponseCode {
    Success = 0x00,
}
