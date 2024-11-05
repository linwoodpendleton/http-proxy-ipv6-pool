mod proxy;
mod socks5;
mod forward;

use cidr::{Ipv4Cidr, Ipv6Cidr};
use getopts::Options;
use proxy::start_proxy;
use socks5::start_socks5_proxy;
use std::{env, net::IpAddr, net::SocketAddr, process::exit};
use std::sync::Arc;
use std::time::Duration;
use forward::{parse_forward_mapping, start_forward_proxy};
fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("b", "bind", "HTTP proxy bind address", "BIND");
    opts.optopt(
        "i",
        "ipv6-subnets",
        "Comma-separated list of IPv6 subnets (e.g., 2001:19f0:6001:48e4::/64,2001:19f0:6001:48e5::/64)",
        "IPv6_SUBNETS",
    );
    opts.optopt(
        "v",
        "ipv4-subnets",
        "Comma-separated list of IPv4 subnets (e.g., 192.168.0.0/24,192.168.1.0/24)",
        "IPv4_SUBNETS",
    );
    opts.optopt(
        "a",
        "allowed-ips",
        "Comma-separated list of allowed IP addresses",
        "ALLOWED_IPS",
    );
    opts.optopt(
        "S",
        "socks5",
        "SOCKS5 proxy bind address (e.g., 127.0.0.1:51081)",
        "SOCKS5_ADDR",
    );
    opts.optopt("u", "username", "Username for SOCKS5 authentication", "USERNAME");
    opts.optopt("p", "password", "Password for SOCKS5 authentication", "PASSWORD");
    opts.optopt("t", "timeout", "Timeout duration in seconds", "TIMEOUT");  // 新增-t参数
    opts.optflag("h", "help", "Print this help menu");
    opts.optopt("r", "system_route", "Whether to use system routing instead of ndpdd. (Provide network card interface, such as eth0)", "Network Interface");
    opts.optopt("g", "gateway", "Some service providers need to track the route before it takes effect.", "Gateway");


    // 新增的 --forward 参数
    opts.optmulti(
        "",
        "forward",
        "Forwarding mapping in the format local_addr,remote_addr,sni_host[,proxy_addr1|proxy_addr2|...,proxy_type]",
        "FORWARD",
    );


    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            eprintln!("Error parsing options: {}", f);
            print_usage(&program, opts);
            exit(1);
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let system_route = matches.opt_str("r").unwrap_or_else(|| "".to_string());
    println!("System route option received: {}", system_route);

    let gateway = matches.opt_str("g").unwrap_or_else(|| "".to_string());
    println!("Gateway: {}", gateway);

    let bind_addr = matches.opt_str("b").unwrap_or_else(|| "0.0.0.0:51080".to_string());
    let socks5_bind_addr = matches.opt_str("S").unwrap_or_else(|| "127.0.0.1:51081".to_string());

    let ipv6_subnets = matches
        .opt_str("i")
        .map(|s| parse_subnets::<Ipv6Cidr>(&s))
        .unwrap_or_else(Vec::new);

    let ipv4_subnets = matches
        .opt_str("v")
        .map(|s| parse_subnets::<Ipv4Cidr>(&s))
        .unwrap_or_else(Vec::new);

    let allowed_ips = matches.opt_str("a")
        .map(|s| parse_allowed_ips(&s));

    let username = matches.opt_str("u").unwrap_or_else(|| "".to_string());
    let password = matches.opt_str("p").unwrap_or_else(|| "".to_string());

    // Parse the timeout duration from the command line arguments
    let timeout_duration = matches.opt_str("t")
        .and_then(|t| t.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(5));  // Default to 5 seconds if not specified

    let bind_addr = match bind_addr.parse() {
        Ok(b) => b,
        Err(e) => {
            println!("Bind address not valid: {}", e);
            return;
        }
    };

    let socks5_bind_addr = match socks5_bind_addr.parse::<SocketAddr>() {
        Ok(b) => b,
        Err(e) => {
            println!("SOCKS5 bind address not valid: {}", e);
            return;
        }
    };

    // 解析并存储代理映射
    let forward_mappings = matches
        .opt_strs("forward")
        .into_iter()
        .filter_map(|mapping_str| parse_forward_mapping(&mapping_str))
        .collect::<Vec<_>>();

    // 启动代理映射任务
    for mapping in forward_mappings {
        let ipv6_subnets = ipv6_subnets.clone();
        let ipv4_subnets = ipv4_subnets.clone();
        let allowed_ips = allowed_ips.clone();

        tokio::spawn(async move {
            if let Err(e) = start_forward_proxy(
                mapping.clone(),                       // 克隆 mapping
                Arc::from(ipv6_subnets),             // 克隆 Arc
                Arc::from(ipv4_subnets),             // 克隆 Arc
                allowed_ips.clone(),                   // 克隆 allowed_ips
                timeout_duration,                      // Copy 类型，无需克隆
            )
                .await
            {
                eprintln!(
                    "Forward proxy for {} encountered an error: {}",
                    mapping.local_addr, e
                );
            }
        });
    }



    let ipv6_subnets = Arc::new(ipv6_subnets);
    let ipv4_subnets = Arc::new(ipv4_subnets);

    // 启动HTTP代理和SOCKS5代理，并处理结果
    let (http_result, socks5_result) = tokio::join!(
        start_proxy(
            bind_addr,
            !system_route.is_empty(),
            gateway.clone(),
            system_route.clone(),
            ipv6_subnets.clone(),
            ipv4_subnets.clone(),
            allowed_ips.clone(),
            username.clone(),
            password.clone(),
            timeout_duration  // 传递timeout_duration
        ),
        start_socks5_proxy(socks5_bind_addr, ipv6_subnets, ipv4_subnets, allowed_ips, username, password, timeout_duration)
    );

    if let Err(e) = http_result {
        eprintln!("HTTP Proxy encountered an error: {}", e);
    }

    if let Err(e) = socks5_result {
        eprintln!("SOCKS5 Proxy encountered an error: {}", e);
    }
}

fn parse_subnets<C: std::str::FromStr>(subnets_str: &str) -> Vec<C> {
    subnets_str
        .split(',')
        .filter_map(|subnet_str| subnet_str.parse::<C>().ok())
        .collect()
}

fn parse_allowed_ips(allowed_ips_str: &str) -> Vec<IpAddr> {
    allowed_ips_str
        .split(',')
        .filter_map(|ip_str| ip_str.parse::<IpAddr>().ok())
        .collect()
}
