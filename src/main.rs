mod proxy;

use cidr::Ipv6Cidr;
use getopts::Options;
use proxy::start_proxy;
use std::{env, process::exit};
use std::sync::atomic::{AtomicBool, Ordering};
use proxy::SYSTEM_ROUTE;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("b", "bind", "http proxy bind address", "BIND");
    opts.optopt(
        "i",
        "ipv6-subnet",
        "IPv6 Subnet: 2001:19f0:6001:48e4::/64",
        "IPv6_SUBNET",
    );
    opts.optflag("h", "help", "print this help menu");
    opts.optopt("s", "system_route", "use system route (provide 1 to enable)", "ROUTE");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("{}", f.to_string())
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    // Parse the options
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!("Error parsing options: {}", f),
    };

    // Check if the system_route option was provided and act accordingly
    let system_route = matches.opt_str("s").unwrap_or("0".to_string());
    println!("System route option received: {}", system_route);

    let route_flag = system_route == "1";
    println!("System route option received: {}", route_flag);
    SYSTEM_ROUTE.store(route_flag, Ordering::SeqCst);

    let bind_addr = matches.opt_str("b").unwrap_or("0.0.0.0:51080".to_string());
    let ipve_subnet = matches
        .opt_str("i")
        .unwrap_or("2001:19f0:6001:48e4::/64".to_string());
    run(bind_addr, ipve_subnet)
}

#[tokio::main]
async fn run(bind_addr: String, ipv6_subnet: String) {
    let ipv6 = match ipv6_subnet.parse::<Ipv6Cidr>() {
        Ok(cidr) => {
            let a = cidr.first_address();
            let b = cidr.network_length();
            (a, b)
        }
        Err(_) => {
            println!("invalid IPv6 subnet");
            exit(1);
        }
    };

    let bind_addr = match bind_addr.parse() {
        Ok(b) => b,
        Err(e) => {
            println!("bind address not valid: {}", e);
            return;
        }
    };
    if let Err(e) = start_proxy(bind_addr, ipv6).await {
        println!("{}", e);
    }
}
