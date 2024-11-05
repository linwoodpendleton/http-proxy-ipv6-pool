// httpproxy

use std::env;

fn main() {
    // 获取目标操作系统
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    match target_os.as_str() {
        "linux" => {
            // Linux 特定的链接设置
            println!("cargo:rustc-link-search=native=libcurl-impersonate-v0.6.1.x86_64-linux-gnu/");
            println!("cargo:rustc-link-lib=static=curl-impersonate-chrome");
            println!("cargo:rustc-link-lib=static=ssl");
            println!("cargo:rustc-link-lib=static=crypto");
            println!("cargo:rustc-link-lib=static=pthread");
            println!("cargo:rustc-link-lib=static=dl");
            println!("cargo:rustc-link-lib=static=z");
        },
        "macos" => {
            // macOS 特定的链接设置
            println!("cargo:rustc-link-search=native=libcurl-impersonate-v0.6.1.x86_64-macos/");
            println!("cargo:rustc-link-lib=static=curl-impersonate-chrome");
            println!("cargo:rustc-link-lib=static=ssl");
            println!("cargo:rustc-link-lib=static=crypto");
            println!("cargo:rustc-link-lib=static=pthread");
            println!("cargo:rustc-link-lib=static=dl"); // 注意：macOS 上 libdl 可能不是必需的
            println!("cargo:rustc-link-lib=static=z");
        },
        other => {
            panic!("Unsupported target OS: {}", other);
        }
    }

    // 如果需要根据不同的 CPU 架构进一步区分，可以在此添加更多条件
}
