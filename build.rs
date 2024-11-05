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

            println!("cargo:rustc-link-lib=static=curl-impersonate-chrome");

        },
        "macos" => {
            // macOS 特定的链接设置
            println!("cargo:rustc-link-search=native=libcurl-impersonate-v0.6.1.x86_64-macos/");
            println!("cargo:rustc-link-lib=static=curl-impersonate-chrome");
            // 静态链接 libnghttp2、Brotli 和其他依赖库
            println!("cargo:rustc-link-lib=static=nghttp2");
            println!("cargo:rustc-link-lib=static=brotlidec");

            // 静态链接 OpenSSL
            println!("cargo:rustc-link-lib=static=ssl");
            println!("cargo:rustc-link-lib=static=crypto");

            // 静态链接其他系统库
            println!("cargo:rustc-link-lib=dylib=pthread");
            println!("cargo:rustc-link-lib=dylib=dl");
            println!("cargo:rustc-link-lib=dylib=m");
            println!("cargo:rustc-link-lib=dylib=util");
            println!("cargo:rustc-link-lib=dylib=rt");

        },
        other => {
            panic!("Unsupported target OS: {}", other);
        }
    }

    // 如果需要根据不同的 CPU 架构进一步区分，可以在此添加更多条件
}
