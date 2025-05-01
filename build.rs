// build.rs

use std::env;

fn main() {
    // 只有当脚本自身或下面这些环境变量变化时才重新运行
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_ALLOW_CROSS");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=OPENSSL_STATIC");

    // 完整目标三元组，比如 "x86_64-unknown-linux-musl"
    let target = env::var("TARGET").expect("TARGET not set");

    // 静态 musl 支持：x86_64 和 aarch64
    if target == "x86_64-unknown-linux-musl" || target == "aarch64-unknown-linux-musl" {
        // 根据架构选取对应目录
        let lib_dir = if target == "x86_64-unknown-linux-musl" {
            "libcurl-impersonate-v0.8.2.x86_64-linux-musl/"
        } else {
            "libcurl-impersonate-v0.8.2.aarch64-linux-musl/"
        };

        // 先搜索我们所有交叉编译好的 .a 文件
        println!("cargo:rustc-link-search=native={}", lib_dir);
        // 如果你把 curl_wrapper.a 放在项目根，也可以：
        println!("cargo:rustc-link-search=native=.");

        // 1) 主库：curl-impersonate
        println!("cargo:rustc-link-lib=static=curl-impersonate-chrome");
        // 2) 你的 C 包装库（提供 free_headers 等）
        println!("cargo:rustc-link-lib=static=curl_wrapper");
        // 3) 其它 C 依赖
        println!("cargo:rustc-link-lib=static=nghttp2");
        println!("cargo:rustc-link-lib=static=ssl");
        println!("cargo:rustc-link-lib=static=crypto");
        println!("cargo:rustc-link-lib=static=z");
        println!("cargo:rustc-link-lib=static=zstd");
        // 4) Brotli codec → common，保证符号顺序
        println!("cargo:rustc-link-lib=static=brotlidec");
        println!("cargo:rustc-link-lib=static=brotlienc");
        println!("cargo:rustc-link-lib=static=brotlicommon");
        // 5) C++ 运行时（stdc++/gcc/unwind）
        println!("cargo:rustc-link-lib=static=stdc++");
        println!("cargo:rustc-link-lib=static=gcc");
        println!("cargo:rustc-link-lib=static=unwind");
    }
    // GNU/Linux glibc 动态链接分支
    else if target.contains("linux") {
        println!("cargo:rustc-link-search=native=libcurl-impersonate-v0.6.1.x86_64-linux-gnu/");
        println!("cargo:rustc-link-lib=dylib=curl-impersonate-chrome");
        println!("cargo:rustc-link-lib=dylib=nghttp2");
        println!("cargo:rustc-link-lib=dylib=brotlidec");
        println!("cargo:rustc-link-lib=dylib=brotlienc");
        println!("cargo:rustc-link-lib=dylib=ssl");
        println!("cargo:rustc-link-lib=dylib=crypto");
        println!("cargo:rustc-link-lib=dylib=z");
    }
    // macOS 静态链接分支
    else if target.contains("darwin") {
        println!("cargo:rustc-link-search=native=libcurl-impersonate-v0.6.1.x86_64-macos/");
        println!("cargo:rustc-link-lib=static=curl-impersonate-chrome");
        println!("cargo:rustc-link-lib=static=nghttp2");
        println!("cargo:rustc-link-lib=static=brotlidec");
        println!("cargo:rustc-link-lib=static=ssl");
        println!("cargo:rustc-link-lib=static=crypto");
    }
    // 其他平台直接报错
    else {
        panic!("Unsupported TARGET: {}", target);
    }
}
