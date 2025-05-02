~~修改并增加了-s 选项.~~



已经移除了-s 选项.使用了其它方案动态调用代替, 不在维护



使用方法,以下仅为我保存备份. 请参考原作者的说明
增加 -n 参数 绑定网络接口 当设置了-n参数时.绑定IP参数无效.所以想绑定IP不要设置设置此参数
```shell
./httpproxy -b 127.0.0.1:51080 -i 2a12:bec0:165:106::/64,2a00:bec0:165:106::/64 -s eth0 -g 2001:4860:4860::8888 -n eth1
```
增加了ipv4的支持 -v 允许IP设置 -a socks5代理地址 --socks5 基本验证设置 -u username -p password
```shell
./httpproxy  -b 127.0.0.1:51080 --socks5 127.0.0.1:51081 -v 192.168.1.203/32,192.168.0.1/24 -a 127.0.0.1,192.168.0.1 -n eth1
```


# 编译指南

本文档介绍如何在 **x86_64-unknown-linux-musl** 和 **aarch64-unknown-linux-musl** 两个平台上静态编译 `http-proxy-ipv6-pool`。

---

## 前提依赖

- Ubuntu/Debian 环境
- 安装必要工具
  ```bash
  sudo apt update
  sudo apt install build-essential pkg-config libssl-dev libcurl4-openssl-dev git curl wget
  ```

## 获取源码

```bash
git clone https://github.com/linwoodpendleton/http-proxy-ipv6-pool.git
cd http-proxy-ipv6-pool
```

## 生成 C 静态库 `libcurl_wrapper.a`

1. 编译 C 源：
   ```bash
   gcc -c -o curl_callbacks.o curl_callbacks.c
   gcc -c -o curl_wrapper.o curl_wrapper.c
   ```
2. 打包静态库：
   ```bash
   ar rcs libcurl_wrapper.a curl_callbacks.o curl_wrapper.o
   ```
3. 将产物移动到对应目录：
    - **x86_64-musl** 平台：`libcurl-impersonate-v0.6.1.x86_64-linux-musl/`
    - **aarch64-musl** 平台：`libcurl-impersonate-v0.8.2.aarch64-linux-musl/`
   ```bash
   mv curl_callbacks.o curl_wrapper.o libcurl_wrapper.a libcurl-impersonate-.../
   ```

---

## x86_64-unknown-linux-musl 静态编译

1. 安装 musl 和交叉工具链：
   ```bash
   # 方式一：安装 musl-tools
   sudo apt install musl-tools

   # 方式二：使用 musl-cross-make
   git clone https://github.com/richfelker/musl-cross-make.git
   cd musl-cross-make
   make TARGET=x86_64-linux-musl install
   export PATH=/home/parallels/musl-cross-make/output/bin/:$PATH
   ```
2. 导出环境变量：
   ```bash
   export CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc
   export AR_x86_64_unknown_linux_musl=x86_64-linux-musl-ar
   export PKG_CONFIG_ALLOW_CROSS=1
   export PKG_CONFIG_PATH=/usr/local/musl/lib/pkgconfig
   export OPENSSL_DIR=/usr/lib/ssl
   export OPENSSL_INCLUDE_DIR=/usr/include/openssl
   export OPENSSL_LIB_DIR=/usr/lib
   export OPENSSL_STATIC=1
   ```
3. 配置 Cargo：
   在项目根目录创建 `.cargo/config.toml`：
   ```toml
   [build]
   target = "x86_64-unknown-linux-musl"

   [target.x86_64-unknown-linux-musl]
   linker = "x86_64-linux-musl-g++"
   ar     = "x86_64-linux-musl-ar"
   ```
4. 添加 Rust 目标并编译：
   ```bash
   rustup target add x86_64-unknown-linux-musl
   cargo clean
   cargo build --release --target x86_64-unknown-linux-musl
   ```
5. 可执行文件位于：
   ```bash
    target/x86_64-unknown-linux-musl/release/http-proxy-ipv6-pool
   ```

---

## aarch64-unknown-linux-musl 静态编译

1. 安装 AArch64 musl 交叉工具链：
   ```bash
   cd musl-cross-make
   make TARGET=aarch64-linux-musl install
   export PATH=/home/parallels/musl-cross-make/output/bin/:$PATH
   ```
2. 复制 curl 头文件到交叉链 sysroot：
   ```bash
   SYSROOT=$(aarch64-linux-musl-gcc --print-sysroot)
   sudo mkdir -p $SYSROOT/include/curl
   sudo cp /usr/include/x86_64-linux-gnu/curl/*.h $SYSROOT/include/curl/
   ```
3. 导出环境变量：
   ```bash
   export CC_aarch64_unknown_linux_musl=aarch64-linux-musl-gcc
   export AR_aarch64_unknown_linux_musl=aarch64-linux-musl-ar
   export PKG_CONFIG_ALLOW_CROSS=1
   export PKG_CONFIG_PATH=$SYSROOT/lib/pkgconfig
   export OPENSSL_STATIC=1
   ```
4. 配置 Cargo：
   在 `.cargo/config.toml` 添加：
   ```toml
   [target.aarch64-unknown-linux-musl]
   linker = "aarch64-linux-musl-g++"
   ar     = "aarch64-linux-musl-ar"
   ```
5. 添加 Rust 目标并编译：
   ```bash
   rustup target add aarch64-unknown-linux-musl
   cargo clean
   cargo build --release --target aarch64-unknown-linux-musl
   ```
6. 可执行文件位于：
   ```bash
   target/aarch64-unknown-linux-musl/release/http-proxy-ipv6-pool
   ```

---

## 验证静态链接

```bash
ldd target/*/*/http-proxy-ipv6-pool
# 应显示 "not a dynamic executable"
```




# 编译说明。    
```shell
apt install libssl-dev
apt install libcurl4-openssl-dev
export OPENSSL_DIR=/usr/lib/ssl
export OPENSSL_INCLUDE_DIR=/usr/include/openssl
export OPENSSL_LIB_DIR=/usr/lib
gcc -c -o curl_callbacks.o curl_callbacks.c
gcc -c -o curl_wrapper.o curl_wrapper.c
ls
ar rcs libcurl_wrapper.a curl_callbacks.o curl_wrapper.o
mv curl_callbacks.o  libcurl-impersonate-v0.6.1.x86_64-linux-gnu/
mv curl_wrapper.o  libcurl-impersonate-v0.6.1.x86_64-linux-gnu/
mv libcurl_wrapper.a  libcurl-impersonate-v0.6.1.x86_64-linux-gnu/
cp -r libcurl-impersonate-v0.6.1.x86_64-linux-gnu/*  /usr/lib/
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"  # This loads the environment variables
cargo build #debug
cargo build --release

```

# Http Proxy IPv6 Pool

Make every request from a separate IPv6 address.

https://zu1k.com/posts/tutorials/http-proxy-ipv6-pool/

## Tutorial

Assuming you already have an entire IPv6 subnet routed to your server, for me I purchased [Vultr's server](https://www.vultr.com/?ref=9039594-8H) to get one.

Get your IPv6 subnet prefix and interface name, for me is `2001:19f0:6001:48e4::/64` and `enp1s0`.

```sh
$ ip a
......
2: enp1s0: <BROADCAST,MULTICAST,ALLMULTI,UP,LOWER_UP> mtu 1500 qdisc fq state UP group default qlen 1000
    ......
    inet6 2001:19f0:6001:48e4:5400:3ff:fefa:a71d/64 scope global dynamic mngtmpaddr 
       valid_lft 2591171sec preferred_lft 603971sec
    ......
```

Add route via default internet interface

```sh
ip route add local 2001:19f0:6001:48e4::/64 dev enp1s0
```

Open `ip_nonlocal_bind` for binding any IP address:

```sh
sysctl net.ipv6.ip_nonlocal_bind=1
```

For IPv6 NDP, install `ndppd`:

```sh
apt install ndppd
```

then edit `/etc/ndppd.conf`:


```conf
route-ttl 30000

proxy <INTERFACE-NAME> {
    router no
    timeout 500
    ttl 30000

    rule <IP6_SUBNET> {
        static
    }
}
```
(edit the file to match your configuration)

Restart the service:
```sh
service ndppd restart
```


Now you can test by using `curl`:

```sh
$ curl --interface 2001:19f0:6001:48e4::1 ipv6.ip.sb
2001:19f0:6001:48e4::1

$ curl --interface 2001:19f0:6001:48e4::2 ipv6.ip.sb
2001:19f0:6001:48e4::2
```

Great!

Finally, use the http proxy provided by this project:

```sh
$ while true; do curl -x http://127.0.0.1:51080 ipv6.ip.sb; done
2001:19f0:6001:48e4:971e:f12c:e2e7:d92a
2001:19f0:6001:48e4:6d1c:90fe:ee79:1123
2001:19f0:6001:48e4:f7b9:b506:99d7:1be9
2001:19f0:6001:48e4:a06a:393b:e82f:bffc
2001:19f0:6001:48e4:245f:8272:2dfb:72ce
2001:19f0:6001:48e4:df9e:422c:f804:94f7
2001:19f0:6001:48e4:dd48:6ba2:ff76:f1af
2001:19f0:6001:48e4:1306:4a84:570c:f829
2001:19f0:6001:48e4:6f3:4eb:c958:ddfa
2001:19f0:6001:48e4:aa26:3bf9:6598:9e82
2001:19f0:6001:48e4:be6b:6a62:f8f7:a14d
2001:19f0:6001:48e4:b598:409d:b946:17c
```

## Author

**Http Proxy IPv6 Pool** © [zu1k](https://github.com/zu1k), Released under the [MIT](./LICENSE) License.
