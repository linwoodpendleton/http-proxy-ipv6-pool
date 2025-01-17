~~修改并增加了-s 选项.~~



已经移除了-s 选项.使用了其它方案动态调用代替, 不在维护



使用方法,以下仅为我保存备份. 请参考原作者的说明
```shell
./httpproxy -b 127.0.0.1:51080 -i 2a12:bec0:165:106::/64,2a00:bec0:165:106::/64 -s eth0 -g 2001:4860:4860::8888
```
增加了ipv4的支持 -v 允许IP设置 -a socks5代理地址 --socks5 基本验证设置 -u username -p password
```shell
./httpproxy  -b 127.0.0.1:51080 --socks5 127.0.0.1:51081 -v 192.168.1.203/32,192.168.0.1/24 -a 127.0.0.1,192.168.0.1
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
