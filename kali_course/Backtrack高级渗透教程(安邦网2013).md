## 目录
* [一、01 BT5简介](#一01BT5简介)  
* [二、02 BT5的安装及基本配置](#二02BT5的安装及基本配置)  
* [三、03 信息收集](#三03信息收集)  
* [四、04 漏洞评估](#四04漏洞评估)  



***
### 一、01 BT5简介

### 二、02 BT5的安装及基本配置
#### 1、渗透测试步骤
* 目标范围划定
* 信息收集
* 目标发现
* 目标枚举
* 漏洞利用
* 提升权限
* 持续控制
* 文档及报告
#### 2、入侵步骤
* 域攻击
    * 踩点扫描
        * 常规信息获取
            * 信息收集
                ping/telnet/whois/traceroute/nslookup
            * 端口扫描
                nmap
        * 漏洞扫描
            X-scan
        * 社会工程学
        * 搜索引擎
            goolge/baidu
* 攻击
    * DoS/DDos
    * 远程渗透
        * 远程口令猜测
            NAT
        * 远程溢出
        * 应用攻击
            SQL注入/目录遍历
* 后攻击
    * 权限提升
        * 本地溢出
        * 口令渗透
        * 本地口令猜解
    * 维持攻击
        * 后门维持
            nc
        * 维持设置
            ftp代理
        * 痕迹擦除
#### 3、配置IP地址
```
    ip addr
    ipconfig eth0 192.168.1.111 netmask 255.255.255.0 
```
#### 4、配置路由
```
    route add -net X.X.X.X netmask X.X.X.X gw X.X.X.X
    route del -net X.X.X.X netmask X.X.X.X
```
#### 5、配置SSH
```
    vi /etc/ssh/sshd_config
    PasswordAuthentication yes
    PermitRootLogin yes

    sshd-generate
    service ssh start

    apt-get install sysv-rc-conf
    sysv-rc-conf
    //ssh自启动配置
```
#### 6、安装中文输入法
```
    apt-get install language-pack-zh language-support-zh
```
#### 7、翻墙
```
    apt-get install network-manager-gnome
    apt-get install network-manager-pptp
    apt-get install network-manager-vpnc
    cp /etc/network/interfaces /etc/network/interface.backup
    echo "auto lo" > /etc/network/interfaces
    echo "iface lo inet loopback" >> /etc/network/interfaces
    service network-manager restart
    //注：安装并重启network-manager后，gnone菜单右上角出现网络图标，点击添加VPN即可

    pptpsetup --create HK --server 1.1.1.1 --username test --password test --encrypt --start
    //拨入方式
```
### 三、03 信息收集
#### 1、DNS收集信息
DNS域名系统（Domain Name System）是因特网的一项核心服务，它作为可以将域名和IP地址相互映射的一个分布式数据库，能够使人更方便的访问互联网，而不用去记住能够被机器直接读取的IP数串。
##### 1）DNS解析方式，如下：
* 递归解析：上级域名服务器没有找到域名时，由上级域名服务器发送请求给更上一级域名服务器，直到找到为止
* 反复解析：域名服务器没有找到域名时，通知客户端其他的域名服务器“可能”知道此域名，客户端再向其他域名服务器发送请求，直到找到为止
##### 2）DNS资源类型
* SOA起始授权机构：此记录指定区域的起点。它所包含的信息有区域名、区域管理员电子邮件地址，以及指示辅DNS服务器如何更新区域数据文件的设置等
* A地址：此记录列出特定主机名的IP地址。这时名称解析的重要记录
* CNAME标准名称：此记录指定标准主机名的别名
* MX邮件交换器：此记录列出了负责接收发到域中的电子邮件的主机
* NS名称服务器：此记录指定负责给定区域的名称服务器
```
    nslookup
    www.baidu.com
    set type=mx
    mail.163.com
    set type=all
```
##### 3）Dig信息收集
```
    dig
    dig @DNSserver XXX.com AXFR
    dig XXX.com +nssearch
    dig XXX.com +trace
    dig XXX.com -t ns
```
##### 4）Dnsenum信息收集
* get the host's address(A record)
* get the nameserver
* get the MX record
* perform axfr quenes on namservers and get bind version
* get extra names and subdomain via google scripting
* bruteforce subdomain from file,can also perform recursive on subdomain that have NS record
* calculate C class domain networkranges and perform whois quenes on them
* perform reverse lookup on netrange
* write to domain_ips txt file ip-blocks
```
    ./dnsenum.pl --dnsserver 8.8.8.8 wikipedia.org
    ./dnsenum.pl --dnsserver 8.8.8.8 cisco.com -f dns.txt
```
##### 5）dnswalk信息收集
a DNS debugger.It performs zone transfers of specified domain,and checks the databases in numerous ways for internal consistency,as well as accuracy
```
    ./dnswalk wkipedia.org.
```
##### 6）lbd
查看负载均衡load balance
```
    ./lbd.sh google.com
```
#### 2、WEB收集信息
##### 1）whois
    http://tool.chinaz.com/
##### 2）netcraft
    http://searchdns.netcraft.com
##### 3）wahtweb
WhatWeb a next generation web scanner.WhatWeb recognises web technologies including content management systems(CMS),bloggingplatforms,statistic/analytics packages,JavaScriptlibraries,web servers,and embedded devices.WhatWeb has over 1000 plugins,each to recognise something different.WhatWeb also identifies version numbers,email addresses,account IDs,web framework modules,SQL errors,and more
```
    ./whatweb -v http://www.discuz.net
```
##### 4）curl
```
    curl -I www.anquan580.com
    curl -T a.txt ftp://aaa:aaa@1.1.1.1
```
##### 5）waffit
WAFW00F allows one to identify and fingerprint WAF products protecting a website
```
    python wafw00f.py http://www.baidu.com
```
##### 6）GOOGLE HACKER
```
    site anquan580.com inurl test
    inurl .action site anquan580.com
    filetype action
    hack -baidu & +google
```
#### 3、网络收集信息
##### 1）arping
```
    arping 192.168.1.1
```
##### 2）fping
```
    fping -a -g 192.168.1.0/24 > a.txt
    //fping后可以使用nmap -iL a.txt -sP
```
##### 3）hping
hping is a commandline oriented TCP/IP packet assembler/analyzer.The interfaces imspired to the ping unix command,but hping isn't only able to send ICMPecho requests.It supports TCP、UDP、ICMP and RAW-IP protocols,has a traceroutemode,the ability to send files between a covered channel,and many otherfeatures
* firewall testing
* advanced port scanning
* network testing,using different protocols,TOS,fragmentation
* manual path MTU discovery
* advanced traceroute,under all the supported protocols
* remote os fingerprinting
* remote uptime guessing
* TCP/IP stacks auditing
* hping can also be useful to students that are learning TCP/IP
```
    hping3 -a 1.1.1.1 192.168.1.1
    hping3 -a 1.1.1.1 192.168.1.1 -R -A -S
    hping3 -a 1.1.1.1 192.168.1.1 -b
    hping3 -a 1.1.1.1 192.168.1.1 -e "lion_00"
```
##### 4）fragroute
可以测试IDS和IPS
```
    fragroute -f test.conf 192.168.1.112
    注：根据test.conf配置规则,如下：
    dup last 100
    print
    order reverse
    ip_ttl 100
    echo lion_00
    delay first 2
```
##### 5）traceroute

TTL=64 linux
TTL=128 windows
TTL=50 其他机器

##### 6）netifera

##### 7）maltego

##### 8）sslscan
```
    CA->证书->公钥、私钥
    PKI加密模型：通信双方都有各自的公钥和私钥，一方有另一方的公钥，加密后，传送给另一方，另一方通过自己的私钥解密，显示明文
    PKI签名模型：通信双方都有各自的公钥和私钥，一方通过自己的私钥进行签名，另一方有对方的公钥，传送给另一方后，另一方通过对方的公钥进行验证，验证成功显示明文
```
##### 9）TCPIP
* IP
![IP](/image/IP.png "IP")
* TCP
![TCP](/image/TCP.png "TCP")
##### 10）tcpdump抓包
* HUB模式：可以直接对另外两台计算机通信进行抓包
* 交换机模式：三种方式实现抓包：端口镜像、使交换机变成HUB、强制变成网关
```
    tcpdump udp port 123
    tcpdump host 192.168.1.1 -s 555 -w lp.cap
    注：自己到192.168.1.1的包，每个包的大小为555字节，并保存结果
    tcpdump tcp port 22 and \( host 192.168.1.1 \)
    tcpdump ip host 192.168.1.1 and ! 192.168.1.100
    tcpdump i src host 192.168.1.1
```
##### 11）wireshark

##### 12）nmap
```
    nmap -A 192.168.1.100
    注：全扫描
    nmap -sP -iL 1.txt
    注：使用ping扫描（-sP同-sn），扫描1.txt中的地址 
    nmap -PS 80 -iL 1.txt
    注：对80端口进行TCP SYN/ACK、UDP或SCTP扫描
    nmap -p 1-65535 192.168.1.201 --reason
    注：1-6553端口的SYN扫描(同-sS)，--reason查看扫描类型
    nmap -sA -p 135,449,5000,3389 192.168.1.201 --reason
    注：指定端口的ACK扫描
    nmap -sT -p 135,449,5000,3389 192.168.1.201 --reason
    注：指定端口TCP全扫描
    nmap -p1-65535 192.168.1.233 -sV
    注：扫描版本
    nmap -p21 --scanflags SYNFINACK 192.168.1.201
    注：同时进行SYN/FIN/ACK扫描
    nmap -A 192.168.1.201 --script=smb-check-vulns.nse
    注：使用脚本扫描
    nmap -A 192.168.1.201 --script=mysql-brute.nse 
    nmap -p3306 192.168.1.201 --script=mysql-databases.nse --script-args=mysqluser=root,mysqlpass=111
    nmap 192.168.1.201 -O --osscan-guess
    注：对计算机进行猜测
    nmap -p3389 -S 1.1.1.1 --spoof-mac cisco 192.168.1.100 -e eth0
    注：伪装1.1.1.1发包扫描
```
### 四、04 漏洞评估
#### 1、nessus

#### 2、burp

#### 3、sqlmap




