## 目录
* [一、BT5.2011.1.信息收集](#一BT520111信息收集)  
* [二、BT5.2011.2.扫描工具](#二BT520112扫描工具)  
* [三、BT5.2011.3.漏洞发现](#三BT520113漏洞发现)  
* [四、BT5.2011.4.社会工程学](#四BT520114社会工程学) 



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

setoolkit










