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












