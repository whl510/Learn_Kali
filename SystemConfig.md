<div id="SystemConfig.md"></div>

一、树莓派安装（笔记本直连）
1、SD卡里面那个cmdline.txt文件里面加一个ip＝192.168.137.2 （不用换行，就在末尾空一格添加） 地址随便填，但是等会要和电脑的一个网段，然后和电脑用网线连起来，然后以太网属性，IPV4那个，把电脑地址设为静态，比如192.168.137.1
2、在SD卡根目录新建一个ssh.txt（空白内容就好）才能连ssh
3、*****主要下面操作*****
1）断开树莓派和电脑的有限连接（拔网线）
2）点开WiFi —> 属性 —> 共享 —> （关掉）允许其他网络用户通过此计算机xxx
3）重启电脑和树莓派
4）点开WiFi —> 属性 —> 共享 —> （打开）允许其他网络用户通过此计算机xxx
5）连接网线
6）arp -a查找树莓派IP


二、更新系统
#vi /etc/apt/sources.list

#阿里云kali源
deb http://mirrors.aliyun.com/kali kali-rolling main non-free contrib
deb-src http://mirrors.aliyun.com/kali kali-rolling main non-free contrib
deb http://mirrors.aliyun.com/kali-security kali-rolling/updates main contrib non-free
deb-src http://mirrors.aliyun.com/kali-security kali-rolling/updates main contrib non-free
#中科大kali源
deb http://mirrors.ustc.edu.cn/kali kali-rolling main non-free contrib
deb-src http://mirrors.ustc.edu.cn/kali kali-rolling main non-free contrib
deb http://mirrors.ustc.edu.cn/kali-security kali-current/updates main contrib non-free
deb-src http://mirrors.ustc.edu.cn/kali-security kali-current/updates main contrib non-free

#apt-get update && apt-get upgrade && apt-get dist-upgrade && apt-get clean


三、树莓派扩展工具
树莓派默认不会完整的使用整个SD卡空间，所以需要扩展分区
针对树莓派最好的扩展工具是raspi-config，在kali1的源中也是存在的，但在2.0版本中则被移除了，只好手动安装。
首先从http://archive.raspberrypi.org/debian/pool/main/r/raspi-config/下载最新的raspi-config，然后解决依赖
#apt-get install triggerhappy lua5.1 alsa-utils libfftw3-single3 psmisc
#dpkg -i raspi-config_20180406+1_all.deb
在终端输入raspi-config，连按两次确定键，重启即可(df -h显示SD卡整个空间)


四、安装kali组件
#apt-cache search kali-
#apt-get install kali-linux-all


五、wifi设置
1、第一种方式
#vi /etc/network/interfaces
auto wlan0 iface wlan0 inet dhcp wpa-ssid “your network name” wpa-psk “the network password”
