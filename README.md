# 0x01 Linux 系统中 FTP 服务安全防护
创建 test 普通用户并设置密码，修改登录 shell：
```
//bash
useradd test
passwd test
usermod -s /bin/sh test
```
禁用 test 用户：
```
//bash
usermod -L test
```
修改 /etc/vstpd.conf 配置文件：
```
#关闭匿名用户：在配置文件中找到 anonymous_enable=YES，改为 
anonymous_enable=NO
#限制本地用户只能在自己的家目录中活动：添加或修改
local_enable=YES 
chroot_local_user=YES。
#设置每个 IP 的最大客户端连接数目为 5：添加或修改 
max_per_ip=5。
#设置服务监听端口为 2121：找到 listen_port=21，改为
listen_port=2121
#设置客户端同时最大连接数为 100：添加或修改
max_clients=100
#设置匿名用户的家目录为 /ftphome：添加或修改
anon_root=/ftphome
#禁止所有用户进行写操作：找到 write_enable=YES，改为
write_enable=NO
```
重启vsftpd服务使配置生效
``
//bash
systemctl restart vsftpd
``


# 0x02 url-rot13-base64 解密算法：
```
VmFzYmV6bmd2YmElM jBGcnBoZXZnbCUyME5xenZhdmZnZW5nYmU=
Vasbezngvba%20Frphevgl%20Nqzvavfgengbe
Vasbezngvba Frphevgl Nqzvavfgengbe
Information Security Administrator
```

# 0x03 数据散列与 Base64 编码算法
计算字符串 “MD5 is a data digest algorithm.” 的 MD5 哈希值：使用 CyberChef 工具，在输入框中输入该字符串，选择 MD5 哈希算法进行计算，并对工具配置情况和计算结果进行截图。
计算字符串 “SHA-3is a secure hash algorithm.” 的 SHA-3 哈希值（输出长度 512）：同样在 CyberChef 工具中，输入字符串后选择 SHA-3 哈希算法，并设置输出长度为 512，然后进行计算和截图。
计算字符串 “This is anencodingtest.” 的 Base64 编码值：在 CyberChef 工具中输入字符串，选择 Base64 编码算法进行计算和截图。
使用 Base64 算法对字符串 “VGhpcyBpcyBhIGRlY29kaW5nIHRlc3Qu” 进行解码：在 CyberChef 工具中输入该字符串，选择 Base64 解码算法进行操作和截图。


# 0x04 SQL Server 数据库备份
启动虚拟机（192.168.101.104），其安装了 SQL Server 数据库（用户名、密码是 sa/Sa123456）。
SQL Server 数据库的默认服务端口为 1433。
在宿主机上配置 SSMS 工具访问数据库：打开 SSMS，在连接窗口中输入服务器名称（192.168.101.104）、用户名（sa）、密码（Sa123456），然后连接数据库，并对工具配置情况进行截图。
通过 SSMS 工具查询 master 数据库下 dbo.Company 表中 10 行数据内容：在 SSMS 中展开数据库，找到对应的表，右键选择 “编辑前 200 行”，查看并截图数据内容，同时记录该表的行数。
通过 SSMS 工具将 master 数据库 “全量备份” 到虚拟机 /var/opt/mssql/data 目录下：在 SSMS 中右键点击 master 数据库，选择 “任务” - “备份”，在备份窗口中设置备份路径为 /var/opt/mssql/data，然后执行备份操作，并对备份成功的提示进行截图。
通过 SSMS 工具 “恢复数据库” 功能对上一步中备份的文件进行验证：在 SSMS 中右键点击 “数据库”，选择 “还原数据库”，按照提示选择备份文件进行验证操作。


# 0x05 Windows 本地安全防护
禁止系统在未登录的情况下关闭：
在组策略编辑器（gpedit.msc）中，依次展开 “计算机配置” - “windows设置” - “安全设置” - “本地策略” - “安全选项”，双击 “关机：允许系统在未登录的情况下关闭”，选择 “已禁用”。

不显示最后登录的用户名：
在组策略编辑器中，依次展开 “计算机配置” - “Windows 设置” - “安全设置” - “本地策略” - “安全选项”，找到 “交互式登录：不显示最后的用户名”，设置为 “已启用”。

不允许 SAM 账户的匿名枚举：
在组策略编辑器中，同上，找到 “网络访问：不允许 SAM 账户的匿名枚举”，设置为 “已启用”。

设置只有 Administrators 组用户才能从网络访问此计算机：
在组策略编辑器中，同上，找到 “网络访问：本地账户的共享和安全模型”，设置为 “仅来宾 - 对本地用户进行身份验证，其身份为来宾”，然后在 “用户权限分配” 中找到 “从网络访问此计算机”，只保留 Administrators 组。

禁止从远程系统强制关闭计算机：
在组策略编辑器中，依次展开 “计算机配置” - “Windows 设置” - “安全设置” - “本地策略” - “用户权限分配”，找到 “从远程系统强制关机”删除所有用户组。

禁止将未加密的密码发送到第三方的 SMB 服务器：
在组策略编辑器中，依次展开 “计算机配置” - “Windows 设置” - “安全设置” - “本地策略” - “安全选项”，找到“Microsoft网络客户端：将未加密的密码发送到第三方SMB 服务器”，设置为 “已禁用”。

禁止软盘复制并访问所有的驱动器和所有文件夹：
在组策略编辑器中，同上，找到“恢复控制台：允许软盘复制并访问所有的驱动器和所有文件夹”，设置为 “已禁用”。

设置只有 Administrators 用户组才能关闭系统：
在组策略编辑器中，找到 “计算机配置” - “Windows 设置” - “安全设置” - “本地策略” - “用户权限分配” - “关闭系统”，只保留 Administrators 组。

设置用户在登录系统时应该有 “Hello,World!!!” 的提示信息：
在组策略编辑器中，依次展开 “计算机配置” - “Windows 设置” - “安全设置” - “本地策略” - “安全选项”，找到“交互式登录：试图登录的用户的消息标题”、“交互式登录：试图登录的用户的消息文本”，设置为“Hello,World!!!”  （win7测试有一个值为空都不会显示）

设置远程用户非活动会话连接超时为 5 分钟：
在组策略编辑器中，找到 “计算机配置” - “管理模板” - “Windows 组件” - “远程桌面服务” - “远程桌面会话主机” - “会话时间限制”，找到”设置活动但空闲的远程桌面服务会话的时间限制“设置相应的超时时间。

删除可远程访问的注册表路径：
在组策略编辑器中，找到 “计算机配置” - “Windows 设置” - “安全设置” - “本地策略” - “安全选项”，找到“网络访问：可远程访问的注册表路径”删除所有路径，下一条子路径最好也删除。

禁止将 Everyone 权限应用于匿名用户：
在组策略编辑器中，同上，找到 “网络访问：将Everyone权限应用于匿名用户”，设置为 “已禁用”。

不允许存储网络身份验证的密码和凭据：
在组策略编辑器中，同上，找到“网络访问：不允许存储网络身份验证的密码和凭据”，设置为“已启用”。


# 0x06 取证技术应用
登入虚拟机（0f3f0c_网络与信息安全管理员高级工级_Win7_x64），双击 “c:\tools\ 开启蜜罐.bat”，然后打开蜜罐设备管理页（https://miguan.test:4433/web/, 账号密码: admin/HFish2021）：
查看攻击日志或相关统计信息，找出攻击最频繁的攻击者 ip。
查看蜜罐服务的运行状态或日志，列取被攻击的蜜罐服务。
分析攻击数据，找出攻击者最常用的密码。
利用电子取证技术恢复虚拟磁盘（c:\files\test.vhd）唯一分区中被恶意删除的机密文件，并获取机密文件内容：可以使用专门的取证软件，如 Recuva、EaseUS Data Recovery Wizard 等，按照软件的操作步骤进行文件恢复操作。


# 0x07 Windows 数据销毁
以管理员账户登录当前 Windows 系统，在系统桌面上创建考试目录 “test”，并在该目录下创建文件 “1.txt” 和 “2.txt”。

使用 Sdelete 工具删除文件 “1.txt” 的命令：
```
//plaintext
sdelete 1.txt
```
使用 Sdelete 工具删除目录 “test” 并进行 5 次覆盖的命令：
```
//plaintext
sdelete -p 5 -r test
``
使用 Sdelete 工具清除 Y 盘的空闲空间并进行 2 次覆盖的命令（该操作不允许实际执行）：
``
//plaintext
sdelete -p 2 -z Y: 
```

# 0x08 Linux 系统中文件服务防护
创建 test 普通用户并设置密码，修改登录 shell：
```
//bash
useradd test
passwd test
usermod -s /bin/sh test
```
禁用 test 用户：
```
//bash
usermod -L test
```
创建系统账户 smbuser 并添加为 smb 用户：
```
//bash
useradd smbuser
smbpasswd -a smbuser
```
创建 /smbshare 目录：
```
//bash
mkdir /smbshare
```
修改 /etc/samba/smb.conf 配置文件：
创建 share1 共享：在配置文件末尾添加以下内容
```
[share1]
comment = SecurityShare
path = /smbshare
guest ok = no
valid users = smbuser
read only = yes
```
开启 smb 服务：
```
//bash
systemctl start smb
```
使用 smbclient 命令配合 -L 参数查看当前系统 smb 服务的共享情况：
```
//bash
smbclient -L localhost
```

# 0x09 Linux 系统密码策略和用户安全防护
查看当前系统中的用户：
```
//bash
cat /etc/passwd
```
新建 test 用户并添加到超级管理员组：
```
//bash
useradd test
usermod -aG wheel test
```
禁用 Administrator 与 guest 用户：
```
//bash
usermod -L Administrator
usermod -L guest
```
设置密码最小长度为 8 位，密码必须符包含大小写字符与数字的策略：在 /etc/pam.d/system-auth 或 /etc/pam.d/password-auth 文件中添加或修改以下内容
```
//plaintext
password requisite pam_cracklib.so minlen=8 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1
```
三次登录无效用户锁定，锁定时间为 10 分钟：在 /etc/pam.d/login 文件中添加或修改以下内容
```
//plaintext
auth required pam_tally2.so onerr=fail deny=3 unlock_time=600
```

# 0x10 系统日志分析
登入虚拟机（Win7_x64），提取 2021.09.12 05:15:00 - 2021.09.12 05:20:00 时间段的远程桌面登录日志，将过滤的日志存储为 evtx 格式日志：
可以使用 Windows 自带的事件查看器（eventvwr.msc），在其中设置相应的时间筛选条件，然后将筛选后的日志导出为 evtx 格式。记录详细提取过程，并描述该时间段内的用户认证成功日志记录条目数。
分析系统安全日志文件：
在事件查看器中查看安全日志，查找哪位用户在该机器上新建了用户 share，以及哪个 ip 通过新用户 share 成功地远程登录过本系统。


# 0x11 Windows 系统防护防火墙规则设置
1、使用防火墙封堵服务器的 445 端口进站：
在 Windows 防火墙高级设置中，创建入站规则，选择端口，指定 445 端口，设置为阻止连接。

2、使用防火墙封堵服务器的 Telnet 服务端口流量：
同样在防火墙高级设置中，创建入站规则，选择 Telnet 服务，设置为阻止连接。

3、禁止服务器主机响应 ping 请求：
在防火墙高级设置中，找到 “文件和打印机共享（回显请求 - ICMPv4-In）” 规则，设置为禁用。

4、在命令行中关闭服务器的防火墙：
在管理员命令提示符下输入 netsh advfirewall set allprofiles state off。

5、为防止信息泄露使用 SSL 安全层加密客户端和服务器之间的信息：
需要在相应的应用程序或服务中配置 SSL 加密，具体步骤因应用而异。例如在 IIS 中，可以通过安装证书并配置 SSL 绑定来实现。创建名为 My-Certificate 的证书：可以使用 Windows 自带的证书管理工具或第三方证书颁发机构工具来创建证书，具体步骤根据工具不同而有所差异。


# 0x12 数据泄露应急处置
登入虚拟机（Win7_x64），尝试分析数据包文件（c:\files\ftp_data.pcapng）：使用 Wireshark 打开数据包文件，查看其中的流量信息，找出攻击者窃取的压缩包文件名。
尝试使用相关取证手段恢复数据流中被窃取的压缩包及内容：可以结合 Wireshark 和 C:\tools\winhex.exe 等工具，根据数据包中的信息和文件特征进行恢复操作，但具体恢复方法需要根据实际情况进行分析和尝试。
