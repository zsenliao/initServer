# initServer
一个服务器初始化脚本工具。脚本借鉴了 [lnmp](https://github.com/licess/lnmp) 的许多写法，Nginx 的编译安装及配置参考了 [本博客开始支持 TLS 1.3](https://imququ.com/post/enable-tls-1-3.html) 的方式。在此感谢两位大大。

## 使用方式

`curl https://raw.githubusercontent.com/zsenliao/initServer/master/initServer.sh -O`

> 也可以通过在命令末尾添加 ` | tee install-info.log` 的方式来记录安装日志

## 主要功能

* 添加用户及 SSH 配置。可选择添加用户，以及是否自定义配置 `SSH`。如选择是，按照提示「傻瓜」式操作就好。
* git/zsh/oh-my-zsh 等安装、vim 升级
* MySQL/PHP/Python3(uwsgi)/Redis/Nodejs/Nginx/ikev2/acme.sh 等服务可选择安装

### 关于 添加用户及 SSH 配置

> * 按照提示操作，如果成功，后续登录服务器只能通过密钥文件的方式；操作失败可选是否删除新添加的用户；
> * SSH 配置会禁用 ROOT 远程登录、禁用用户密码登录；
> * 如需要 ROOT 权限，可以通过添加的用户名登录后，再 `su` 切换到 ROOT 用户；
> * 如果使用的是阿里云、腾讯云等云服务器，并且自定义了 SSH 端口，需要在云管理平台添加对应的端口；

### 关于 VIM

> * 安装了 [vim-for-server](https://github.com/wklken/vim-for-server) 插件；
> * 代码高亮增加了 `nginx`, `ini`, `php`, `python` 等文件类型

### 关于 MySQL

> * 禁止了远程连接；
> * 可以自行安装 `phpMyAdmin` 之类的工具；如使用桌面客户端，请使用 `SSH 隧道` 的方式；

## 工具说明

* 脚本主要自用，因此没考虑多系统环境
* 只支持 CentOS
* 不提供 MySQL/PHP/Nginx 等服务的多版本选择
* 提供了一个简单的管理工具 `pnmp`（可自定义名字，但注意不要与系统或其他第三方工具同名）

### 关于管理工具

> * Usage: pnmp {start|stop|reload|restart|kill|status|test}
> * Usage: pnmp {nginx|mysql|php-fpm|redis|uwsgi} {start|stop|reload|restart|kill|status}
> * Usage: pnmp vhost {add|list|del}
> * Usage: pnmp cert {check|update|auto}

### 通过管理工具添加站点说明

> * 新增站点时，会通过 acme.sh 申请并安装域名证书；
> * _~~证书有效期 `3个月`，请记得通过 acme.sh 及时续期（看一些文档是说有自动续期功能，但我的没实现😂）；~~_ 安装脚本的 BUG，已修复
> * 泛域名证书的申请，只能通过 `DNS` 的方式，请自行通过 acme.sh 申请；
> * 站点强制使用 `HTTPS`

## TODO
* [x] 站点目录自定义更改
* [x] 管理工具自定义命名
* [x] 选择安装是否 [shellMonitor](https://github.com/zsenliao/shellMonitor)
* [x] 增加域名证书到期时间检测
* [x] 域名证书续期
* [x] 增加自定义命名管理工具时的名称检测
* [x] 增加管理工具的升级功能
* [x] 修复新增域名时申请正式后自动更新失败的 BUG
* [ ] 跨域设置中，增加多域名的处理
* [x] 增加邮件发送处理
* [x] 增加 Tomcat 安装
* [x] 安装失败日志记录
* [x] 自动获取IP失败，提示手动输入
* [ ] 自定义升级服务版本
* [x] 增加 htop 安装
* [ ] 增加 https 泛域名证书申请