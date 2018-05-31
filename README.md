# initServer
一个服务器初始化脚本工具。脚本借鉴了 [lnmp](https://github.com/licess/lnmp) 的许多写法，Nginx 的编译安装及配置参考了 [本博客开始支持 TLS 1.3](https://imququ.com/post/enable-tls-1-3.html) 的方式。在此感谢两位大大。

## 主要功能

* 添加用户及 SSH 配置。可选择添加用户，以及是否自定义配置 `SSH`。如选择是，按照提示「傻瓜」式操作就好。
* git/zsh 等安装、vim 升级
* MySQL/PHP/Python3/Redis/Nodejs/Tomcat/Nginx/ikev2 等服务可选择安装

## 工具说明

* 脚本主要自用，因此没考虑多系统环境
* 只支持 CentOS
* 不提供 MySQL/PHP/Nginx 等服务的多版本选择
* 提供了一个简单的管理工具 `pnmp`

## TODO
* [ ] 站点目录自定义更改
* [ ] 管理工具自定义命名
* [ ] 选择安装是否 [shellMonitor](https://github.com/zsenliao/shellMonitor)
