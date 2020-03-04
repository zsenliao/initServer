#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

INSSTACK=$1
STARTTIME=$(date +%s)
CUR_DIR=$(cd $(dirname $BASH_SOURCE); pwd)
MemTotal=$(free -m | grep Mem | awk '{print  $2}')
CPUS=$(grep processor /proc/cpuinfo | wc -l)

if [[ ${INSSTACK} == "upgrade" ]]; then
    INSTITLE="升级"
else
    INSTITLE="安装"
fi

CMAKE_VER=3.16.2
PYTHON3_VER=3.7.6
NODEJS_VER=v12.14.0
STARTSTOPDAEMON_VER=1.17.27
NGINX_VER=1.17.7
PHP_VER=7.4.1
MCRYPT_VER=1.0.3
REDIS_VER=5.0.7
MYSQL_VER=5.7.21
TOMCAT_VER=9.0.30
HTOP_VER=2.2.0
LIBZIP_VER=1.5.2
OPENSSL_VER=1.1.1d

get_server_ip() {
    local CURLTXT
    CURLTXT=$(curl httpbin.org/ip 2>/dev/null | grep origin | awk '{print $3}')
    if [[ ${CURLTXT} == "" ]]; then
        for url in "ifconfig.io" "ifconfig.me" "ip.cip.cc" "api.ip.la"; do
            HOSTIP=$(curl $url 2>/dev/null)
            if [[ ${HOSTIP} != "" && ${#HOSTIP} -le 15 ]]; then
                break
            fi
        done
        if [[ ${HOSTIP} == "" || ${#HOSTIP} -gt 15 ]]; then
            HOSTIP="服务器IP获取失败"
        fi
    else
        HOSTIP=${CURLTXT:0:-1}
    fi
}

check_hosts() {
    if grep -Eqi '^127.0.0.1[[:space:]]*localhost' /etc/hosts; then
        echo_green "Hosts: ok!"
    else
        echo "127.0.0.1 localhost.localdomain localhost" >> /etc/hosts
    fi
}

disable_selinux() {
    if [ -s /etc/selinux/config ]; then
        sed -i "s/^SELINUX=.*/SELINUX=disabled/g" /etc/selinux/config
    fi
}

echo_red() {
    echo -e "\e[0;31m$1\e[0m"
}

echo_green() {
    echo -e "\e[0;32m$1\e[0m"
}

echo_yellow() {
    echo -e "\e[0;33m$1\e[0m"
}

echo_blue() {
    echo -e "\e[0;34m$1\e[0m"
}

echo_info() {
    printf "%-s: \e[0;33m%-s\e[0m\n" "$1" "$2"
}

ins_begin() {
    echo -e "\e[0;34m[+] 开始${INSTITLE} ${1-$MODULE_NAME}...\e[0m"
}

get_module_ver() {
    MODULE_CLI=$(echo ${1-$MODULE_NAME} | tr '[:upper:]' '[:lower:]')

    if [[ $MODULE_CLI == "nginx" ]]; then
        command -v nginx 1>/dev/null && MODULE_VER=$(cat /usr/local/nginx/version.txt 2>/dev/null || echo "8.8.8.8") || MODULE_VER=""
    elif [[ $MODULE_CLI == "vim" ]]; then
        MODULE_VER=$(echo $(vim --version 2>/dev/null) | awk -F ')' '{print $1}')
    elif [[ $MODULE_CLI == "redis" ]]; then
        MODULE_VER=$(redis-server --version 2>/dev/null)
    elif [[ $MODULE_CLI == "nodejs" ]]; then
        MODULE_VER=$(node --version 2>/dev/null)
    else
        MODULE_VER=$(${MODULE_CLI} --version 2>/dev/null)
    fi
}

ins_end() {
    get_module_ver $1
    if [ -n "${MODULE_VER}" ]; then
        echo_green "[√] ${1-$MODULE_NAME} ${INSTITLE}成功! 当前版本：${MODULE_VER}"
    else
        echo_red "[x] ${1-$MODULE_NAME} ${INSTITLE}失败! "
    fi
}

show_ver() {
    get_module_ver
    if [ -n "${MODULE_VER}" ]; then
        echo_green "当前已安装 ${MODULE_NAME}, 版本：${MODULE_VER}"
        echo_yellow "是否重新编译安装?"
    else
        echo_yellow "是否安装 ${MODULE_NAME}?"
    fi
}

wget_cache() {
    if [ ! -f "$2" ]; then
        if ! wget -c "$1" -O "$2"; then
            rm -f "$2"
            echo "${3-$MODULE_NAME} 下载失败!" >> /root/install-error.log
            echo_red "${3-$MODULE_NAME} 下载失败! 请输入新的地址后回车重新下载:"
            echo_blue "当前下载地址: $1"
            read -r -p "请输入新的下载地址: " downloadUrl
            wget "${downloadUrl}" -O "$2"
        fi
    fi
}

set_time_zone() {
    echo_blue "设置时区..."
    rm -rf /etc/localtime
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
}

set_host_name() {
    echo_blue "[+] 修改 Hostname..."
    if [[ ${INSSTACK} != "auto" ]]; then
        read -r -p "请输入 Hostname: " HOST_NAME
    fi
    if [ -z "${HOST_NAME}" ]; then
        HOST_NAME="myServer"
    fi
    echo "hostname=\"${HOST_NAME}\"" >> /etc/sysconfig/network
    echo "" > /etc/hostname
    echo "${HOST_NAME}" > /etc/hostname
    /etc/init.d/network restart
    echo_green "[√] 修改 Hostname 成功!"
}

add_user() {
    echo_blue "[+] 添加用户..."
    while :;do
        read -r -p "请输入用户名: " USERNAME
        if [[ "${USERNAME}" != "" ]]; then
            break
        else
            echo_red "用户名不能为空！"
        fi
    done
    while :;do
        read -r -p "请输入用户密码: " PASSWORD
        if [[ "${PASSWORD}" != "" ]]; then
            break
        else
            echo_red "密码不能为空！"
        fi
    done
    read -r -p "请输入 ssh 证书名(留空则与用户名相同): " FILENAME

    # if [[ -n "${USERNAME}" && -n "${PASSWORD}" ]]; then
    useradd "${USERNAME}"
    echo "${PASSWORD}" | passwd "${USERNAME}" --stdin  &>/dev/null

    mkdir -p "/home/${USERNAME}/.ssh"
    chown -R "${USERNAME}":"${USERNAME}" "/home/${USERNAME}"
    chmod -R 755 "/home/${USERNAME}"
    cd "/home/${USERNAME}/.ssh"
    if [ -z "${FILENAME}" ]; then
        FILENAME=${USERNAME}
    fi

    echo_yellow "请输入证书密码(如不要密码请直接回车)"
    su "${USERNAME}" -c "ssh-keygen -t rsa -f ${FILENAME}"

    cd "${CUR_DIR}/src"

    chown -R "${USERNAME}":"${USERNAME}" "/home/${USERNAME}"
    chmod -R 755 "/home/${USERNAME}"
    chmod 700 "/home/${USERNAME}/.ssh"
    chmod 600 "/home/${USERNAME}/.ssh/${FILENAME}"
    restorecon -Rv "/home/${USERNAME}/.ssh"
    echo_green "[√] 添加用户成功!"
    # fi
}

ssh_setting() {
    echo_blue "[+] 修改 SSH 配置..."
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    if [ -n "${USERNAME}" ]; then
        echo_blue "请打开一个新的命令窗口后，通过以下指令下载证书文件："
        echo "scp ${USERNAME}@${HOSTIP}:/home/${USERNAME}/.ssh/${FILENAME} ./"
        echo_yellow "是否下载成功?"
        read -r -p "是(Y)/否(N): " DOWNFILE
        if [[ ${DOWNFILE} == "y" || ${DOWNFILE} == "Y" ]]; then
            # 是否允许使用基于密码的认证
            sed -i "s/^PasswordAuthentication [a-z]*/#&/g; 1,/^#PasswordAuthentication [a-z]*/{s/^#PasswordAuthentication [a-z]*/PasswordAuthentication no/g}" /etc/ssh/sshd_config
            sed -i "s|AuthorizedKeysFile.*|AuthorizedKeysFile .ssh/${FILENAME}.pub|g" /etc/ssh/sshd_config
        fi
        #echo "" >> /etc/ssh/sshd_config
        #echo "AllowUsers ${USERNAME}" >> /etc/ssh/sshd_config
    fi

    echo_yellow "是否修改 SSH 默认端口(强烈建议修改，如不修改请直接回车)?"
    read -r -p "请输入 ssh 端口(数字): " SSHPORT
    if [[ -n ${SSHPORT} && ${SSHPORT} != "22" ]]; then
        sed -i "s/^Port [0-9]*/#&/g; 1,/^#Port [0-9]*/{s/^#Port [0-9]*/Port ${SSHPORT}/g}" /etc/ssh/sshd_config
    fi

    echo_yellow "是否限制指定 IP 连接?"
    echo_red "注意：如限定，除该IP外的其他连接请求都将被拒绝!"
    read -r -p "请输入 IP 地址(不限定请直接回车): " LOGINIP
    if [ -n "${LOGINIP}" ]; then
        sed -i "s/^ListenAddress [0-9.]*/#&/g; 1,/^#ListenAddress [0-9.]*/{s/^#ListenAddress [0-9.]*/ListenAddress ${LOGINIP}/g}" /etc/ssh/sshd_config
    fi

    echo_yellow "是否允许 root 用户登录?"
    read -r -p "是(Y)/否(N): " ALLOWROOT
    if [[ ${ALLOWROOT} != "y" && ${ALLOWROOT} != "Y" ]]; then
        # 禁止 ROOT 用户登录
        sed -i "s/^PermitRootLogin [a-z]*/#&/g; 1,/^#PermitRootLogin [a-z]*/{s/^#PermitRootLogin [a-z]*/PermitRootLogin no/g}" /etc/ssh/sshd_config
    fi

    echo_yellow "限制错误登录次数?"
    read -r -p "请输入(默认3次): " MaxAuthTries
    if [[ ${MaxAuthTries} == "" ]]; then
        MaxAuthTries=3
    fi
    sed -i "s/^MaxAuthTries [0-9]*/#&/g; 1,/^#MaxAuthTries [0-9]*/{s/^#MaxAuthTries [0-9]*/MaxAuthTries ${MaxAuthTries}/g}" /etc/ssh/sshd_config

    sed -i "s/^Protocol [0-9]*/#&/g; 1,/^#Protocol [0-9]*/{s/^#Protocol [0-9]*/Protocol 2/g}" /etc/ssh/sshd_config
    # 是否允许公钥认证
    sed -i "s/^PubkeyAuthentication [a-z]*/#&/g; 1,/^#PubkeyAuthentication [a-z]*/{s/^#PubkeyAuthentication [a-z]*/PubkeyAuthentication yes/g}" /etc/ssh/sshd_config
    # 是否允许密码为空的用户远程登录。默认为no
    sed -i "s/^PermitEmptyPasswords [a-z]*/#&/g; 1,/^#PermitEmptyPasswords [a-z]*/{s/^#PermitEmptyPasswords [a-z]*/PermitEmptyPasswords no/g}" /etc/ssh/sshd_config
    # 是否使用PAM模块认证
    sed -i "s/^UsePAM [a-z]*/#&/g; 1,/^#UsePAM [a-z]*/{s/^#UsePAM [a-z]*/UsePAM no/g}" /etc/ssh/sshd_config
    # 检查用户主目录和相关配置文件的权限。如果权限设置错误，会出现登录失败情况
    sed -i "s/^StrictModes [a-z]*/#&/g; 1,/^#StrictModes [a-z]*/{s/^#StrictModes [a-z]*/StrictModes yes/g}" /etc/ssh/sshd_config
    # 是否取消使用 ~/.ssh/.rhosts 来做为认证。推荐设为yes
    sed -i "s/^IgnoreRhosts [a-z]*/#&/g; 1,/^#IgnoreRhosts [a-z]*/{s/^#IgnoreRhosts [a-z]*/IgnoreRhosts yes/g}" /etc/ssh/sshd_config
    # 指定系统是否向客户端发送 TCP keepalive 消息
    sed -i "s/^TCPKeepAlive [a-z]*/#&/g; 1,/^#TCPKeepAlive [a-z]*/{s/^#TCPKeepAlive [a-z]*/TCPKeepAlive yes/g}" /etc/ssh/sshd_config
    # 服务器端向客户端发送消息时常，秒
    sed -i "s/^ClientAliveInterval [0-9]*/#&/g; 1,/^#ClientAliveInterval [0-9]*/{s/^#ClientAliveInterval [0-9]*/ClientAliveInterval 300/g}" /etc/ssh/sshd_config
    # 客户端未响应次数，超过则服务器端主动断开
    sed -i "s/^ClientAliveCountMax [0-9]/#&/g; 1,/^#ClientAliveCountMax [0-9]/{s/^#ClientAliveCountMax [0-9]/ClientAliveCountMax 3/g}" /etc/ssh/sshd_config
    # 指定是否显示最后一位用户的登录时间
    sed -i "s/^PrintLastLog [a-z]*/#&/g; 1,/^#PrintLastLog [a-z]*/{s/^#PrintLastLog [a-z]*/PrintLastLog yes/g}" /etc/ssh/sshd_config
    # 登入后是否显示出一些信息，例如上次登入的时间、地点等等
    sed -i "s/^PrintMotd [a-z]*/#&/g; 1,/#PrintMotd[a-z]*/{s/^#PrintMotd [a-z]*/PrintMotd no/g}" /etc/ssh/sshd_config
    # 使用 rhosts 档案在 /etc/hosts.equiv配合 RSA 演算方式来进行认证, 推荐no。RhostsRSAAuthentication 是version 1
    sed -i "s/^HostbasedAuthentication [a-z]*/#&/g; 1,/#HostbasedAuthentication[a-z]*/{s/^#HostbasedAuthentication [a-z]*/HostbasedAuthentication no/g}" /etc/ssh/sshd_config
    # 是否在 RhostsRSAAuthentication 或 HostbasedAuthentication 过程中忽略用户的 ~/.ssh/known_hosts 文件
    sed -i "s/^IgnoreUserKnownHosts [a-z]*/#&/g; 1,/#IgnoreUserKnownHosts[a-z]*/{s/^#IgnoreUserKnownHosts [a-z]*/IgnoreUserKnownHosts yes/g}" /etc/ssh/sshd_config
    # 限制登录验证在30秒内
    sed -i "s/^LoginGraceTime [a-z0-9]*/#&/g; 1,/^#LoginGraceTime [a-z0-9]*/{s/^#LoginGraceTime [a-z0-9]*/LoginGraceTime 30/g}" /etc/ssh/sshd_config

    # 开启sftp日志
    sed -i "s/sftp-server/sftp-server -l INFO -f AUTH/g" /etc/ssh/sshd_config
    # 限制 SFTP 用户在自己的主目录
    # ChrootDirectory /home/%u
    echo "" >> /etc/rsyslog.conf
    echo "auth,authpriv.*                                         /var/log/sftp.log" >> /etc/rsyslog.conf

    if [[ ${SSHPORT} != "22" ]]; then
        # 如果 SELinux 启用下，需要额外针对 SELinux 添加 SSH 新端口权限
        if sestatus -v | grep enabled; then
            echo_blue "SELinux 启用，添加 SELinux 下的 SSH 新端口权限..."
            yum install -y policycoreutils-python
            semanage port -a -t ssh_port_t -p tcp "${SSHPORT}"
        fi

        echo_blue "正在关闭 SSH 默认端口(22)..."
        firewall-cmd --permanent --remove-service=ssh
        echo_blue "正在添加 SSH 连接新端口(${SSHPORT})..."
        firewall-cmd --zone=public --add-port="${SSHPORT}"/tcp --permanent
        echo_blue "正在重启防火墙"
        firewall-cmd --reload
    fi

    echo_blue "已完成 SSH 配置，正在重启 SSH 服务..."
    service sshd restart
    service rsyslog restart

    if [[ ${DOWNFILE} == "y" || ${DOWNFILE} == "Y" ]]; then
        EMPTY_SER_NAME="MyServer"
        echo_green "已设置证书登录(如设置了证书密码，还需要输入密码)，登录方式："
        echo "ssh -i ./${FILENAME} -p ${SSHPORT} ${USERNAME}@${HOSTIP}"
        echo_blue "请根据实际情况修改上面命令中 ./${FILENAME} 证书路径，并将证书文件设置 600 权限：chmod 600 ${FILENAME}"
        echo_red "请注意：如果客户机 ~/.ssh 目录下有多个证书，以上命令会连接失败！"
        echo_red "需要在 ~/.ssh/config 文件中添加 Host 将服务器与证书对应(Windows 系统未验证)"
        echo_green "参考以下方式添加 ~/.ssh/config 内容："
        echo "Host ${HOST_NAME-$EMPTY_SER_NAME}"
        echo "    HostName ${HOSTIP}"
        echo "    User ${USERNAME}"
        echo "    Port ${SSHPORT}"
        echo "    PreferredAuthentications publickey"
        echo "    IdentityFile ./${FILENAME}"
        echo "    IdentitiesOnly yes"
        echo_green "同样请根据实际情况修改上面命令中 ./${FILENAME} 证书路径，然后通过以下命令连接："
        echo "ssh ${HOST_NAME-$EMPTY_SER_NAME}"
    else
        echo_green "已设置用户密码登录(登录时需输入用户密码 ${PASSWORD})。登录方式："
        echo "ssh -p ${SSHPORT} $(whoami)@${HOSTIP}"
    fi

    echo_blue "[!] 请按照以上方式，打开一个新的 ssh 会话到服务器，看是否能连接成功"
    echo_yellow "是否连接成功?"
    read -r -p "成功(Y)/失败(N): " SSHSUSS
    if [[ ${SSHSUSS} == "n" || ${SSHSUSS} == "N" ]]; then
        if [ -n "${USERNAME}" ]; then
            echo_yellow "是否删除新添加的用户: ${USERNAME}?"
            read -r -p "是(Y)/否(N): " DELUSER
            if [[ ${DELUSER} == "y" || ${DELUSER} == "Y" ]]; then
                userdel "${USERNAME}"
                rm -rf "/home/${USERNAME}"
                echo_red "删除用户成功!"
            fi
        fi

        cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        echo_blue "正在删除新增 SSH 端口..."
        firewall-cmd --remove-port="${SSHPORT}"/tcp --permanent
        echo_blue "正在恢复默认 SSH 端口..."
        firewall-cmd --permanent --add-service=ssh
        echo_blue "正在重启防火墙..."
        firewall-cmd --reload
        echo_blue "正在重启 SSH 服务..."
        service sshd restart
        echo_red "[!] 已复原 SSH 配置!"
    else
        echo_green "[√] SSH 配置修改成功!"
    fi
}

install_git() {
    yum install -y autoconf zlib-devel curl-devel openssl-devel perl cpio expat-devel gettext-devel openssl zlib gcc perl-ExtUtils-MakeMaker

    wget_cache "https://github.com/git/git/archive/master.tar.gz" "git-master.tar.gz"
    tar xzf git-master.tar.gz || return 255

    cd git-master
    make configure && ./configure --prefix=/usr/local
    make -j ${CPUS} && make install || make_result="fail"
    cd ..
    if [[ $make_result == "fail" ]]; then
        return 1
    fi
}

install_zsh() {
    yum install -y zsh
    chsh -s /bin/zsh

    if [[ ${INSSTACK} != "auto" ]]; then
        echo_yellow "是否安装 oh my zsh?"
        read -r -p "是(Y)/否(N): " INSOHMYZSH
    fi
    if [[ ${INSOHMYZSH} == "y" || ${INSOHMYZSH} == "Y" ]]; then
        echo_blue "[+] 安装 oh my zsh..."
        wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | sh
        sed -i "s/ZSH_THEME=\"robbyrussell\"/ZSH_THEME=\"ys\"/g" ~/.zshrc
    fi

    cat > ~/.zshrc<<EOF
export HISTSIZE=10000
export SAVEHIST=10000
export HISTFILE=~/.zsh_history
export PATH=/usr/local/bin:\$PATH
export EDITOR=/usr/bin/local/vim

export CLICOLOR=1
alias ll="ls -alF"
alias la="ls -A"
alias l="ls -CF"
alias lbys="ls -alhS"
alias lbyt="ls -alht"
alias cls="clear"
alias grep="grep --color"
alias vi="vim"
alias cp="cp -i"
alias mv="mv -i"
alias rm="rm -i"

autoload -U colors && colors
local exit_code="%(?,,C:%{\$fg[red]%}%?%{\$reset_color%})"
PROMPT="\$fg[blue]#\${reset_color} \$fg[cyan]%n\$reset_color@\$fg[green]%m\$reset_color:\$fg[yellow]%1|%~\$reset_color [zsh-%*] \$exit_code
%{\$terminfo[bold]\$fg[red]%}$ %{\$reset_color%}"

setopt INC_APPEND_HISTORY # 以附加的方式写入历史纪录
setopt HIST_IGNORE_DUPS   # 如果连续输入的命令相同，历史纪录中只保留一个
setopt EXTENDED_HISTORY   # 为历史纪录中的命令添加时间戳
#setopt HIST_IGNORE_SPACE  # 在命令前添加空格，不将此命令添加到纪录文件中

autoload -U compinit
compinit

# 自动补全功能
setopt AUTO_LIST
setopt AUTO_MENU
#setopt MENU_COMPLETE      # 开启此选项，补全时会直接选中菜单项
setopt AUTO_PUSHD         # 启用 cd 命令的历史纪录，cd -[TAB]进入历史路径
setopt PUSHD_IGNORE_DUPS  # 相同的历史路径只保留一个

setopt completealiases
#自动补全选项
zstyle ":completion:*" menu select
zstyle ":completion:*:*:default" force-list always
zstyle ":completion:*:match:*" original only
zstyle ":completion::prefix-1:*" completer _complete
zstyle ":completion:predict:*" completer _complete
zstyle ":completion:incremental:*" completer _complete _correct
zstyle ":completion:*" completer _complete _prefix _correct _prefix _match _approximate

#路径补全
zstyle ":completion:*" expand "yes"
zstyle ":completion:*" squeeze-shlashes "yes"
zstyle ":completion::complete:*" "\\\\"

#错误校正
zstyle ":completion:*" completer _complete _match _approximate
zstyle ":completion:*:approximate:*" max-errors 1 numeric

#kill 命令补全
compdef pkill=kill
compdef pkill=killall
zstyle ":completion:*:*:kill:*" menu yes select
zstyle ":completion:*:*:*:*:processes" force-list always
zstyle ":completion:*:processes" command "ps -au\$USER"

bindkey "^[[A" history-beginning-search-backward
bindkey "^[[B" history-beginning-search-forward
EOF

    if [[ "${USERNAME}" != "" ]]; then
        cp ~/.zshrc /home/${USERNAME}/
        chown ${USERNAME}:${USERNAME} /home/${USERNAME}/
    fi
}

install_vim() {
    wget_cache "https://github.com/vim/vim/archive/master.tar.gz" "vim-master.tar.gz"
    tar zxvf vim-master.tar.gz || return 255

    yum uninstall -y vim
    yum remove -y vim
    yum install -y ncurses-devel

    cd vim-master/src
    make -j && make install || make_result="fail"
    cd ../..
    if [[ $make_result == "fail" ]]; then
        return 1
    fi

    echo_blue "[+] 安装 vim 插件..."
    curl https://raw.githubusercontent.com/wklken/vim-for-server/master/vimrc > ~/.vimrc

    mkdir -p ~/.vim/syntax

    wget -O ~/.vim/syntax/nginx.vim http://www.vim.org/scripts/download_script.php?src_id=19394
    echo "au BufRead,BufNewFile ${INSHOME}/wwwconf/nginx/*,/usr/local/nginx/conf/* if &ft == '' | setfiletype nginx | endif " >> ~/.vim/filetype.vim

    wget -O ini.vim.zip https://www.vim.org/scripts/download_script.php?src_id=10629
    unzip ini.vim.zip && mv vim-ini-*/ini.vim ~/.vim/syntax/ini.vim
    rm -rf vim-ini-* ini.vim.zip
    echo "au BufNewFile,BufRead *.ini,*/.hgrc,*/.hg/hgrc setf ini" >> ~/.vim/filetype.vim

    wget -O php.vim.tar.gz https://www.vim.org/scripts/download_script.php?src_id=8651
    tar zxvf php.vim.tar.gz && mv syntax/php.vim ~/.vim/syntax/php.vim
    rm -rf syntax php.vim.tar.gz
    echo "au BufNewFile,BufRead *.php setf php" >> ~/.vim/filetype.vim

    wget -O ~/.vim/syntax/python.wim https://www.vim.org/scripts/download_script.php?src_id=21056
    echo "au BufNewFile,BufRead *.py setf python" >> ~/.vim/filetype.vim

    if [[ "${USERNAME}" != "" ]]; then
        cp ~/.vimrc /home/${USERNAME}/
        cp -r ~/.vim /home/${USERNAME}/
        chown ${USERNAME}:${USERNAME} /home/${USERNAME}/
    fi
}

install_htop() {
    yum install -y ncurses-devel
    wget_cache "https://hisham.hm/htop/releases/${HTOP_VER}/htop-${HTOP_VER}.tar.gz" "htop-${HTOP_VER}.tar.gz"
    tar zxvf htop-${HTOP_VER}.tar.gz || return 255
    cd htop-${HTOP_VER}
    ./configure
    make && make install
    cd ..
}

install_ikev2() {
    echo_blue "[+] 安装 one-key-ikev2..."
    install_acme

    mkdir ikev2
    cd ikev2
    wget -c https://raw.githubusercontent.com/quericy/one-key-ikev2-vpn/master/one-key-ikev2.sh
    chmod +x one-key-ikev2.sh
    bash one-key-ikev2.sh
    cd ..
}  # TODO

install_cmake() {
    wget_cache "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VER}/cmake-${CMAKE_VER}.tar.gz" "cmake-${CMAKE_VER}.tar.gz"
    tar zxvf cmake-${CMAKE_VER}.tar.gz || return 255

    rpm -q cmake
    yum remove -y cmake
    yum install -y gcc gcc-c++

    cd cmake-${CMAKE_VER}
    ./bootstrap
    make -j ${CPUS} && make install || make_result="fail"
    cd ..
    if [[ $make_result == "fail" ]]; then
        return 1
    fi
}

install_acme() {
    if [ -f "/root/.acme.sh/acme.sh.env" ]; then
        echo_green "acme.sh 已安装，当前版本：$(/root/.acme.sh/acme.sh --version)"
        echo_blue "更新版本..."
        acme.sh --upgrade
    else
        ins_begin "acme.sh"
        yum install -y socat

        curl https://get.acme.sh | sh

        /root/.acme.sh/acme.sh --upgrade --auto-upgrade

        ins_end "/root/.acme.sh/acme.sh"
    fi
}

install_uwsgi() {
    pip3 install uwsgi
    ln -sf /usr/local/python3.7/bin/uwsgi /usr/local/bin/uwsgi

    TMPCONFDIR=${INSHOME}/wwwconf/uwsgi
    mkdir -p ${TMPCONFDIR}
    chown -R nobody:nobody "${INSHOME}/wwwconf"

    cat > /etc/init.d/uwsgi<<EOF
#!/bin/bash
# chkconfig: 2345 55 25
# Description: Startup script for uwsgi webserver on Debian. Place in /etc/init.d and
# run 'update-rc.d -f uwsgi defaults', or use the appropriate command on your
# distro. For CentOS/Redhat run: 'chkconfig --add uwsgi'

### BEGIN INIT INFO
# Provides:          uwsgi
# Required-Start:    \$all
# Required-Stop:     \$all
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: starts the uwsgi web server
# Description:       starts uwsgi using start-stop-daemon
### END INIT INFO

# Modify by lykyl
# Ver:1.1
# Description: script can loads multiple configs now.

DESC="Python uWSGI"
NAME=uwsgi
DAEMON=/usr/local/python3.7/bin/uwsgi
CONFIGDIR=${TMPCONFDIR}
PIDDIR=/tmp

log_success_msg(){
    printf "%-58s \\033[32m[ %s ]\\033[0m\\n" "\$@"
}
log_failure_msg(){
    printf "%-58s \\033[31m[ %s ]\\033[0m\\n" "\$@"
}
log_warning_msg(){
    printf "%-58s \\033[33m[ %s ]\\033[0m\\n" "\$@"
}

iniList=\$(ls \${CONFIGDIR}/*.ini 2>/dev/null)

start() {
    if [ \${#iniList} -eq 0 ]; then
        log_warning_msg "Starting \$DESC: " "No Application"
    else
        echo "Starting \$DESC: "
        # for i in \${CONFIGDIR}/*.ini
        for i in \${iniList[@]}
        do
            SiteName=\${i:${#TMPCONFDIR}+1:0-4}
            pid=\$(ps aux | grep \$i | grep -v grep | awk '{ print \$13 }' | sort -mu 2>/dev/null)
            if [ ! -z "\$pid" ]; then
                log_warning_msg "        \${SiteName}: " "Already Running"
            else
                \$DAEMON --ini \${i} 2>/dev/null
                if [ \$? -eq 0 ]; then
                    log_success_msg "        \${SiteName}: " "SUCCESS"
                else
                    log_failure_msg "        \${SiteName}: " "Failed"
                fi
            fi
        done
    fi
}

stop() {
    if [ \${#iniList} -eq 0 ]; then
        log_warning_msg "Stopping \$DESC: " "No Application"
    else
        echo "Stopping \$DESC: "
        for i in \${iniList[@]}
        do
            SiteName=\${i:${#TMPCONFDIR}+1:0-4}
            pid=\$(ps aux | grep \$i | grep -v grep | awk '{ print \$13 }' | sort -mu 2>/dev/null)
            if [ ! -z "\$pid" ]; then
                \$DAEMON --stop \${PIDDIR}/\${SiteName}.uwsgi.pid 2>/dev/null
                if [ \$? -eq 0 ]; then
                    log_success_msg "        \${SiteName}: " "SUCCESS"
                else
                    log_failure_msg "        \${SiteName}: " "Failed"
                fi
            else
                log_warning_msg "        \${SiteName}: " "Not Running"
            fi
        done
    fi
}

reload() {
    if [ \${#iniList} -eq 0 ]; then
        log_warning_msg "Stopping \$DESC: " "No Application"
    else
        echo "Reloading \$DESC: "
        for i in \${iniList[@]}
        do
            SiteName=\${i:${#TMPCONFDIR}+1:0-4}
            pid=\$(ps aux | grep \$i | grep -v grep | awk '{ print \$13 }' | sort -mu 2>/dev/null)
            if [ ! -z "\$pid" ]; then
                \$DAEMON --reload \${PIDDIR}/\${SiteName}.uwsgi.pid 2>/dev/null
                if [ \$? -eq 0 ]; then
                    log_success_msg "        \${SiteName}: " "SUCCESS"
                else
                    log_failure_msg "        \${SiteName}: " "Failed"
                fi
            else
                log_warning_msg "        \${SiteName}: " "Not Running"
            fi
        done
    fi
}

status() {
    pid=\$(ps aux | grep \$DAEMON | grep -v grep | awk '{ print \$13 }' | sort -mu 2>/dev/null)
    if [ ! -z "\$pid" ]; then
        echo "\${DESC} application status: "
        for i in \${pid[@]}
        do
            log_success_msg "        \${i:${#TMPCONFDIR}+1:0-4}: " "Running"
        done
    else
        log_warning_msg "\${DESC} application status: " "All Application Stopped"
    fi
}

kill() {
    # killall -9 uwsgi
    echo "shutting down uWSGI service ......"
    pids=\$(ps aux | grep uwsgi | grep -v grep | awk '{ print \$2 }')
    for pid in \$pids[@]
    do
        # echo \$pid | xargs kill -9
        \`kill -9 \$pid\`
    done
}

[ -x "\$DAEMON" ] || exit 0

case "\$1" in
    status)
        status
        ;;
    start)
        start
        ;;
    stop)
        stop
        ;;
    reload)
        reload
        ;;
    restart)
        stop
        sleep 3
        start
        ;;
    kill)
        kill
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|reload|kill|status}"
        ;;
esac

exit 0
EOF
    chmod +x /etc/init.d/uwsgi
    chkconfig --add uwsgi
    chkconfig uwsgi on
    service uwsgi start
}

install_python3() {
    yum install -y epel-release zlib-devel readline-devel bzip2-devel ncurses-devel sqlite-devel gdbm-devel libffi-devel

    wget_cache "https://www.python.org/ftp/python/${PYTHON3_VER}/Python-${PYTHON3_VER}.tgz" "Python-${PYTHON3_VER}.tgz"
    tar xf Python-${PYTHON3_VER}.tgz || return 255

    cd Python-${PYTHON3_VER}
    ./configure --prefix=/usr/local/python3.7 --enable-optimizations
    make -j ${CPUS} && make install || make_result="fail"
    cd ..
    if [[ $make_result == "fail" ]]; then
        return 1
    fi

    ln -sf /usr/local/python3.7/bin/python3 /usr/local/bin/python3
    ln -sf /usr/local/python3.7/bin/2to3 /usr/local/bin/2to3
    ln -sf /usr/local/python3.7/bin/idle3 /usr/local/bin/idle3
    ln -sf /usr/local/python3.7/bin/pydoc3 /usr/local/bin/pydoc3
    ln -sf /usr/local/python3.7/bin/python3.7-config /usr/local/bin/python3.7-config
    ln -sf /usr/local/python3.7/bin/python3-config /usr/local/bin/python3-config
    ln -sf /usr/local/python3.7/bin/pyvenv /usr/local/bin/pyvenv

    curl https://bootstrap.pypa.io/get-pip.py | python3
    ln -sf /usr/local/python3.7/bin/pip3 /usr/local/bin/pip3
    pip3 install --upgrade pip
    install_uwsgi

    if [[ ${INSSTACK} != "auto" ]]; then
        echo_yellow "[!] 是否将 Python3 设置为默认 Python 解释器: "
        read -r -p "是(Y)/否(N): " DEFPYH
        if [[ ${DEFPYH} == "y" || ${DEFPYH} == "Y" ]]; then
            # rm -r /usr/bin/python
            ln -sf /usr/local/bin/python3 /usr/local/bin/python
            sed -i "s/python/python2/" /usr/bin/yum

            # rm -r /usr/bin/pip
            ln -sf /usr/local/bin/pip3 /usr/local/bin/pip
        fi
    fi
}

install_nodejs() {
    wget_cache "https://nodejs.org/dist/${NODEJS_VER}/node-${NODEJS_VER}-linux-x64.tar.xz" "node-${NODEJS_VER}-linux-x64.tar.xz"
    tar -xf node-${NODEJS_VER}-linux-x64.tar.xz || return 255

    mv node-${NODEJS_VER}-linux-x64 /usr/local/node
    chown root:root -R /usr/local
    ln -sf /usr/local/node/bin/node /usr/local/bin/node
    ln -sf /usr/local/node/bin/npm /usr/local/bin/npm
    ln -sf /usr/local/node/bin/npx /usr/local/bin/npx
}

install_mysql() {
    # wget https://dev.mysql.com/get/mysql57-community-release-el7-11.noarch.rpm
    # rpm -Uvh mysql57-community-release-el7-11.noarch.rpm
    # yum install -y mysql-community-server

    if [[ ${INSSTACK} != "auto" ]]; then
        echo_yellow "请输入 MySQL ROOT 用户密码（直接回车将自动生成密码）"
        read -r -p "密码: " DBROOTPWD
    fi
    if [[ ${DBROOTPWD} == "" ]]; then
        echo_red "没有输入密码，将采用默认密码。"
        DBROOTPWD="zsen@Club#$RANDOM"
    fi
    echo_green "MySQL ROOT 用户密码(请记下来): ${DBROOTPWD}"

    wget_cache "http://www.sourceforge.net/projects/boost/files/boost/1.59.0/boost_1_59_0.tar.gz" "boost_1_59_0.tar.gz" "Boost"
    tar zxvf boost_1_59_0.tar.gz || return 255

    mv boost_1_59_0 /usr/local/boost
    chown root:root -R /usr/local/boost

    wget_cache "https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-${MYSQL_VER}.tar.gz" "mysql-${MYSQL_VER}.tar.gz"
    tar zxvf mysql-${MYSQL_VER}.tar.gz || return 255

    get_module_ver "cmake"
    if [ -z "${MODULE_VER}" ]; then
        MODULE_NAME="CMake"
        echo_yellow "编译 MySQL 源码需要使用到 CMake!"
        ins_begin
        install_cmake
        if [[ $? == 1 ]]; then
            return 1
        fi
        ins_end
        MODULE_NAME="MySQL"
    fi

    rpm -qa | grep mysql
    rpm -e mysql mysql-libs --nodeps
    yum remove -y mysql-server mysql mysql-libs
    yum install -y ncurses-devel gcc gcc-c++ bison
    yum -y remove boost-*

    MYSQLHOME=${INSHOME}/database/mysql
    rm -rf ${MYSQLHOME}
    rm -rf /usr/local/mysql
    rm -f /etc/my.cnf
    groupadd mysql
    useradd -r -g mysql -s /bin/false mysql
    mkdir -p ${MYSQLHOME}
    chown -R mysql:mysql ${MYSQLHOME}

    cd mysql-${MYSQL_VER}
    cmake . -DCMAKE_INSTALL_PREFIX=/usr/local/mysql \
            -DDOWNLOAD_BOOST=1 \
            -DWITH_BOOST=/usr/local/boost \
            -DMYSQL_DATADIR="${MYSQLHOME}" \
            -DDEFAULT_CHARSET=utf8mb4 \
            -DDEFAULT_COLLATION=utf8mb4_general_ci
    make -j ${CPUS} && make install || make_result="fail"
    cd ..
    if [[ $make_result == "fail" ]]; then
        return 1
    fi

    chgrp -R mysql /usr/local/mysql/.
    cp /usr/local/mysql/support-files/mysql.server /etc/init.d/mysqld
    chmod +x /etc/init.d/mysqld
    chkconfig --add mysqld
    chkconfig mysqld on  # 设置开机启动

    cat > /etc/my.cnf<<EOF
[client]
#password   = your_password
port        = 3306
socket      = /tmp/mysql.sock
default-character-set = utf8

[mysqld]
port        = 3306
socket      = /tmp/mysql.sock
datadir     = ${MYSQLHOME}
skip-external-locking
key_buffer_size = 16M
max_allowed_packet = 1M
table_open_cache = 64
sort_buffer_size = 512K
net_buffer_length = 8K
read_buffer_size = 256K
read_rnd_buffer_size = 512K
myisam_sort_buffer_size = 8M
thread_cache_size = 8
query_cache_size = 8M
tmp_table_size = 16M
performance_schema_max_table_instances = 500

explicit_defaults_for_timestamp = true
#skip-networking
max_connections = 500
max_connect_errors = 100
open_files_limit = 65535

log-bin=mysql-bin
binlog_format = mixed
server-id = 1
expire_logs_days = 10
early-plugin-load = ""

default_storage_engine = InnoDB
innodb_file_per_table = 1
innodb_data_home_dir = ${MYSQLHOME}
innodb_data_file_path = ibdata1:10M:autoextend
innodb_log_group_home_dir = ${MYSQLHOME}
innodb_buffer_pool_size = 16M
innodb_log_file_size = 5M
innodb_log_buffer_size = 8M
innodb_flush_log_at_trx_commit = 1
innodb_lock_wait_timeout = 50

character-set-server = utf8
collation-server = utf8_general_ci  # 不区分大小写
# collation-server =  utf8_bin  # 区分大小写
# collation-server = utf8_unicode_ci  # 比 utf8_general_ci 更准确

[mysqldump]
quick
max_allowed_packet = 16M

[mysql]
no-auto-rehash
auto-rehash                   # 自动补全命令
default-character-set=utf8    # mysql 连接字符集

[myisamchk]
key_buffer_size = 20M
sort_buffer_size = 20M
read_buffer = 2M
write_buffer = 2M

[mysqlhotcopy]
interactive-timeout
EOF

    if [[ ${MemTotal} -gt 1024 && ${MemTotal} -lt 2048 ]]; then
        sed -i "s#^key_buffer_size.*#key_buffer_size = 32M#" /etc/my.cnf
        sed -i "s#^table_open_cache.*#table_open_cache = 128#" /etc/my.cnf
        sed -i "s#^sort_buffer_size.*#sort_buffer_size = 768K#" /etc/my.cnf
        sed -i "s#^read_buffer_size.*#read_buffer_size = 768K#" /etc/my.cnf
        sed -i "s#^myisam_sort_buffer_size.*#myisam_sort_buffer_size = 8M#" /etc/my.cnf
        sed -i "s#^thread_cache_size.*#thread_cache_size = 16#" /etc/my.cnf
        sed -i "s#^query_cache_size.*#query_cache_size = 16M#" /etc/my.cnf
        sed -i "s#^tmp_table_size.*#tmp_table_size = 32M#" /etc/my.cnf
        sed -i "s#^innodb_buffer_pool_size.*#innodb_buffer_pool_size = 128M#" /etc/my.cnf
        sed -i "s#^innodb_log_file_size.*#innodb_log_file_size = 32M#" /etc/my.cnf
        sed -i "s#^performance_schema_max_table_instances.*#performance_schema_max_table_instances = 1000#" /etc/my.cnf
    elif [[ ${MemTotal} -ge 2048 && ${MemTotal} -lt 4096 ]]; then
        sed -i "s#^key_buffer_size.*#key_buffer_size = 64M#" /etc/my.cnf
        sed -i "s#^table_open_cache.*#table_open_cache = 256#" /etc/my.cnf
        sed -i "s#^sort_buffer_size.*#sort_buffer_size = 1M#" /etc/my.cnf
        sed -i "s#^read_buffer_size.*#read_buffer_size = 1M#" /etc/my.cnf
        sed -i "s#^myisam_sort_buffer_size.*#myisam_sort_buffer_size = 16M#" /etc/my.cnf
        sed -i "s#^thread_cache_size.*#thread_cache_size = 32#" /etc/my.cnf
        sed -i "s#^query_cache_size.*#query_cache_size = 32M#" /etc/my.cnf
        sed -i "s#^tmp_table_size.*#tmp_table_size = 64M#" /etc/my.cnf
        sed -i "s#^innodb_buffer_pool_size.*#innodb_buffer_pool_size = 256M#" /etc/my.cnf
        sed -i "s#^innodb_log_file_size.*#innodb_log_file_size = 64M#" /etc/my.cnf
        sed -i "s#^performance_schema_max_table_instances.*#performance_schema_max_table_instances = 2000#" /etc/my.cnf
    elif [[ ${MemTotal} -ge 4096 && ${MemTotal} -lt 8192 ]]; then
        sed -i "s#^key_buffer_size.*#key_buffer_size = 128M#" /etc/my.cnf
        sed -i "s#^table_open_cache.*#table_open_cache = 512#" /etc/my.cnf
        sed -i "s#^sort_buffer_size.*#sort_buffer_size = 2M#" /etc/my.cnf
        sed -i "s#^read_buffer_size.*#read_buffer_size = 2M#" /etc/my.cnf
        sed -i "s#^myisam_sort_buffer_size.*#myisam_sort_buffer_size = 32M#" /etc/my.cnf
        sed -i "s#^thread_cache_size.*#thread_cache_size = 64#" /etc/my.cnf
        sed -i "s#^query_cache_size.*#query_cache_size = 64M#" /etc/my.cnf
        sed -i "s#^tmp_table_size.*#tmp_table_size = 64M#" /etc/my.cnf
        sed -i "s#^innodb_buffer_pool_size.*#innodb_buffer_pool_size = 512M#" /etc/my.cnf
        sed -i "s#^innodb_log_file_size.*#innodb_log_file_size = 128M#" /etc/my.cnf
        sed -i "s#^performance_schema_max_table_instances.*#performance_schema_max_table_instances = 4000#" /etc/my.cnf
    elif [[ ${MemTotal} -ge 8192 && ${MemTotal} -lt 16384 ]]; then
        sed -i "s#^key_buffer_size.*#key_buffer_size = 256M#" /etc/my.cnf
        sed -i "s#^table_open_cache.*#table_open_cache = 1024#" /etc/my.cnf
        sed -i "s#^sort_buffer_size.*#sort_buffer_size = 4M#" /etc/my.cnf
        sed -i "s#^read_buffer_size.*#read_buffer_size = 4M#" /etc/my.cnf
        sed -i "s#^myisam_sort_buffer_size.*#myisam_sort_buffer_size = 64M#" /etc/my.cnf
        sed -i "s#^thread_cache_size.*#thread_cache_size = 128#" /etc/my.cnf
        sed -i "s#^query_cache_size.*#query_cache_size = 128M#" /etc/my.cnf
        sed -i "s#^tmp_table_size.*#tmp_table_size = 128M#" /etc/my.cnf
        sed -i "s#^innodb_buffer_pool_size.*#innodb_buffer_pool_size = 1024M#" /etc/my.cnf
        sed -i "s#^innodb_log_file_size.*#innodb_log_file_size = 256M#" /etc/my.cnf
        sed -i "s#^performance_schema_max_table_instances.*#performance_schema_max_table_instances = 6000#" /etc/my.cnf
    elif [[ ${MemTotal} -ge 16384 && ${MemTotal} -lt 32768 ]]; then
        sed -i "s#^key_buffer_size.*#key_buffer_size = 512M#" /etc/my.cnf
        sed -i "s#^table_open_cache.*#table_open_cache = 2048#" /etc/my.cnf
        sed -i "s#^sort_buffer_size.*#sort_buffer_size = 8M#" /etc/my.cnf
        sed -i "s#^read_buffer_size.*#read_buffer_size = 8M#" /etc/my.cnf
        sed -i "s#^myisam_sort_buffer_size.*#myisam_sort_buffer_size = 128M#" /etc/my.cnf
        sed -i "s#^thread_cache_size.*#thread_cache_size = 256#" /etc/my.cnf
        sed -i "s#^query_cache_size.*#query_cache_size = 256M#" /etc/my.cnf
        sed -i "s#^tmp_table_size.*#tmp_table_size = 256M#" /etc/my.cnf
        sed -i "s#^innodb_buffer_pool_size.*#innodb_buffer_pool_size = 2048M#" /etc/my.cnf
        sed -i "s#^innodb_log_file_size.*#innodb_log_file_size = 512M#" /etc/my.cnf
        sed -i "s#^performance_schema_max_table_instances.*#performance_schema_max_table_instances = 8000#" /etc/my.cnf
    elif [[ ${MemTotal} -ge 32768 ]]; then
        sed -i "s#^key_buffer_size.*#key_buffer_size = 1024M#" /etc/my.cnf
        sed -i "s#^table_open_cache.*#table_open_cache = 4096#" /etc/my.cnf
        sed -i "s#^sort_buffer_size.*#sort_buffer_size = 16M#" /etc/my.cnf
        sed -i "s#^read_buffer_size.*#read_buffer_size = 16M#" /etc/my.cnf
        sed -i "s#^myisam_sort_buffer_size.*#myisam_sort_buffer_size = 256M#" /etc/my.cnf
        sed -i "s#^thread_cache_size.*#thread_cache_size = 512#" /etc/my.cnf
        sed -i "s#^query_cache_size.*#query_cache_size = 512M#" /etc/my.cnf
        sed -i "s#^tmp_table_size.*#tmp_table_size = 512M#" /etc/my.cnf
        sed -i "s#^innodb_buffer_pool_size.*#innodb_buffer_pool_size = 4096M#" /etc/my.cnf
        sed -i "s#^innodb_log_file_size.*#innodb_log_file_size = 1024M#" /etc/my.cnf
        sed -i "s#^performance_schema_max_table_instances.*#performance_schema_max_table_instances = 10000#" /etc/my.cnf
    fi

    /usr/local/mysql/bin/mysqld --initialize-insecure --basedir=/usr/local/mysql --datadir=${MYSQLHOME} --user=mysql
    # --initialize 会生成一个随机密码(~/.mysql_secret)，--initialize-insecure 不会生成密码

    cat > /etc/ld.so.conf.d/mysql.conf<<EOF
/usr/local/mysql/lib
/usr/local/lib
EOF
    ldconfig
    ln -sf /usr/local/mysql/lib/mysql /usr/lib/mysql
    ln -sf /usr/local/mysql/include/mysql /usr/include/mysql

    if [ -d "/proc/vz" ]; then
        ulimit -s unlimited
    fi

    ln -sf /usr/local/mysql/bin/mysql /usr/local/bin/mysql
    ln -sf /usr/local/mysql/bin/mysqladmin /usr/local/bin/mysqladmin
    ln -sf /usr/local/mysql/bin/mysqldump /usr/local/bin/mysqldump
    ln -sf /usr/local/mysql/bin/myisamchk /usr/local/bin/myisamchk
    ln -sf /usr/local/mysql/bin/mysqld_safe /usr/local/bin/mysqld_safe
    ln -sf /usr/local/mysql/bin/mysqlcheck /usr/local/bin/mysqlcheck

    /etc/init.d/mysqld start

    # 设置数据库密码
    /usr/local/mysql/bin/mysqladmin -u root password "${DBROOTPWD}"
    # /usr/local/mysql/bin/mysql -e "grant all privileges on *.* to root@'127.0.0.1' identified by \"${DBROOTPWD}\" with grant option;"
    # /usr/local/mysql/bin/mysql -e "grant all privileges on *.* to root@'localhost' identified by \"${DBROOTPWD}\" with grant option;"
    # /usr/local/mysql/bin/mysql -e "SET PASSWORD FOR 'root'@'localhost' = PASSWORD('${DBROOTPWD}');"
    # /usr/local/mysql/bin/mysql -e "UPDATE mysql.user SET authentication_string=PASSWORD('${DBROOTPWD}') WHERE User='root';"
    /usr/local/mysql/bin/mysql -e "FLUSH PRIVILEGES;" -uroot -p${DBROOTPWD}

    if [[ ${INSSTACK} != "auto" ]]; then
        echo_yellow "是否生成 ~/.my.cnf（如选择是，在命令行可以不用密码进入MySQL）? "
        read -r -p "是(Y)/否(N): " ADDMYCNF
    fi
    if [[ ${ADDMYCNF} == "y" || ${ADDMYCNF} == "Y" ]]; then
        cat > /root/.my.cnf << EOF
[client]
host     = localhost
user     = root
password = ${DBROOTPWD}
EOF
        chmod 0400 /root/.my.cnf
    fi
}

install_start-stop-daemon() {
    ins_begin "start-stop-daemon"

    yum install -y ncurses-devel
    wget_cache "http://ftp.de.debian.org/debian/pool/main/d/dpkg/dpkg_${STARTSTOPDAEMON_VER}.tar.xz" "start-stop-daemon_${STARTSTOPDAEMON_VER}.tar.xz" "start-stop-daemon"
    mkdir start-stop-daemon_${STARTSTOPDAEMON_VER}
    if ! tar -xf start-stop-daemon_${STARTSTOPDAEMON_VER}.tar.xz -C ./start-stop-daemon_${STARTSTOPDAEMON_VER} --strip-components 1; then
        echo "start-stop-daemon-${STARTSTOPDAEMON_VER} 源码包下载失败，会影响 Nginx 服务！" >> /root/install-error.log
        ins_end
        return
    fi

    cd start-stop-daemon_${STARTSTOPDAEMON_VER}
    ./configure
    make && make install || echo "start-stop-daemon-${STARTSTOPDAEMON_VER} 源码编译失败，会影响 Nginx 服务！" >> /root/install-error.log
    cd ..

    ins_end "start-stop-daemon"
}

install_nginx() {
    rpm -qa | grep httpd
    rpm -e httpd httpd-tools --nodeps
    yum remove -y httpd*
    yum install -y build-essential libpcre3 libpcre3-dev zlib1g-dev patch redhat-lsb pcre-devel

    install_start-stop-daemon
    install_acme

    get_module_ver "git"
    if [ -z "${MODULE_VER}" ]; then
        MODULE_NAME="Git"
        echo_yellow "编译 Nginx 源码需要使用到 Git!"
        ins_begin
        install_git
        if [[ $? == 1 ]]; then
            return 1
        fi
        ins_end
        MODULE_NAME="Nginx"
    fi

    git clone https://github.com/google/ngx_brotli.git
    cd ngx_brotli
    git submodule update --init
    cd ..

    wget_cache "https://www.openssl.org/source/openssl-${OPENSSL_VER}.tar.gz" "openssl-${OPENSSL_VER}.tar.gz" "OpenSSL"
    tar xzf openssl-${OPENSSL_VER}.tar.gz || return 255
    mv openssl-${OPENSSL_VER} openssl

    wget_cache "https://nginx.org/download/nginx-${NGINX_VER}.tar.gz" "nginx-${NGINX_VER}.tar.gz"
    tar zxvf nginx-${NGINX_VER}.tar.gz || return 255
    rm -rf /usr/local/nginx

    cd nginx-${NGINX_VER}
    sed -i "s/${NGINX_VER}/8.8.8.8/g" src/core/nginx.h
    ./configure \
        --add-module=../ngx_brotli \
        --with-openssl=../openssl \
        --with-openssl-opt='enable-tls1_3 enable-weak-ssl-ciphers' \
        --with-http_v2_module \
        --with-http_ssl_module \
        --with-http_gzip_static_module \
        --without-mail_pop3_module \
        --without-mail_imap_module \
        --without-mail_smtp_module
    make -j ${CPUS} && make install || make_result="fail" 
    cd ..
    if [[ $make_result == "fail" ]]; then
        return 1
    fi

    ln -sf /usr/local/nginx/sbin/nginx /usr/local/bin/nginx
    rm -f /usr/local/nginx/conf/nginx.conf
    echo "${NGINX_VER}" > /usr/local/nginx/version.txt

    mkdir -p "${INSHOME}/wwwlogs"
    chmod 777 "${INSHOME}/wwwlogs"

    mkdir -p "${INSHOME}/wwwroot/challenges"
    chown -R nobody:nobody "${INSHOME}/wwwroot"
    chmod +w "${INSHOME}/wwwroot"
    chmod -R 777 "${INSHOME}/wwwroot/challenges"
    
    mkdir -p "${INSHOME}/wwwcert/scts"
    chown -R nobody:nobody "${INSHOME}/wwwcert/scts"

    mkdir -p "${INSHOME}/wwwconf/nginx"
    chown -R nobody:nobody "${INSHOME}/wwwconf"
    chmod +w "${INSHOME}/wwwconf"

    cat > /usr/local/nginx/conf/nginx.conf<<EOF
worker_processes auto;

error_log  ${INSHOME}/wwwlogs/nginx_error.log  crit;

pid        /usr/local/nginx/logs/nginx.pid;

#Specifies the value for maximum file descriptors that can be opened by this process.
worker_rlimit_nofile 51200;

events
    {
        use epoll;
        worker_connections 51200;
        multi_accept on;
    }

http
    {
        include       mime.types;
        default_type  application/octet-stream;

        charset UTF-8;

        server_names_hash_bucket_size 128;
        client_header_buffer_size 32k;
        large_client_header_buffers 4 32k;
        client_max_body_size 50m;

        sendfile           on;
        tcp_nopush         on;
        tcp_nodelay        on;

        keepalive_timeout  60;

        gzip               on;
        gzip_vary          on;

        gzip_min_length    1k;
        gzip_comp_level    6;
        gzip_buffers       16 8k;
        gzip_types         text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript application/javascript image/svg+xml;

        gzip_proxied       any;
        gzip_disable       "msie6";

        gzip_http_version  1.0;

        brotli             on;
        brotli_comp_level  6;
        brotli_types       text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript application/javascript image/svg+xml;

        server_tokens off;
        access_log off;

        # php-fpm Configure
        fastcgi_connect_timeout 300;
        fastcgi_send_timeout 300;
        fastcgi_read_timeout 300;
        fastcgi_buffer_size 64k;
        fastcgi_buffers 4 64k;
        fastcgi_busy_buffers_size 128k;
        fastcgi_temp_file_write_size 256k;

        server {
            listen 80 default_server;
            server_name _;
            rewrite ^ http://www.gov.cn/ permanent;
        }

        include ${INSHOME}/wwwconf/nginx/*.conf;
    }
EOF

    cat > /etc/init.d/nginx<<EOF
#! /bin/sh

### BEGIN INIT INFO
# Provides:          nginx
# Required-Start:    \$all
# Required-Stop:     \$all
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: starts the nginx web server
# Description:       starts nginx using start-stop-daemon
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
NAME=nginx
DESC=Nginx
DAEMON=/usr/local/nginx/sbin/\$NAME
PIDFILE=/usr/local/nginx/logs/\$NAME.pid
CONFIGFILE=/usr/local/nginx/conf/\$NAME.conf

test -x \$DAEMON || exit 1

log_success_msg(){
    printf "%-58s \\033[32m[ %s ]\\033[0m\\n" "\$@"
}
log_failure_msg(){
    printf "%-58s \\033[31m[ %s ]\\033[0m\\n" "\$@"
}
log_warning_msg(){
    printf "%-58s \\033[33m[ %s ]\\033[0m\\n" "\$@"
}

case "\$1" in
    start)
        start-stop-daemon --start --quiet --pidfile \$PIDFILE --exec \$DAEMON -- \$DAEMON_OPTS || true
        if [ \$? -eq 0 ]; then
            log_success_msg "Starting \$DESC: " "SUCCESS"
        else
            log_failure_msg "Starting \$DESC: " "Failed"
        fi
        ;;

    stop)
        start-stop-daemon --stop --quiet --pidfile \$PIDFILE --exec \$DAEMON || true
        if [ \$? -eq 0 ]; then
            log_success_msg "Stopping \$DESC: " "SUCCESS"
        else
            log_failure_msg "Stopping \$DESC: " "Failed"
        fi
        ;;

    restart|force-reload)
        start-stop-daemon --stop --quiet --pidfile \$PIDFILE --exec \$DAEMON || true
        sleep 1
        start-stop-daemon --start --quiet --pidfile \$PIDFILE --exec \$DAEMON -- \$DAEMON_OPTS || true
        if [ \$? -eq 0 ]; then
            log_success_msg "Restarting \$DESC: " "SUCCESS"
        else
            log_failure_msg "Restarting \$DESC: " "Failed"
        fi
        ;;

    reload)
        start-stop-daemon --stop --signal HUP --quiet --pidfile \$PIDFILE --exec \$DAEMON || true
        if [ \$? -eq 0 ]; then
            log_success_msg "Reloading \$DESC configuration: " "SUCCESS"
        else
            log_failure_msg "Reloading \$DESC configuration: " "Failed"
        fi
        ;;

    status)
        start-stop-daemon --status --pidfile \$PIDFILE
        case "\$?" in
            0)
                log_success_msg "\$DESC status: " "Running"
                ;;
            1)
                log_failure_msg "\$DESC status: (pid file exists)" "Stopped"
                ;;
            3)
                log_warning_msg "\$DESC status: " "Stopped"
                ;;
            4)
                log_failure_msg "\$DESC status: " "Unable"
                ;;
        esac
        ;;

    configtest|test)
        \$DAEMON -t
        if [ \$? -eq 0 ]; then
            log_success_msg "Test \$DESC configuration: " "OK"
        else
            log_failure_msg "Test \$DESC configuration: " "Failed"
        fi
        ;;

    *)
        echo "Usage: \$0 {start|stop|restart|reload|status|configtest}"
        ;;
esac

exit 0
EOF

    # 添加防火墙端口
    firewall-cmd --zone=public --add-port=80/tcp --permanent
    firewall-cmd --zone=public --add-port=443/tcp --permanent
    firewall-cmd --reload

    chmod +x /etc/init.d/nginx
    chkconfig --add nginx
    chkconfig nginx on
}

install_php() {
    yum -y remove php* libzip
    rpm -qa | grep php
    rpm -e php-mysql php-cli php-gd php-common php --nodeps
    yum install -y libmcrypt libmcrypt-devel mcrypt mhash oniguruma-devel libxslt libxslt-devel libxml2 libxml2-devel curl-devel libjpeg-devel libpng-devel freetype-devel libicu-devel

    wget_cache "https://libzip.org/download/libzip-${LIBZIP_VER}.tar.gz" "libzip-${LIBZIP_VER}.tar.gz" "libzip"
    tar zxvf libzip-${LIBZIP_VER}.tar.gz || return 255

    get_module_ver "cmake"
    if [ -z "${MODULE_VER}" ]; then
        MODULE_NAME="CMake"
        echo_yellow "编译 PHP 源码需要使用到 CMake!"
        ins_begin
        install_cmake
        if [[ $? == 1 ]]; then
            return 1
        fi
        ins_end
        MODULE_NAME="PHP"
    fi

    mkdir libzip-${LIBZIP_VER}/build 
    cd libzip-${LIBZIP_VER}/build
    cmake ..
    make && make install || make_result="fail"
    cd ../..
    if [[ $make_result == "fail" ]]; then
        echo "make libzip failed!" >> /root/install-error.log
        return 1
    fi
    make_result=""

    cat > /etc/ld.so.conf.d/php.local.conf<<EOF
/usr/local/lib64
/usr/local/lib
/usr/lib
/usr/lib64
EOF
    ldconfig

    wget_cache "http://cn2.php.net/get/php-${PHP_VER}.tar.gz/from/this/mirror" "php-${PHP_VER}.tar.gz" "PHP"
    tar zxvf php-${PHP_VER}.tar.gz || return 255

    cd php-${PHP_VER}
    ./configure --prefix=/usr/local/php \
                --with-config-file-path=/usr/local/php/etc \
                --with-config-file-scan-dir=/usr/local/php/conf.d \
                --with-fpm-user=nobody \
                --with-fpm-group=nobody \
                --with-mysqli=mysqlnd \
                --with-pdo-mysql=mysqlnd \
                --with-iconv-dir \
                --with-freetype-dir=/usr/local/freetype \
                --with-jpeg-dir \
                --with-png-dir \
                --with-zlib \
                --with-libzip \
                --with-libxml-dir=/usr \
                --with-curl \
                --with-gd \
                --with-openssl \
                --with-mhash \
                --with-xmlrpc \
                --with-gettext \
                --with-xsl \
                --with-pear \
                --disable-rpath \
                --enable-fpm \
                --enable-xml \
                --enable-bcmath \
                --enable-shmop \
                --enable-sysvsem \
                --enable-inline-optimization \
                --enable-mysqlnd \
                --enable-mbregex \
                --enable-mbstring \
                --enable-intl \
                --enable-pcntl \
                --enable-ftp \
                --enable-pcntl \
                --enable-sockets \
                --enable-soap \
                --enable-opcache \
                --enable-zip \
                --enable-exif \
                --enable-session

    #make ZEND_EXTRA_LIBS='-liconv' && make install
    make -j ${CPUS} && make install || make_result="fail"
    cd ..
    if [[ $make_result == "fail" ]]; then
        return 1
    fi

    ln -sf /usr/local/php/bin/php /usr/local/bin/php
    ln -sf /usr/local/php/bin/phpize /usr/local/bin/phpize
    ln -sf /usr/local/php/bin/pear /usr/local/bin/pear
    ln -sf /usr/local/php/bin/pecl /usr/local/bin/pecl
    ln -sf /usr/local/php/sbin/php-fpm /usr/local/bin/php-fpm
    rm -f /usr/local/php/conf.d/*

    mkdir -p /usr/local/php/{etc,conf.d}
    cp php-${PHP_VER}/php.ini-production /usr/local/php/etc/php.ini

    # php extensions
    sed -i "s/post_max_size =.*/post_max_size = 50M/g" /usr/local/php/etc/php.ini
    sed -i "s/upload_max_filesize =.*/upload_max_filesize = 50M/g" /usr/local/php/etc/php.ini
    sed -i "s/;date.timezone =.*/date.timezone = PRC/g" /usr/local/php/etc/php.ini
    sed -i "s/short_open_tag =.*/short_open_tag = On/g" /usr/local/php/etc/php.ini
    sed -i "s/;cgi.fix_pathinfo=.*/cgi.fix_pathinfo=0/g" /usr/local/php/etc/php.ini
    sed -i "s/max_execution_time =.*/max_execution_time = 60/g" /usr/local/php/etc/php.ini
    sed -i "s/expose_php = On/expose_php = Off/g" /usr/local/php/etc/php.ini
    sed -i "s/disable_functions =.*/disable_functions = passthru,exec,system,chroot,chgrp,chown,shell_exec,proc_open,proc_get_status,popen,ini_alter,ini_restore,dl,openlog,syslog,readlink,symlink,popepassthru,stream_socket_server/g" /usr/local/php/etc/php.ini
    sed -i "s#;error_log = php_errors.log#error_log = ${INSHOME}/wwwlogs/php_errors.log#g" /usr/local/php/etc/php.ini

    if [[ ${MemTotal} -gt 2048 && ${MemTotal} -le 4096 ]]; then
        sed -i "s/memory_limit =.*/memory_limit = 128M/g" /usr/local/php/etc/php.ini
    elif [[ ${MemTotal} -ge 4096 ]]; then
        sed -i "s/memory_limit =.*/memory_limit = 256M/g" /usr/local/php/etc/php.ini
    fi

    if [[ ${INSSTACK} != "auto" ]]; then
        echo_yellow "是否启用 Opcache? "
        read -r -p "是(Y)/否(N): " OPCACHE
    else
        OPCACHE="Y"
    fi
    if [[ ${OPCACHE} == "y" || ${OPCACHE} == "Y" ]]; then
        sed -i "s/;opcache.enable=1/opcache.enable=1/g" /usr/local/php/etc/php.ini
        sed -i "s/;opcache.enable_cli=1/opcache.enable_cli=1/g" /usr/local/php/etc/php.ini
        sed -i "s/;opcache.memory_consumption=128/opcache.memory_consumption=192/g" /usr/local/php/etc/php.ini
        sed -i "s/;opcache.max_accelerated_files=.*/opcache.max_accelerated_files=7963/g" /usr/local/php/etc/php.ini
        sed -i "s/;opcache.interned_strings_buffer=.*/opcache.interned_strings_buffer=16/g" /usr/local/php/etc/php.ini
        sed -i "s/;opcache.revalidate_freq=.*/opcache.revalidate_freq=0/g" /usr/local/php/etc/php.ini
        echo "zend_extension=opcache.so" >> /usr/local/php/etc/php.ini

        if [[ ${INSSTACK} != "auto" ]]; then
            echo_yellow "当前服务器是否生产服务器（如选择是，每次更新 PHP 代码后请重启 php-fpm）? "
            read -r -p "是(Y)/否(N): " PHPPROD
        else
            PHPPROD="Y"
        fi
        if [[ ${PHPPROD} == "y" || ${PHPPROD} == "Y" ]]; then
            sed -i "s/;opcache.validate_timestamps=.*/opcache.validate_timestamps=0/g" /usr/local/php/etc/php.ini
        fi
    fi

    if [[ ${INSSTACK} != "auto" ]]; then
        echo_yellow "是否限制PHP访问目录(如限制，可能会造成系统缓存影响)?"
        read -r -p "是(Y)/否(N): " SETOPENBASEDIR
    fi
    if [[ ${SETOPENBASEDIR} == "y" || ${SETOPENBASEDIR} == "Y" ]]; then
        echo_blue "默认允许目录: ${INSHOME}/wwwroot /tmp"
        read -r -p "如要允许更多目录，请输入后回车(多个目录请用:隔开): " ALLOWPHPDIR
        if [[ ${ALLOWPHPDIR} != "" ]]; then
            ALLOWPHPDIR=":${ALLOWPHPDIR}"
        fi
        sed -i "s#;open_basedir =#open_basedir = ${INSHOME}/wwwroot:/tmp${ALLOWPHPDIR}#g" /usr/local/php/etc/php.ini
    fi

    pear config-set php_ini /usr/local/php/etc/php.ini
    pecl config-set php_ini /usr/local/php/etc/php.ini

    if [[ ${INSSTACK} != "auto" ]]; then
        echo_yellow "是否安装 Composer? "
        read -r -p "是(Y)/否(N): " INSCPR
        if [[ ${INSCPR} == "y" || ${INSCPR} == "Y" ]]; then
            ins_begin "Composer"
            curl -sS --connect-timeout 30 -m 60 https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
            ins_end "composer"
        fi
    fi

    cat >/usr/local/php/etc/php-fpm.conf<<EOF
[global]
pid = /usr/local/php/var/run/php-fpm.pid
error_log = ${INSHOME}/wwwlogs/php-fpm.log
log_level = notice

[www]
listen = /tmp/php-cgi.sock
listen.backlog = -1
listen.allowed_clients = 127.0.0.1
listen.owner = nobody
listen.group = nobody
listen.mode = 0666
user = nobody
group = nobody
pm = static
pm.max_children = 10
pm.start_servers = 3
pm.min_spare_servers = 2
pm.max_spare_servers = 6
pm.max_requests = 500
request_terminate_timeout = 100
request_slowlog_timeout = 0
slowlog = ${INSHOME}/wwwlogs/php-fpm-slow.log
EOF

    sed -i "s#pm.max_children.*#pm.max_children = $(($MemTotal/2/20))#" /usr/local/php/etc/php-fpm.conf
    sed -i "s#pm.start_servers.*#pm.start_servers = $(($MemTotal/2/30))#" /usr/local/php/etc/php-fpm.conf
    sed -i "s#pm.min_spare_servers.*#pm.min_spare_servers = $(($MemTotal/2/40))#" /usr/local/php/etc/php-fpm.conf
    sed -i "s#pm.max_spare_servers.*#pm.max_spare_servers = $(($MemTotal/2/20))#" /usr/local/php/etc/php-fpm.conf

    cp php-${PHP_VER}/sapi/fpm/init.d.php-fpm /etc/init.d/php-fpm
    sed -i '20 s/^/log_success_msg(){\n\tprintf "%-58s \\033[32m[ %s ]\\033[0m\\n" "\$@"\n}\nlog_failure_msg(){\n\tprintf "%-58s \\033[31m[ %s ]\\033[0m\\n" "\$@"\n}\nlog_warning_msg(){\n\tprintf "%-58s \\033[33m[ %s ]\\033[0m\\n" "\$@"\n}\n/' /etc/init.d/php-fpm
    sed -i 's/echo -n "/title="/g'  /etc/init.d/php-fpm
    sed -i 's/php-fpm "/php-fpm: "/g'  /etc/init.d/php-fpm
    sed -i 's/exit 1/exit 0/g'  /etc/init.d/php-fpm
    sed -i '/echo -n ./d' /etc/init.d/php-fpm
    sed -i "s/echo \" failed\"/log_failure_msg \"\$title\" \"Failed\" /g"  /etc/init.d/php-fpm
    sed -i "s/echo \" done\"/log_success_msg \"\$title\" \"Success\" /g"  /etc/init.d/php-fpm
    sed -i "s/echo \"warning, no pid file found - php-fpm is not running ?\"/log_warning_msg \"\$title\" \"Not Running\"/g" /etc/init.d/php-fpm
    sed -i "s/echo \" failed. Use force-quit\"/log_failure_msg \"\$title\" \"Failed. Use force-quit\"/g"  /etc/init.d/php-fpm
    sed -i 's/echo "php-fpm is stopped"/log_warning_msg "php-fpm status: " "Stopped"/g' /etc/init.d/php-fpm
    sed -i "s/echo \"php-fpm (pid \$PID) is running...\"/log_success_msg \"php-fpm status: (pid \$PID)\" \"Running\"/g"  /etc/init.d/php-fpm
    sed -i 's/echo "php-fpm dead but pid file exists"/log_failure_msg "php-fpm status: (pid file exists)" "Stopped"/g' /etc/init.d/php-fpm
    sed -i "/\$php_fpm_BIN -t/a\\\t\tif [ \$? -eq 0 ]; then\n\t\t\tlog_success_msg \"Test php-fpm configuration: \" \"OK\"\n\t\telse\n\t\t\tlog_failure_msg \"Test php-fpm configuration: \" \"Failed\"\n\t\tfi\n" /etc/init.d/php-fpm

    chmod +x /etc/init.d/php-fpm
    chkconfig --add php-fpm
    chkconfig php-fpm on

    wget_cache "http://pecl.php.net/get/mcrypt-${MCRYPT_VER}.tgz" "mcrypt-${MCRYPT_VER}.tgz" "PHP-Mcrypt"
    if ! tar xf mcrypt-${MCRYPT_VER}.tgz; then
        echo "PHP-Mcrypt ${MCRYPT_VER} 模块源码包下载失败，PHP 服务将不安装此模块！" >> /root/install-error.log
    else
        cd mcrypt-${MCRYPT_VER}
        phpize
        ./configure --with-php-config=/usr/local/php/bin/php-config
        make && make install
        echo "extension=mcrypt.so" >> /usr/local/php/etc/php.ini
        cd ..
    fi

    if [ -s /usr/local/redis/bin/redis-server ]; then
        wget_cache "https://github.com/phpredis/phpredis/archive/master.zip" "phpredis-master.zip" "PHP-Redis"
        if ! unzip phpredis-master.zip; then
            echo "PHP-Redis 模块源码包下载失败，PHP 服务将不安装此模块！" >> /root/install-error.log
        else
            cd phpredis-master
            phpize
            ./configure --with-php-config=/usr/local/php/bin/php-config
            make && make install
            echo "extension=redis.so" >> /usr/local/php/etc/php.ini
            cd ..
        fi
    fi

    if [[ ${INSSTACK} != "auto" ]]; then
        echo_yellow "是否安装 MySQL 扩展（不建议安装，请使用最新版如 MySQLi 扩展）? "
        read -r -p "是(Y)/否(N): " PHPMYSQL
        if [[ ${PHPMYSQL} == "y" || ${PHPMYSQL} == "Y" ]]; then
            wget -c --no-cookie "http://git.php.net/?p=pecl/database/mysql.git;a=snapshot;h=647c933b6cc8f3e6ce8a466824c79143a98ee151;sf=tgz" -O php-mysql.tar.gz
            mkdir ./php-mysql
            if ! tar xzf php-mysql.tar.gz -C ./php-mysql --strip-components 1; then
                echo "PHP-MySQL 扩展源码包下载失败，PHP 服务将不安装此模块！" >> /root/install-error.log
            else
                cd php-mysql
                phpize
                ./configure  --with-php-config=/usr/local/php/bin/php-config --with-mysql=mysqlnd
                make && make install
                echo "extension=mysql.so" >> /usr/local/php/etc/php.ini
                # sed -i "s/^error_reporting = .*/error_reporting = E_ALL & ~E_NOTICE & ~E_DEPRECATED/g" /usr/local/php/etc/php.ini
                cd ..
            fi
        fi
    fi
}

install_redis() {
    if [[ ${INSSTACK} != "auto" ]]; then
        echo_yellow "请输入 Redis 安全密码（直接回车将自动生成密码）"
        read -r -p "密码: " REDISPWD
    fi
    if [[ -z ${REDISPWD} ]]; then
        echo_red "没有输入密码，将采用默认密码。"
        REDISPWD=$(echo "zsenClub#$RANDOM" | md5sum | cut -d " " -f 1)
    fi
    echo_green "Redis 安全密码(请记下来): ${REDISPWD}"

    REDISHOME=${INSHOME}/database/redis
    groupadd redis
    useradd -r -g redis -s /bin/false redis
    mkdir -p /usr/local/redis/{etc,run}
    mkdir -p ${REDISHOME}
    chown -R redis:redis ${REDISHOME}

    wget_cache "http://download.redis.io/releases/redis-${REDIS_VER}.tar.gz" "redis-${REDIS_VER}.tar.gz"
    tar zxvf redis-${REDIS_VER}.tar.gz || return 255

    cd redis-${REDIS_VER}
    make -j ${CPUS} && make PREFIX=/usr/local/redis install || make_result="fail"
    cd ..
    if [[ $make_result == "fail" ]]; then
        return 1
    fi

    cp redis-${REDIS_VER}/redis.conf  /usr/local/redis/etc/
    sed -i "s/daemonize no/daemonize yes/g" /usr/local/redis/etc/redis.conf
    sed -i "s/^# bind 127.0.0.1/bind 127.0.0.1/g" /usr/local/redis/etc/redis.conf
    sed -i "s#^pidfile /var/run/redis_6379.pid#pidfile /usr/local/redis/run/redis.pid#g" /usr/local/redis/etc/redis.conf
    sed -i "s/^# requirepass.*/requirepass ${REDISPWD}/g" /usr/local/redis/etc/redis.conf
    sed -i "s#logfile ""#logfile ${INSHOME}/wwwlogs/redis.log#g" /usr/local/redis/etc/redis.conf
    sed -i "s#dir ./#dir ${REDISHOME}/#g" /usr/local/redis/etc/redis.conf

    cat > /etc/rc.d/init.d/redis<<EOF
#! /bin/bash
#
# redis - this script starts and stops the redis-server daemon
#
# chkconfig:    2345 80 90
# description:  Redis is a persistent key-value database
#
### BEGIN INIT INFO
# Provides:          redis
# Required-Start:    \$syslog
# Required-Stop:     \$syslog
# Should-Start:        \$local_fs
# Should-Stop:        \$local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description:    redis-server daemon
# Description:        redis-server daemon
### END INIT INFO

REDISPORT=6379
BASEDIR=/usr/local/redis
REDIS_USER=redis
EXEC=/usr/local/redis/bin/redis-server
REDIS_CLI=/usr/local/redis/bin/redis-cli

PIDFILE=/usr/local/redis/run/redis.pid
CONF=/usr/local/redis/etc/redis.conf
DESC=Redis-Server

log_success_msg(){
    printf "%-58s \\033[32m[ %s ]\\033[0m\\n" "\$@"
}
log_failure_msg(){
    printf "%-58s \\033[31m[ %s ]\\033[0m\\n" "\$@"
}
log_warning_msg(){
    printf "%-58s \\033[33m[ %s ]\\033[0m\\n" "\$@"
}

redis_pid() {
    echo \`ps aux | grep \${REDISPORT} | grep -v grep | awk '{ print \$2 }'\`
}

start() {
    pid=\$(redis_pid)
    # if [ -f "\$PIDFILE" ]; then
    if [ -n "\$pid" ]; then
        log_warning_msg "Starting \$DESC: (pid: \$pid)" "Already Running"
    else
        /bin/su -m -c "cd \$BASEDIR/bin && \$EXEC \$CONF" \$REDIS_USER
        if [ \$? -eq 0 ]; then
            log_success_msg "Starting \$DESC: " "SUCCESS"
        else
            log_failure_msg "Starting \$DESC: " "Failed"
        fi
    fi
}

status() {
    pid=\$(redis_pid)
    # if [ -f "\$PIDFILE" ]; then
    if [ -n "\$pid" ]; then
        log_success_msg "\$DESC status: (pid: \$pid)" "Running"
    else
        log_warning_msg "\$DESC status: " "Stopped"
    fi
}

stop() {
    pid=\$(redis_pid)
    if [ -n "\$pid" ]; then
        \$REDIS_CLI -p \$REDISPORT -a ${REDISPWD} shutdown 2>/dev/null
        if [ \$? -eq 0 ]; then
            log_success_msg "Stopping \$DESC: " "SUCCESS"
        else
            log_failure_msg "Stopping \$DESC: " "Failed"
        fi
    else
        log_warning_msg "Stopping \$DESC: " "Not Running"
    fi
}

kill() {
    killall redis-server
    pid=\$(redis_pid)
    if [ -n "\$pid" ]; then
        log_failure_msg "Killing \$DESC: " "Failed"
    else
        log_success_msg "Killing \$DESC: " "SUCCESS"
    fi
}

case "\$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart|reload)
        stop
        sleep 2
        start
        ;;
    status)
        status
        ;;
    kill)
        kill
        ;;
  *)
    echo "Usage: /etc/init.d/redis {start|stop|restart|status|kill}"
esac

exit 0
EOF
    chgrp -R redis /usr/local/redis/.
    chmod +x /etc/init.d/redis
    chkconfig --add redis
    chkconfig redis on

    ln -sf /usr/local/redis/bin/redis-server /usr/local/bin/redis-server
    ln -sf /usr/local/redis/bin/redis-cli /usr/local/bin/redis-cli
}

install_java() {
    yum install -y java-11-openjdk.x86_64 java-11-openjdk-devel.x86_64
    export JAVA_HOME=/usr/lib/jvm/java-11-openjdk
    export JRE_HOME=/usr/lib/jvm/java-11-openjdk/jre

    MODULE_NAME="Tomcat"
    ins_begin
    wget_cache "https://archive.apache.org/dist/tomcat/tomcat-9/v${TOMCAT_VER}/bin/apache-tomcat-${TOMCAT_VER}.tar.gz" "apache-tomcat-${TOMCAT_VER}.tar.gz"
    tar zxvf apache-tomcat-${TOMCAT_VER}.tar.gz || return 255

    cd apache-tomcat-${TOMCAT_VER}/bin
    tar zxvf commons-daemon-native.tar.gz
    cd commons-daemon-1.1.0-native-src/unix
    ./configure
    make || make_result="fail"
    if [[ $make_result == "fail" ]]; then
        return 1
    fi
    mv jsvc ../../
    cd ../..
    rm -rf commons-daemon-1.1.0-native-src commons-daemon-native.tar.gz tomcat-native.tar.gz
    cd ../..
    mv apache-tomcat-${TOMCAT_VER} /usr/local/tomcat

    groupadd tomcat
    useradd -r -g tomcat -s /bin/false tomcat
    chmod -R 777 /usr/local/tomcat/logs
    chown -R tomcat:tomcat /usr/local/tomcat

    sed -i 's#<Connector port="8080" protocol="HTTP/1.1"#<Connector port="8080" protocol="org.apache.coyote.http11.Http11NioProtocol" maxThreads="1000" enableLookups="false"#g' /usr/local/tomcat/conf/server.xml
    sed -i 's#connectionTimeout="20000"#connectionTimeout="20000" minSpareThreads="100" acceptCount="900" disableUploadTimeout="true" maxKeepAliveRequests="15"#g' /usr/local/tomcat/conf/server.xml

    cat > /etc/init.d/tomcat<<EOF
#!/bin/bash
#
# tomcat     This shell script takes care of starting and stopping Tomcat
#
# chkconfig: - 80 20
#
### BEGIN INIT INFO
# Provides: tomcat
# Required-Start: \$network \$syslog
# Required-Stop: \$network \$syslog
# Default-Start:
# Default-Stop:
# Short-Description: start and stop tomcat
### END INIT INFO

export JAVA_OPTS="-Dfile.encoding=UTF-8 -Dnet.sf.ehcache.skipUpdateCheck=true -XX:+UseConcMarkSweepGC -XX:+CMSClassUnloadingEnabled -XX:+UseParNewGC -XX:MaxPermSize=128m -Xms512m -Xmx512m"
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk
export JRE_HOME=/usr/lib/jvm/java-11-openjdk/jre
PATH=$PATH:$JAVA_HOME/bin
CLASSPATH=.:$JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib/tools.jar
TOMCAT_USER=tomcat
TOMCAT_HOME=/usr/local/tomcat
CATALINA_HOME=/usr/local/tomcat
DESC=Tomcat

log_success_msg(){
    printf "%-58s \\033[32m[ %s ]\\033[0m\\n" "\$@"
}
log_failure_msg(){
    printf "%-58s \\033[31m[ %s ]\\033[0m\\n" "\$@"
}
log_warning_msg(){
    printf "%-58s \\033[33m[ %s ]\\033[0m\\n" "\$@"
}

tomcat_pid() {
    echo \`ps aux | grep org.apache.catalina.startup.Bootstrap | grep -v grep | awk '{ print \$2 }'\`
}

run() {
    pid=\$(tomcat_pid)
    if [ -n "\$pid" ]; then
        log_warning_msg "Running \$DESC: (pid: \$pid)" "Already Running"
    else
        \$TOMCAT_HOME/bin/daemon.sh run
        if [ \$? -eq 0 ]; then
            log_success_msg "Running \$DESC: " "SUCCESS"
        else
            log_failure_msg "Running \$DESC: " "Failed"
        fi
    fi
}

start() {
    pid=\$(tomcat_pid)
    if [ -n "\$pid" ]; then
        log_warning_msg "Starting \$DESC: (pid: \$pid)" "Already Running"
    else
        \$TOMCAT_HOME/bin/daemon.sh start
        if [ \$? -eq 0 ]; then
            log_success_msg "Starting \$DESC: " "SUCCESS"
        else
            log_failure_msg "Starting \$DESC: " "Failed"
        fi
    fi
}

status() {
    pid=\$(tomcat_pid)
    if [ -n "\$pid" ]; then
        log_success_msg "\$DESC status: (pid: \$pid)" "Running"
    else
        log_warning_msg "\$DESC status: " "Stopped"
    fi
}

stop() {
    pid=\$(tomcat_pid)
    if [ -n "\$pid" ]; then
        \$TOMCAT_HOME/bin/daemon.sh stop
        if [ \$? -eq 0 ]; then
            log_success_msg "Stopping \$DESC: " "SUCCESS"
        else
            log_failure_msg "Stopping \$DESC: " "Failed"
        fi
    else
        log_warning_msg "Stopping \$DESC: " "Not Running"
    fi
}

kill() {
    kill -9 \$(tomcat_pid)
    pid=\$(tomcat_pid)
    if [ -n "\$pid" ]; then
        log_failure_msg "Killing \$DESC: " "Failed"
    else
        log_success_msg "Killing \$DESC: " "SUCCESS"
    fi
}

case \$1 in
    run)
        run
        ;;
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart|reload)
        stop
        start
        ;;
    status)
        status
        ;;
    kill)
        kill
        ;;
    *)
        echo "Usage: \$0 {run|start|stop|kill|status|restart}"
    ;;
esac
exit 0
EOF
    chgrp -R tomcat /usr/local/tomcat/.
    chmod +x /etc/init.d/tomcat
    chkconfig --add tomcat
    chkconfig tomcat on

    MODULE_NAME="Java"
}

setting_sendmail_conf() {
    # 修改默认邮件传输代理：alternatives --config mta
    # 查看邮件传输代理是否修改成功：alternatives --display mta

    echo_yellow "请输入邮箱 smtp 信息:"
    read -r -p "smtp 地址: " SMTPHOST
    read -r -p "smtp 端口: " SMTPPORT
    read -r -p "smtp 用户名: " SMTPUSER
    echo_red "请注意：部分邮箱（如QQ邮箱/网易邮箱，以及开启了「安全登录」的腾讯企业邮箱）的 smtp 密码"
    echo_red "　　　　是邮箱管理设置中的「客户端授权密码」或「客户端专用密码」，不是网页版的登录密码！"
    read -r -p "smtp 密码: " SMTPPASS

    echo_yellow "请选择邮件发送程序: "
    echo_blue "1: 系统默认"
    echo_blue "2: msmtp(建议)"
    read -r -p "请输入对应数字(1 or 2):" MAILCONF
    yum -y remove postfix
    yum -y remove sendmail

    echo_yellow "是否安装 Mutt 发送邮件客户端? "
    read -r -p "是(Y)/否(N): " INSMUTT
    if [[ ${INSMUTT} == "y" || ${INSMUTT} == "Y" ]]; then
        yum install -y mutt
    fi

    case "${MAILCONF}" in
    1)
        echo '' >> /etc/mail.rc
        echo '# Set SMTP conf' >> /etc/mail.rc
        echo "set from=${SMTPUSER}" >> /etc/mail.rc
        echo "set smtp=smtps://${SMTPHOST}:${SMTPPORT}" >> /etc/mail.rc
        echo "set smtp-auth-user=${SMTPUSER}" >> /etc/mail.rc
        echo "set smtp-auth-password=${SMTPPASS}" >> /etc/mail.rc
        echo "set smtp-auth=login" >> /etc/mail.rc
        echo "set ssl-verify=ignore" >> /etc/mail.rc
        echo "set nss-config-dir=/etc/pki/nssdb" >> /etc/mail.rc

        mkdir -p /root/.certs/
        echo -n | openssl s_client -connect "${SMTPHOST}:${SMTPPORT}" | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ~/.certs/smtp.crt
        certutil -A -n "GeoTrust SSL CA" -t "C,," -d ~/.certs -i ~/.certs/smtp.crt
        certutil -A -n "GeoTrust Global CA" -t "C,," -d ~/.certs -i ~/.certs/smtp.crt
        certutil -L -d /root/.certs
        sed -i 's#/etc/pki/nssdb#/root/.certs#g' /etc/mail.rc

        if [[ ${INSMUTT} == "y" || ${INSMUTT} == "Y" ]]; then
            smtp_user=${SMTPUSER/@/\\@}
            cat >> /etc/Muttrc.local<<EOF
# Connection
set ssl_starttls=yes
set ssl_force_tls=yes
set ssl_use_sslv3=yes
set timeout=60
set smtp_authenticators="login"
set smtp_url="smtps://${smtp_user}@${SMTPHOST}:${SMTPPORT}"
#set content_type="text/html"

# Outgoing
#set realname="zhang san"
set from="${SMTPUSER}"
set smtp_pass="${SMTPPASS}"
EOF
        fi

        ;;
    *)
        yum install -y msmtp

cat > /etc/msmtprc<<EOF
defaults
logfile ${INSHOME}/wwwlogs/msmtp_sendmail.log

# You can select this account by using "-a gmail" in your command line.
account       acc1
tls           on
tls_certcheck off
tls_starttls  off
protocol      smtp
auth          login
host          ${SMTPHOST}
port          ${SMTPPORT}
from          ${SMTPUSER}
user          ${SMTPUSER}
password      ${SMTPPASS}

# If you don't use any "-a" parameter in your command line, the default account will be used.
account default: acc1
EOF

        chmod 0600 /etc/msmtprc
        echo '' >> /etc/mail.rc
        echo 'set sendmail=/usr/bin/msmtp' >> /etc/mail.rc

        if [[ ${INSMUTT} == "y" || ${INSMUTT} == "Y" ]]; then
            echo '' >> /etc/Muttrc.local
            echo 'set sendmail=/usr/bin/msmtp' >> /etc/Muttrc.local
        fi
        ;;
    esac
}

install_shellMonitor() {
    if [ -d /usr/local/shellMonitor ]; then
        echo_yellow "已存在 shellMonitor, 是否覆盖安装?"
        read -r -p "是(Y)/否(N): " REINSMONITOR
        if [[ ${REINSMONITOR} == "y" || ${REINSMONITOR} == "Y" ]]; then
            cp /usr/local/shellMonitor/config.sh ./shellMonitor.config.bak
            echo_blue "删除旧 shellMonitor..."
            rm -rf /usr/local/shellMonitor
            sed -i '/shellMonitor/d' /var/spool/cron/root
        else
            echo_blue "退出安装 shellMonitor!"
            return
        fi
    fi

    wget_cache "https://github.com/zsenliao/shellMonitor/archive/master.zip" "shellMonitor.zip" "shellMonitor"
    if ! unzip shellMonitor.zip; then
        echo "shellMonitor 源码包下载失败，退出当前安装！" >> /root/install-error.log
        return
    fi

    mv shellMonitor-master /usr/local/shellMonitor
    chmod +x /usr/local/shellMonitor/*.sh
    if [ -f ./shellMonitor.config.bak ]; then
        echo_blue "当前 shellMonitor 配置为:"
        cat ./shellMonitor.config.bak
    fi
    /usr/local/shellMonitor/main.sh init
    echo_green "[!] shellMonitor 安装成功!"
}

register_management-tool() {
    if [[ ${INSSTACK} == "auto" ]]; then
        MYNAME="pnmp"
    else
        echo_yellow "是否要自定义管理工具名称(如不需要，请直接回车)? "
        while :;do
            read -r -p "请输入管理工具名称: " MYNAME
            if [ -z "${MYNAME}" ]; then
                MYNAME="pnmp"
                break
            else
                command -v ${MYNAME} >/dev/null 2>&1
                if [ $? -eq 0 ]; then
                    echo_red "存在相同的命令，请重新输入!"
                else
                    break
                fi
            fi
        done
    fi
    wget https://raw.githubusercontent.com/zsenliao/initServer/master/pnmp -O /usr/local/bin/${MYNAME}
    sed -i "s|/data|${INSHOME}|g" /usr/local/bin/${MYNAME}
    chmod +x /usr/local/bin/${MYNAME}
}

upgrade_service() {
    echo_blue "升级 ${MODULE_NAME}..."

    get_module_ver
    if [ -n "${MODULE_VER}" ]; then
        echo_green "系统当前版本：${MODULE_VER}"
    else
        echo_green "系统当前未安装 ${MODULE_NAME}"
    fi
    echo_yellow "请输入您要升级的版本(请注意：只需要输入包括数字、小数点的版本号)"
    read -r -p "输入: " UPDATE_VER

    echo_green "${MODULE_NAME} 版本将由 ${MODULE_VER} 升级到 ${UPDATE_VER}"
    echo ""
    echo_yellow "请按任意键开始升级..."
    OLDCONFIG=$(stty -g)
    stty -icanon -echo min 1 time 0
    dd count=1 2>/dev/null
    stty "${OLDCONFIG}"
}

clean_install_files() {
    if [[ ${INSSTACK} != "auto" ]]; then
        echo_yellow "是否清理安装文件?"
        read -r -p "全部(A)是(Y)/否(N): " CLRANINS
    else
        CLRANINS="Y"
    fi
    if [[ ${CLRANINS} == "y" || ${CLRANINS} == "Y" ]]; then
        echo_blue "正在清理安装编译文件..."
        for deldir in "${CUR_DIR}"/src/*
        do
            if [ -d "${deldir}" ]; then
                echo "正在删除 ${deldir}"
                rm -rf "${deldir}"
            fi
        done
        echo_blue "安装编译文件清理完成。"
    elif [[ ${CLRANINS} == "a" || ${CLRANINS} == "A" ]]; then
        echo_blue "正在清理全部文件..."
        rm -rf "${CUR_DIR}"/src
        echo_blue "安装文件清理完成。"
    fi

    ENDTIME=$(date +%s)
    echo_blue "总共用时 $(((ENDTIME-STARTTIME)/60)) 分"
}

clean_install() {
    clean_install_files

    echo_green "服务器环境安装配置成功！"
    echo_blue "环境管理命令：${MYNAME}"
    echo_blue "可以通过 ${MYNAME} vhost add 来添加网站"
    echo " "
    echo_blue "网站程序目录：${INSHOME}/wwwroot"
    echo_blue "网站日志目录：${INSHOME}/wwwlogs"
    echo_blue "配置文件目录：${INSHOME}/wwwconf"
    echo_blue "MySQL 数据库目录：${MYSQLHOME}"
    echo_blue "Redis 数据库目录：${REDISHOME}"
    echo " "
    echo_blue "MySQL ROOT 密码：${DBROOTPWD}"
    echo_blue "Redis 安全密码：${REDISPWD}"
    echo_red "请牢记以上密码！"
    echo " "
    echo_blue "防火墙信息："
    firewall-cmd --list-all

    ${MYNAME} status
    if [ -s /bin/ss ]; then
        ss -ntl
    else
        netstat -ntl
    fi

    if [ -x /usr/local/bin/nginx ]; then
        if [[ ${INSSTACK} != "auto" ]]; then
            echo_yellow "是否要添加默认站点? "
            read -r -p "是(Y)/否(N): " ADDHOST
            if [[ ${ADDHOST} == "y" || ${ADDHOST} == "Y" ]]; then
                ${MYNAME} restart
                ${MYNAME} vhost add
            fi
        fi
    fi
}

OSNAME=$(cat /etc/*-release | grep -i ^name | awk 'BEGIN{FS="=\""} {print $2}' | awk '{print $1}')
if [[ ${OSNAME} != "CentOS" ]]; then
    echo_red "此脚本仅适用于 CentOS 系统！"
    exit 1
fi

if [[ $(id -u) != "0" ]]; then
    echo_red "错误提示: 请在 root 账户下运行此脚本!"
    exit 1
fi

if disk2=$(fdisk -l | grep vdb 2>/dev/null); then
    if ! df -h | grep vdb 2>/dev/null; then
        echo_red "监测到服务器有未挂载磁盘，$(echo $disk2 | awk '{print $1$2$3}')"
        if [[ ${INSSTACK} != "auto" ]]; then
            read -r -p "是否继续安装(按 q 回车退出安装)? " EXITINSTALL
            if [[ ${EXITINSTALL} == "q" || ${EXITINSTALL} == "Q" ]]; then
                exit 0
            fi
        fi
    fi
fi

mkdir -p "${CUR_DIR}/src"
cd "${CUR_DIR}/src" || exit

yum -y update
yum -y upgrade

if ! grep /usr/local/bin ~/.bashrc 1>/dev/null; then
    echo "export PATH=/usr/local/bin:\$PATH" >> ~/.bashrc
fi
if ! grep vim ~/.bashrc 1>/dev/null; then
    echo "alias vi=\"vim\"" >> ~/.bashrc
fi
cat >> ~/.bashrc << EOF

#export HISTCONTROL=erasedups  # 忽略全部重复命令的历史记录，默认是 ignoredups 忽略连续重复的
export HISTIGNORE="pwd:ls:ll:l:"
export EDITOR=/usr/bin/local/vim

alias ll="ls -alhF"
alias la="ls -A"
alias l="ls -CF"
alias lbys="ls -alhS"
alias lbyt="ls -alht"
alias cls="clear"
alias grep="grep --color"

if [[ $- == *i* ]]; then
    bind '"\e[A": history-search-backward'
    bind '"\e[B": history-search-forward'
fi
EOF
echo 'export PS1="\[\\033[1;34m\]#\[\\033[m\] \[\\033[36m\]\\u\[\\033[m\]@\[\\033[32m\]\h:\[\\033[33;1m\]\w\[\\033[m\] [bash-\\t] \`errcode=\$?; if [ \$errcode -gt 0 ]; then echo C:\[\\e[31m\]\$errcode\[\\e[0m\]; fi\` \\n\[\\e[31m\]\$\[\\e[0m\] "' >> /etc/profile


if [[ ${INSSTACK} == "upgrade" ]]; then
    echo_yellow "请选择要更新的服务?"
    echo_blue "0 CMake"
    echo_blue "1 Git"
    echo_blue "2 Vim"
    echo_blue "3 Python3"
    echo_blue "4 Redis"
    echo_blue "5 PHP"
    echo_blue "6 MySQL"
    echo_blue "7 NodeJS"
    echo_blue "8 Nginx"
    echo_blue "9 Tomcat"
    read -r -p "请选择数字: " UPDATE

    case "${UPDATE}" in
        0)
            MODULE_NAME="CMake"
            ;;
        1)
            MODULE_NAME="Git"
            ;;
        2)
            MODULE_NAME="Vim"
            ;;
        3)
            MODULE_NAME="Python3"
            ;;
        4)
            MODULE_NAME="Redis"
            ;;
        5)
            MODULE_NAME="PHP"
            ;;
        6)
            MODULE_NAME="MySQL"
            ;;
        7)
            MODULE_NAME="NodeJS"
            ;;
        8)
            MODULE_NAME="Nginx"
            ;;
        9)
            MODULE_NAME="Tomcat"
            ;;
        *)
            echo_red "所选服务错误，退出升级系统！"
            exit 1
            ;;
    esac
    upgrade_service
    echo_green "测试功能，暂未实现！"

    exit 0
fi


if [[ ${MemTotal} -lt 1024 ]]; then
    echo_blue "内存过低，创建 SWAP 交换区..."
    dd if=/dev/zero of=/swapfile bs=1M count=2048  # 获取要增加的2G的SWAP文件块
    chmod 0600 /swapfile
    mkswap /swapfile  # 创建SWAP文件
    swapon /swapfile  # 激活SWAP文件
    swapon -s  # 查看SWAP信息是否正确
    # echo "/swapfile swap swap defaults 0 0" >> /etc/fstab  # 添加到fstab文件中让系统引导时自动启动
fi

echo_blue "========= 基本信息 ========="
get_server_ip
MEMINFO=$(free -h | grep Mem)
echo_info "服务器IP/名称" "${HOSTIP} / $(uname -n)"
echo_info "内存大小/空闲" "$(echo $MEMINFO|awk '{print $2}') / $(echo $MEMINFO|awk '{print $4}')"
echo_info "硬件平台/处理器类型/内核版本" "$(uname -i)($(uname -m)) / $(uname -p) / $(uname -r)"
echo_info "CPU 型号(物理/逻辑/每个核数)" "$(grep 'model name' /proc/cpuinfo|uniq|awk -F : '{print $2}'|sed 's/^[ \t]*//g'|sed 's/ \+/ /g') ($(grep 'physical id' /proc/cpuinfo|sort|uniq|wc -l) / ${CPUS} / $(grep 'cpu cores' /proc/cpuinfo|uniq|awk '{print $4}'))"
echo_info "服务器时间" "$(date '+%Y年%m月%d日 %H:%M:%S')"
echo_info "防火墙状态" "$(firewall-cmd --stat)"
echo ""
echo_blue "========= 硬盘信息 ========="
df -h
echo ""
echo_blue "========= 系统安装 ========="

if [[ ${INSSTACK} != "auto" ]]; then
    echo_yellow "请输入安装目录（比如 /home 或 /data），默认 /data"
    read -r -p "请输入: " INSHOME
fi
if [ -z "${INSHOME}" ]; then
    INSHOME=/data
fi
echo_blue "系统安装目录：${INSHOME}"
mkdir -p ${INSHOME}

systemctl start firewalld
disable_selinux
check_hosts

yum install -y wget gcc make curl unzip

if [[ ${INSSTACK} != "auto" ]]; then
    echo_yellow "是否调整时区?"
    read -r -p "是(Y)/否(N): " SETTIMEZONE
fi
if [[ ${SETTIMEZONE} == "y" || ${SETTIMEZONE} == "Y" ]]; then
    set_time_zone
fi

if [[ ${INSSTACK} != "auto" ]]; then
    echo_yellow "是否修改 HostName?"
    read -r -p "是(Y)/否(N): " SETHOST
else
    SETHOST="Y"
fi
if [[ ${SETHOST} == "y" || ${SETHOST} == "Y" ]]; then
    set_host_name
fi

if [[ ${INSSTACK} != "auto" ]]; then
    echo_yellow "是否添加用户?"
    read -r -p "是(Y)/否(N): " ADDUSER
fi
if [[ ${ADDUSER} == "y" || ${ADDUSER} == "Y" ]]; then
    add_user
fi

if [[ ${INSSTACK} != "auto" ]]; then
    echo_yellow "是否修改 SSH 配置?"
    read -r -p "是(Y)/否(N): " SETSSH
fi
if [[ ${SETSSH} == "y" || ${SETSSH} == "Y" ]]; then
    ssh_setting
fi


for module in "ZSH" "Htop" "Git" "Vim" "CMake" "MySQL" "Redis" "Python3"  "PHP" "NodeJS" "Nginx" "Java"; do
    MODULE_NAME=${module}
    if [[ ${INSSTACK} != "auto" ]]; then
        show_ver
        read -r -p "是(Y)/否(N): " INPUT_RESULT
    else
        INPUT_RESULT="Y"
    fi
    if [[ ${INPUT_RESULT} == "y" || ${INPUT_RESULT} == "Y" ]]; then
        ins_begin
        make_result=""
        func_name=$(echo $module | tr '[:upper:]' '[:lower:]')
        install_${func_name}
        ins_result=$?
        if [[ $ins_result == 255 ]]; then
            echo "${MODULE_NAME} 源码包下载失败，退出当前安装！" >> /root/install-error.log
        elif [[ $ins_result == 1 ]]; then
            echo "${MODULE_NAME} 源码编译不成功，安装失败！" >> /root/install-error.log
        fi
        ins_end
        if [[ $ins_result == 0 ]]; then
            if [[ $module == "Python3" ]]; then
                echo_green "\tpip版本：$(pip3 --version)"
                echo_green "\tuWsgi版本：$(uwsgi --version)"
            elif [[ $module == "NodeJS" ]]; then
                echo_green "\tnpm版本：$(npm --version)"
            elif [[ $module == "Java" ]]; then
                echo_green "\tTomcat版本：$(/usr/local/tomcat/bin/version.sh|grep 'Server version')"
            fi
        fi
    fi
done


if [[ ${INSSTACK} != "auto" ]]; then
    echo_yellow "是否设置 SMTP 发送邮件?"
    echo_blue "提示：阿里云/腾讯云服务器封掉了 25 端口，默认方式发送邮件不成功(可以申请解封)"
    read -r -p "是(Y)/否(N): " SETSMTP
fi
if [[ ${SETSMTP} == "y" || ${SETSMTP} == "y" ]]; then
    setting_sendmail_conf
fi

if [[ ${INSSTACK} != "auto" ]]; then
    echo_yellow "是否安装 shellMonitor 系统监控工具?"
    read -r -p "是(Y)/否(N): " INSMONITOR
fi
if [[ ${INSMONITOR} == "y" || ${INSMONITOR} == "y" ]]; then
    install_shellMonitor
fi

if [[ ${INSSTACK} != "auto" ]]; then
    echo_yellow "是否启用防火墙(默认启用)?"
    read -r -p "是(Y)/否(N): " FIREWALL
else
    FIREWALL="Y"
fi
if [[ ${FIREWALL} == "y" || ${FIREWALL} == "Y" ]]; then
    systemctl enable firewalld
else
    systemctl stop firewalld
    systemctl disable firewalld
fi

register_management-tool
clean_install
