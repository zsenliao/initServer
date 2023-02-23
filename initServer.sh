#!/bin/bash
PATH=/usr/local/bin:/usr/local/sbin:/bin:/sbin:/usr/bin:/usr/sbin:~/bin
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

CMAKE_VER=3.25.2
PYTHON3_VER=3.11.2
NODEJS_VER=v16.14.2
STARTSTOPDAEMON_VER=1.21.7
NGINX_VER=1.23.3
PHP_VER=8.2.2
PHP_MCRYPT_VER=1.0.5
PHP_IMAGICK_VER=3.7.0
PHP_REDIS_VER=5.3.7
REDIS_VER=7.0.8  # 6.2.10
MYSQL_VER=8.0.32
MONGOD_VER=6.0
TOMCAT_VER=9.0.30
HTOP_VER=3.2.2
LIBZIP_VER=1.9.2
OPENSSL_VER=1.1.1t
GIT_VER=2.39.2
PERL_VER=5.34.1
VIM_VER=9.0.1341
WKHTMLTOX_VER=0.12.6-1

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

    # 解决无法从 github.com 拉取文件导致安装失败的问题
    if [ -f ${CUR_DIR}/src/hosts ]; then
        cat ${CUR_DIR}/src/hosts >> /etc/hosts
    elif [ wget https://raw.githubusercontent.com/521xueweihan/GitHub520/main/hosts -O hosts ]; then
        cat ${CUR_DIR}/src/hosts >> /etc/hosts
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
        # command -v nginx 1>/dev/null && MODULE_VER=$(cat /usr/local/nginx/version.txt 2>/dev/null || echo "0.1.0") || MODULE_VER=""
        MODULE_VER=$(nginx -V 2>/dev/null)
    elif [[ $MODULE_CLI == "vim" ]]; then
        MODULE_VER=$(echo $(vim --version 2>/dev/null) | awk -F ')' '{print $1}')
    elif [[ $MODULE_CLI == "redis" ]]; then
        MODULE_VER=$(redis-server --version 2>/dev/null)
    elif [[ $MODULE_CLI == "nodejs" ]]; then
        MODULE_VER=$(node --version 2>/dev/null)
    elif [[ $MODULE_CLI == "openssl" ]]; then
        MODULE_VER=$(openssl version 2>/dev/null)
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
    echo ""
    echo_blue "=========================================================="
    echo ""
    get_module_ver

    MODULE_INS_VER=$(echo ${MODULE_NAME}_VER | tr '[:lower:]' '[:upper:]')
    if [ -n "${MODULE_VER}" ]; then
        echo_green "当前已安装 ${MODULE_NAME}, 版本：${MODULE_VER}"
        echo_yellow "是否重新编译安装(版本: ${!MODULE_INS_VER})?"
    else
        echo_yellow "是否安装 ${MODULE_NAME}(版本: ${!MODULE_INS_VER})?"
    fi
}

wget_cache() {
    cd "${CUR_DIR}/src"

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

setting_timezone() {
    echo_blue "设置时区..."
    rm -rf /etc/localtime
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
}

setting_hostname() {
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

setting_ssh() {
    echo_blue "[+] 修改 SSH 配置..."
    \cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

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

        \cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
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
export EDITOR=/usr/local/bin/vim

export CLICOLOR=1
alias ll="ls -alhF"
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
        \cp ~/.zshrc /home/${USERNAME}/
        chown ${USERNAME}:${USERNAME} /home/${USERNAME}/
    fi
}

install_vim() {
    wget_cache "https://github.com/vim/vim/archive/refs/tags/v${VIM_VER}.tar.gz" "vim-${VIM_VER}.tar.gz"
    tar zxf "vim-${VIM_VER}.tar.gz" || return 255

    yum uninstall -y vim
    yum remove -y vim

    cd "vim-${VIM_VER}/src"
    make -j && make install || make_result="fail"
    if [[ $make_result == "fail" ]]; then
        return 1
    fi

    echo_blue "[+] 安装 vim 插件..."
    cat > ~/.vimrc<<EOF
" leader
let mapleader = ','
let g:mapleader = ','

" syntax
syntax on

" history : how many lines of history VIM has to remember
set history=2000

" filetype
filetype on
" Enable filetype plugins
filetype plugin on
filetype indent on

" base
set nocompatible                " don't bother with vi compatibility
set autoread                    " reload files when changed on disk, i.e. via `git checkout`
set shortmess=atI

set magic                       " For regular expressions turn magic on
set title                       " change the terminal's title
set nobackup                    " do not keep a backup file

set novisualbell                " turn off visual bell
set noerrorbells                " don't beep
set visualbell t_vb=            " turn off error beep/flash
set t_vb=
set tm=500

" show location
set cursorcolumn
set cursorline

" movement
set scrolloff=7                 " keep 3 lines when scrolling

" show
set ruler                       " show the current row and column
set number                      " show line numbers
set nowrap
set showcmd                     " display incomplete commands
set showmode                    " display current modes
set showmatch                   " jump to matches when entering parentheses
set matchtime=2                 " tenths of a second to show the matching parenthesis

" search
set hlsearch                    " highlight searches
set incsearch                   " do incremental searching, search as you type
set ignorecase                  " ignore case when searching
set smartcase                   " no ignorecase if Uppercase char present

" tab
set expandtab                   " expand tabs to spaces
set smarttab
set shiftround

" indent
set autoindent smartindent shiftround
set shiftwidth=4
set tabstop=4
set softtabstop=4                " insert mode tab and backspace use 4 spaces

" NOT SUPPORT
" fold
set foldenable
set foldmethod=indent
set foldlevel=99
let g:FoldMethod = 0
map <leader>zz :call ToggleFold()<cr>
fun! ToggleFold()
    if g:FoldMethod == 0
        exe "normal! zM"
        let g:FoldMethod = 1
    else
        exe "normal! zR"
        let g:FoldMethod = 0
    endif
endfun

" encoding
set encoding=utf-8
set fileencodings=ucs-bom,utf-8,cp936,gb18030,big5,euc-jp,euc-kr,latin1
set termencoding=utf-8
set ffs=unix,dos,mac
set formatoptions+=m
set formatoptions+=B

" select & complete
set selection=inclusive
set selectmode=mouse,key

set completeopt=longest,menu
set wildmenu                           " show a navigable menu for tab completion"
set wildmode=longest,list,full
set wildignore=*.o,*~,*.pyc,*.class

" others
set backspace=indent,eol,start  " make that backspace key work the way it should
set whichwrap+=<,>,h,l

" if this not work ,make sure .viminfo is writable for you
if has("autocmd")
  au BufReadPost * if line("'\"") > 1 && line("'\"") <= line("$") | exe "normal! g'\"" | endif
endif

" NOT SUPPORT
" Enable basic mouse behavior such as resizing buffers.
" set mouse=a


" ============================ theme and status line ============================

" theme
set background=dark
colorscheme desert

" set mark column color
hi! link SignColumn   LineNr
hi! link ShowMarksHLl DiffAdd
hi! link ShowMarksHLu DiffChange

" status line
set statusline=%<%f\ %h%m%r%=%k[%{(&fenc==\"\")?&enc:&fenc}%{(&bomb?\",BOM\":\"\")}]\ %-14.(%l,%c%V%)\ %P
set laststatus=2   " Always show the status line - use 2 lines for the status bar


" ============================ specific file type ===========================

autocmd FileType python set tabstop=4 shiftwidth=4 expandtab ai
autocmd FileType ruby set tabstop=2 shiftwidth=2 softtabstop=2 expandtab ai
autocmd BufRead,BufNew *.md,*.mkd,*.markdown  set filetype=markdown.mkd

autocmd BufNewFile *.sh,*.py exec ":call AutoSetFileHead()"
function! AutoSetFileHead()
    " .sh
    if &filetype == 'sh'
        call setline(1, "\#!/bin/bash")
    endif

    " python
    if &filetype == 'python'
        call setline(1, "\#!/usr/bin/env python")
        call append(1, "\# encoding: utf-8")
    endif

    normal G
    normal o
    normal o
endfunc

autocmd FileType c,cpp,java,go,php,javascript,puppet,python,rust,twig,xml,yml,perl autocmd BufWritePre <buffer> :call <SID>StripTrailingWhitespaces()
fun! <SID>StripTrailingWhitespaces()
    let l = line(".")
    let c = col(".")
    %s/\s\+$//e
    call cursor(l, c)
endfun

" ============================ key map ============================

nnoremap k gk
nnoremap gk k
nnoremap j gj
nnoremap gj j

map <C-j> <C-W>j
map <C-k> <C-W>k
map <C-h> <C-W>h
map <C-l> <C-W>l

nnoremap <F2> :set nu! nu?<CR>
nnoremap <F3> :set list! list?<CR>
nnoremap <F4> :set wrap! wrap?<CR>
set pastetoggle=<F5>            "    when in insert mode, press <F5> to go to
                                "    paste mode, where you can paste mass data
                                "    that won't be autoindented
au InsertLeave * set nopaste
nnoremap <F6> :exec exists('syntax_on') ? 'syn off' : 'syn on'<CR>

" kj 替换 Esc
inoremap kj <Esc>

" Quickly close the current window
nnoremap <leader>q :q<CR>
" Quickly save the current file
nnoremap <leader>w :w<CR>

" select all
map <Leader>sa ggVG"

" remap U to <C-r> for easier redo
nnoremap U <C-r>

" Swap implementations of ` and ' jump to markers
" By default, ' jumps to the marked line, ` jumps to the marked line and
" column, so swap them
nnoremap ' `
nnoremap ` '

" switch # *
" nnoremap # *
" nnoremap * #

"Keep search pattern at the center of the screen."
nnoremap <silent> n nzz
nnoremap <silent> N Nzz
nnoremap <silent> * *zz
nnoremap <silent> # #zz
nnoremap <silent> g* g*zz

" remove highlight
noremap <silent><leader>/ :nohls<CR>

"Reselect visual block after indent/outdent.调整缩进后自动选中，方便再次操作
vnoremap < <gv
vnoremap > >gv

" y$ -> Y Make Y behave like other capitals
map Y y$

"Map ; to : and save a million keystrokes
" ex mode commands made easy 用于快速进入命令行
nnoremap ; :

" Shift+H goto head of the line, Shift+L goto end of the line
nnoremap H ^
nnoremap L $

" save
cmap w!! w !sudo tee >/dev/null %

" command mode, ctrl-a to head, ctrl-e to tail
cnoremap <C-j> <t_kd>
cnoremap <C-k> <t_ku>
cnoremap <C-a> <Home>
cnoremap <C-e> <End>
EOF

    mkdir -p ~/.vim/syntax

    wget -O ~/.vim/syntax/nginx.vim "http://www.vim.org/scripts/download_script.php?src_id=19394"
    echo "au BufRead,BufNewFile ${INSHOME}/wwwconf/nginx/*,/usr/local/nginx/conf/* if &ft == '' | setfiletype nginx | endif " >> ~/.vim/filetype.vim

    wget -O ini.vim.zip "https://www.vim.org/scripts/download_script.php?src_id=10629"
    unzip ini.vim.zip && mv vim-ini-*/ini.vim ~/.vim/syntax/ini.vim
    rm -rf vim-ini-* ini.vim.zip
    echo "au BufNewFile,BufRead *.ini,*/.hgrc,*/.hg/hgrc setf ini" >> ~/.vim/filetype.vim

    wget -O php.vim.tar.gz "https://www.vim.org/scripts/download_script.php?src_id=8651"
    tar zxf php.vim.tar.gz && mv syntax/php.vim ~/.vim/syntax/php.vim
    rm -rf syntax php.vim.tar.gz
    echo "au BufNewFile,BufRead *.php setf php" >> ~/.vim/filetype.vim

    wget -O ~/.vim/syntax/python.wim "https://www.vim.org/scripts/download_script.php?src_id=21056"
    echo "au BufNewFile,BufRead *.py setf python" >> ~/.vim/filetype.vim

    if [[ "${USERNAME}" != "" ]]; then
        \cp ~/.vimrc /home/${USERNAME}/
        \cp -r ~/.vim /home/${USERNAME}/
        chown ${USERNAME}:${USERNAME} /home/${USERNAME}/
    fi
}

install_htop() {
    wget_cache "https://github.com/htop-dev/htop/releases/download/${HTOP_VER}/htop-${HTOP_VER}.tar.xz" "htop-${HTOP_VER}.tar.xz"
    tar -xvf htop-${HTOP_VER}.tar.xz || return 255
    cd htop-${HTOP_VER}
    ./configure
    make && make install
}

install_git() {
    yum install -y autoconf cpio expat-devel gettext-devel perl-ExtUtils-MakeMaker

    wget_cache "https://github.com/git/git/archive/refs/tags/v${GIT_VER}.tar.gz" "git-${GIT_VER}.tar.gz"
    tar xzf git-${GIT_VER}.tar.gz || return 255

    cd git-${GIT_VER}
    make configure && ./configure --prefix=/usr/local
    make -j ${CPUS} && make install || make_result="fail"
    if [[ $make_result == "fail" ]]; then
        return 1
    fi
}

install_ikev2() {
    echo_blue "[+] 安装 one-key-ikev2..."
    install_acme

    mkdir ikev2
    cd ikev2
    wget -c "https://raw.githubusercontent.com/quericy/one-key-ikev2-vpn/master/one-key-ikev2.sh"
    chmod +x one-key-ikev2.sh
    bash one-key-ikev2.sh
    cd ..
}  # TODO

install_cmake() {
    wget_cache "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VER}/cmake-${CMAKE_VER}.tar.gz" "cmake-${CMAKE_VER}.tar.gz"
    tar zxf cmake-${CMAKE_VER}.tar.gz || return 255

    rpm -q cmake
    yum remove -y cmake

    cd cmake-${CMAKE_VER}
    ./bootstrap
    make -j ${CPUS} && make install || make_result="fail"
    if [[ $make_result == "fail" ]]; then
        return 1
    fi
}

install_acme() {
    if [ -f "/root/.acme.sh/acme.sh.env" ]; then
        echo_green "acme.sh 已安装，当前版本：$(/root/.acme.sh/acme.sh --version)"
        echo_blue "更新版本..."
        /root/.acme.sh/acme.sh --upgrade
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
    ln -sf /usr/local/python3/bin/uwsgi /usr/local/bin/uwsgi

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
DAEMON=/usr/local/python3/bin/uwsgi
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
}

install_python3() {
    yum install -y epel-release bzip2-devel gdbm-devel libffi-devel

    wget_cache "https://www.python.org/ftp/python/${PYTHON3_VER}/Python-${PYTHON3_VER}.tgz" "Python-${PYTHON3_VER}.tgz"
    tar xf Python-${PYTHON3_VER}.tgz || return 255

    cd Python-${PYTHON3_VER}
    ./configure --prefix=/usr/local/python3 --with-openssl=/usr/local/openssl
    make -j ${CPUS} && make install || make_result="fail"
    if [[ $make_result == "fail" ]]; then
        return 1
    fi

    ln -sf /usr/local/python3/bin/python3 /usr/local/bin/python3
    ln -sf /usr/local/python3/bin/python3-config /usr/local/bin/python3-config

    curl https://bootstrap.pypa.io/get-pip.py | python3
    ln -sf /usr/local/python3/bin/pip3 /usr/local/bin/pip3
    if [[ ${CHANGEYUM} == "Y" || ${CHANGEYUM} == "Y" ]]; then
        python3 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple --upgrade pip
        pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
    else
        pip3 install --upgrade pip
    fi
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
    rpm -qa | grep mysql
    rpm -e mysql mysql-libs --nodeps
    yum remove -y mysql-server mysql mysql-libs
    yum install -y libaio numactl-libs
    yum install -y devtoolset-9-gcc devtoolset-9-gcc-c++ devtoolset-9-binutils
    source /opt/rh/devtoolset-9/enable
    gcc -v

    echo_yellow "选择安装方式(输入数字): "
    read -r -p "(1)二进制文件/(2)rpm包/(3)编译安装: " MYSQL_INSTALL_TYPE
    if [[ ${MYSQL_INSTALL_TYPE} == "1" ]]; then
        wget_cache "https://dev.mysql.com/get/Downloads/MySQL-8.0/mysql-${MYSQL_VER}-linux-glibc2.17-x86_64-minimal.tar.xz" "mysql-${MYSQL_VER}-linux-glibc2.17-x86_64-minimal.tar.xz"
        tar xf mysql-${MYSQL_VER}-linux-glibc2.17-x86_64-minimal.tar.xz
        \cp -r mysql-${MYSQL_VER}-linux-glibc2.17-x86_64-minimal /usr/local/mysql
        # mkdir /usr/local/mysql && tar xf mysql-${MYSQL_VER}.tar.xz -C /usr/local/mysql --strip-components 1
    elif [[ ${MYSQL_INSTALL_TYPE} == "2" ]]; then
        wget https://dev.mysql.com/get/mysql80-community-release-el7-7.noarch.rpm
        yum localinstall mysql80-community-release-el7-7.noarch.rpm
        yum clean all && yum makecache
        yum -y install mysql-community-server
        echo_yellow "记住默认密码，并按以下提示操作:"
        grep password /var/log/mysqld.log
        mysql_secure_installation
    else
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

        wget_cache "https://dev.mysql.com/get/Downloads/MySQL-8.0/mysql-boost-${MYSQL_VER}.tar.gz" "mysql-boost-${MYSQL_VER}.tar.gz"
        tar zxf mysql-boost-${MYSQL_VER}.tar.gz || return 255

        cd mysql-${MYSQL_VER}
        cmake . -DCMAKE_INSTALL_PREFIX=/usr/local/mysql \
                -DDOWNLOAD_BOOST=0 \
                -DWITH_BOOST=./boost \
                -DFORCE_INSOURCE_BUILD=1 \
                -DDEFAULT_CHARSET=utf8mb4 \
                -DDEFAULT_COLLATION=utf8mb4_general_ci

        make -j ${CPUS} && make install || make_result="fail"
        if [[ $make_result == "fail" ]]; then
            return 1
        fi
    fi

    MYSQLHOME=${INSHOME}/database/mysql
    rm -rf ${MYSQLHOME}
    rm -rf /usr/local/mysql
    rm -f /etc/my.cnf
    mkdir -p ${MYSQLHOME}

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

character-set-server = utf8mb4
collation-server = utf8mb4_general_ci  # 不区分大小写
# collation-server =  utf8mb4_bin  # 区分大小写
# collation-server = utf8mb4_unicode_ci  # 比 utf8mb4_general_ci 更准确

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

    if [[ ${MYSQL_INSTALL_TYPE} != "2" ]]; then
        if [[ ${INSSTACK} != "auto" ]]; then
            echo_yellow "请输入 MySQL ROOT 用户密码（直接回车将自动生成密码）"
            read -r -p "密码: " DBROOTPWD
        fi
        if [[ ${DBROOTPWD} == "" ]]; then
            echo_red "没有输入密码，将采用默认密码。"
            DBROOTPWD="zsen@Club#$RANDOM"
        fi
        echo_green "MySQL ROOT 用户密码(请记下来): ${DBROOTPWD}"

        groupadd mysql
        useradd -r -g mysql -s /bin/false mysql
        chgrp -R mysql /usr/local/mysql/.

        \cp /usr/local/mysql/support-files/mysql.server /etc/init.d/mysqld
        # sed -i 's/^\(basedir=\)$/\1\/usr\/local\/mysql/' /etc/init.d/mysqld
        # sed -i 's/^\(datadir=\)$/\1\${MYSQLHOME}/' /etc/init.d/mysqld
        chmod +x /etc/init.d/mysqld
        chkconfig --add mysqld
        chkconfig mysqld on  # 设置开机启动

        echo "/usr/local/mysql/lib" >> /etc/ld.so.conf.d/local.conf
        ldconfig

        # ln -sf /usr/local/mysql/lib/mysql /usr/lib/mysql
        ln -sf /usr/local/mysql/include/mysql /usr/include/mysql
        ln -sf /usr/local/mysql/bin/mysql /usr/local/bin/mysql
        ln -sf /usr/local/mysql/bin/mysqladmin /usr/local/bin/mysqladmin
        ln -sf /usr/local/mysql/bin/mysqldump /usr/local/bin/mysqldump
        ln -sf /usr/local/mysql/bin/myisamchk /usr/local/bin/myisamchk
        ln -sf /usr/local/mysql/bin/mysqld_safe /usr/local/bin/mysqld_safe
        ln -sf /usr/local/mysql/bin/mysqlcheck /usr/local/bin/mysqlcheck
        ln -sf /usr/local/mysql/bin/mysqld /user/local/bin/mysqld

        /usr/local/mysql/bin/mysqld --initialize-insecure --basedir=/usr/local/mysql --datadir=${MYSQLHOME} --user=mysql
        # --initialize 会生成一个随机密码(~/.mysql_secret)，--initialize-insecure 不会生成密码

        /etc/init.d/mysqld start
    fi

    if [ -d "/proc/vz" ]; then
        ulimit -s unlimited
    fi

    chown -R mysql:mysql ${MYSQLHOME}
    # 设置数据库密码
    mysqladmin -u root password "${DBROOTPWD}"
    # mysql -e "grant all privileges on *.* to root@'127.0.0.1' identified by \"${DBROOTPWD}\" with grant option;"
    # mysql -e "grant all privileges on *.* to root@'localhost' identified by \"${DBROOTPWD}\" with grant option;"
    # mysql -e "SET PASSWORD FOR 'root'@'localhost' = PASSWORD('${DBROOTPWD}');"
    # mysql -e "UPDATE mysql.user SET authentication_string=PASSWORD('${DBROOTPWD}') WHERE User='root';"
    mysql -e "FLUSH PRIVILEGES;" -uroot -p${DBROOTPWD}

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

install_perl() {
    wget_cache "https://www.cpan.org/src/5.0/perl-${PERL_VER}.tar.gz" "perl-${PERL_VER}.tar.gz"
    tar -zxf perl-${PERL_VER}.tar.gz
    cd perl-${PERL_VER}
    ./Configure -des -Dprefix=/usr/local/perl
    make && make install
    ln -sf /usr/local/perl/bin/perl /usr/local/bin/perl
}

install_start-stop-daemon() {
    ins_begin "start-stop-daemon"

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

    ins_end "start-stop-daemon"
}

install_openssl() {
    wget_cache "https://www.openssl.org/source/openssl-${OPENSSL_VER}.tar.gz" "openssl-${OPENSSL_VER}.tar.gz" "OpenSSL"
    tar xzf openssl-${OPENSSL_VER}.tar.gz || return 255
    # mv openssl-${OPENSSL_VER} /usr/local/openssl
    cd openssl-${OPENSSL_VER}
    ./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl shared zlib enable-tls1_3 '-Wl,-rpath,$(LIBRPATH)'
    make && make install
    echo "/usr/local/openssl/lib" >> /etc/ld.so.conf.d/local.conf
    ldconfig -v
    ln -sf /usr/local/openssl/bin/openssl /usr/local/bin/openssl
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
    fi

    if [ ! -d "${CUR_DIR}/src/ngx_brotli" ]; then
        git clone https://github.com/google/ngx_brotli.git || return 255
        cd ngx_brotli
        git submodule update --init
    else
        cd ${CUR_DIR}/src/ngx_brotli
        git config pull.rebase false
        git pull
        git submodule update --init
    fi

    MODULE_NAME="Nginx"
    wget_cache "https://nginx.org/download/nginx-${NGINX_VER}.tar.gz" "nginx-${NGINX_VER}.tar.gz"
    tar zxf nginx-${NGINX_VER}.tar.gz || return 255
    rm -rf /usr/local/nginx

    cd nginx-${NGINX_VER}
    # sed -i "s#${NGINX_VER}#0.0.0#g" src/core/nginx.h
    # sed -i "s#\"NGINX\"#\"Apache\"#" src/core/nginx.h
    # sed -i "s#\"nginx/\"#\"Apache/\"#" src/core/nginx.h
    # sed -i "s#Server: nginx#Server: Apache#" src/http/ngx_http_header_filter_module.c
    # sed -i "s#\"<hr><center>nginx<\/center>\"#\"<hr><center>Apache<\/center>\"#" src/http/ngx_http_special_response.c
    # sed -i "s#server: nginx#server: Apache#" src/http/v2/ngx_http_v2_filter_module.c
    # sed -i "s#/.openssl/#/#g" auto/lib/openssl/conf
    ./configure \
        --add-module=../ngx_brotli \
        --with-openssl=../openssl-${OPENSSL_VER} \
        --with-openssl-opt=enable-tls1_3 \
        --with-http_v2_module \
        --with-http_ssl_module \
        --with-http_gzip_static_module \
        --with-http_realip_module \
        --with-pcre \
        --with-threads \
        --without-mail_pop3_module \
        --without-mail_imap_module \
        --without-mail_smtp_module
    make -j ${CPUS} && make install || make_result="fail" 
    if [[ $make_result == "fail" ]]; then
        return 1
    fi

    # 升级不要 make install
    # cp /usr/local/nginx/sbin/nginx /root/src/nginx.bak
    # cp ./objs/nginx /usr/local/nginx/sbin/
    # make upgrade
    # nginx -V

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

    yum -y remove php* libzip
    rpm -qa | grep php
    rpm -e php-mysql php-cli php-gd php-common php --nodeps
    yum install -y oniguruma-devel libmcrypt libmcrypt-devel mcrypt mhash libxslt libxslt-devel libxml2 libxml2-devel libjpeg-devel libpng-devel freetype-devel libicu-devel libwebp-devel libcurl-devel gd-devel libxslt-devel ImageMagick-devel

    # yun install ver: 6.8.2 
    # yum -y install https://rpms.remirepo.net/enterprise/7/remi/x86_64/oniguruma5php-6.9.8-1.el7.remi.x86_64.rpm
    # yum -y install https://rpms.remirepo.net/enterprise/7/remi/x86_64/oniguruma5php-devel-6.9.8-1.el7.remi.x86_64.rpm

    wget_cache "https://libzip.org/download/libzip-${LIBZIP_VER}.tar.gz" "libzip-${LIBZIP_VER}.tar.gz" "libzip"
    tar zxf libzip-${LIBZIP_VER}.tar.gz || return 255
    mkdir libzip-${LIBZIP_VER}/build 
    cd libzip-${LIBZIP_VER}/build
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local/libzip -DENABLE_OPENSSL=on -DENABLE_GNUTLS=off -DENABLE_MBEDTLS=off
    make && make install || make_result="fail"
    if [[ $make_result == "fail" ]]; then
        echo "make libzip failed!" >> /root/install-error.log
        return 1
    fi
    make_result=""
    echo "/usr/local/libzip/lib64" >> /etc/ld.so.conf.d/local.conf
    ldconfig

    wget_cache "http://cn2.php.net/get/php-${PHP_VER}.tar.gz/from/this/mirror" "php-${PHP_VER}.tar.gz" "PHP"
    tar zxf php-${PHP_VER}.tar.gz || return 255

    cd php-${PHP_VER}
    export PKG_CONFIG_PATH="$PKG_CONFIG_PATH:/usr/local/libzip/lib64/pkgconfig"
    ./configure --prefix=/usr/local/php \
                --with-config-file-path=/usr/local/php/etc \
                --with-config-file-scan-dir=/usr/local/php/conf.d \
                --with-fpm-user=nobody \
                --with-fpm-group=nobody \
                --with-mysqli=mysqlnd \
                --with-pdo-mysql=mysqlnd \
                --with-iconv \
                --with-freetype=/usr/local/freetype \
                --with-jpeg \
                --with-webp \
                --with-zip \
                --with-curl \
                --with-openssl \
                --with-mhash \
                --with-xsl \
                --with-zlib \
                --with-pear \
                --disable-rpath \
                --enable-gd \
                --enable-fpm \
                --enable-xml \
                --enable-bcmath \
                --enable-shmop \
                --enable-sysvsem \
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
                --enable-exif \
                --enable-session

    #make ZEND_EXTRA_LIBS='-liconv' && make install
    make -j ${CPUS} && make install || make_result="fail"
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
    \cp ${CUR_DIR}/src/php-${PHP_VER}/php.ini-production /usr/local/php/etc/php.ini

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

    \cp php-${PHP_VER}/sapi/fpm/init.d.php-fpm /etc/init.d/php-fpm
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

    wget_cache "https://pecl.php.net/get/mcrypt-${PHP_MCRYPT_VER}.tgz" "mcrypt-${PHP_MCRYPT_VER}.tgz" "PHP-Mcrypt"
    if ! tar xf mcrypt-${PHP_MCRYPT_VER}.tgz; then
        echo "PHP-Mcrypt ${PHP_MCRYPT_VER} 模块源码包下载失败，PHP 服务将不安装此模块！" >> /root/install-error.log
    else
        cd mcrypt-${PHP_MCRYPT_VER}
        phpize
        ./configure --with-php-config=/usr/local/php/bin/php-config
        make && make install
        echo "extension=mcrypt.so" >> /usr/local/php/etc/php.ini
    fi

    # yum install ImageMagick-devel  # ver: 6.9.10.68
    # yum -y install https://rpms.remirepo.net/enterprise/7/remi/x86_64/ImageMagick6-6.9.12.77-1.el7.remi.x86_64.rpm
    # yum -y install https://rpms.remirepo.net/enterprise/7/remi/x86_64/ImageMagick6-devel-6.9.12.77-1.el7.remi.x86_64.rpm
    # https://rpms.remirepo.net/enterprise/7/remi/x86_64/ImageMagick7-7.1.0.62-1.el7.remi.x86_64.rpm
    # https://rpms.remirepo.net/enterprise/7/remi/x86_64/ImageMagick7-devel-7.1.0.62-1.el7.remi.x86_64.rpm
    wget_cache "https://pecl.php.net/get/imagick-${PHP_IMAGICK_VER}.tgz" "imagick-${PHP_IMAGICK_VER}.tgz" "PHP-Imagick"
    if ! tar xf imagick-${PHP_IMAGICK_VER}.tgz; then
        echo "PHP-Imagick ${PHP_IMAGICK_VER} 模块源码包下载失败，PHP 服务将不安装此模块！" >> /root/install-error.log
    else
        cd imagick-${PHP_IMAGICK_VER}
        phpize
        ./configure --with-php-config=/usr/local/php/bin/php-config
        make && make install
        echo "extension=imagick.so" >> /usr/local/php/etc/php.ini
    fi

    if [ -s /usr/local/redis/bin/redis-server ]; then
        wget_cache "https://github.com/phpredis/phpredis/archive/refs/tags/${PHP_REDIS_VER}.tar.gz" "phpredis-${PHP_REDIS_VER}.tar.gz" "PHP-Redis"
        if ! tar zxf phpredis-${PHP_REDIS_VER}.tar.gz; then
            echo "PHP-Redis 模块源码包下载失败，PHP 服务将不安装此模块！" >> /root/install-error.log
        else
            cd phpredis-${PHP_REDIS_VER}
            phpize
            ./configure --with-php-config=/usr/local/php/bin/php-config
            make && make install
            echo "extension=redis.so" >> /usr/local/php/etc/php.ini
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
            fi
        fi
    fi
}

install_redis() {
    yum -y install centos-release-scl
    yum -y install devtoolset-9-gcc devtoolset-9-gcc-c++ devtoolset-9-binutils
    source /opt/rh/devtoolset-9/enable
    # 如果要长期使用gcc 9的话：
    # echo "source /opt/rh/devtoolset-9/enable" >> /etc/profile

    wget_cache "http://download.redis.io/releases/redis-${REDIS_VER}.tar.gz" "redis-${REDIS_VER}.tar.gz"
    tar zxf redis-${REDIS_VER}.tar.gz || return 255

    if [[ ${INSSTACK} != "auto" ]]; then
        echo_yellow "请输入 Redis 安全密码（直接回车将自动生成密码）"
        read -r -p "密码: " REDISPWD
        echo_yellow "请输入 Redis 端口（直接回车将使用默认端口）"
        read -r -p "端口: " REDISPORT
    fi
    if [[ -z ${REDISPWD} ]]; then
        echo_red "没有输入密码，将采用默认密码。"
        REDISPWD=$(echo "zsenClub#$RANDOM" | md5sum | cut -d " " -f 1)
    fi
    if [[ -z ${REDISPORT} ]]; then
        echo_red "没有输入端口，将采用默认端口(6379)。"
        REDISPORT=6379
    fi
    echo_green "Redis 安全密码(请记下来): ${REDISPWD}"
    echo_green "Redis 端口(请记下来): ${REDISPORT}"

    REDISHOME=${INSHOME}/database/redis
    groupadd redis
    useradd -r -g redis -s /bin/false redis
    mkdir -p /usr/local/redis/{etc,run}
    mkdir -p ${REDISHOME}
    chown -R redis:redis ${REDISHOME}

    cd redis-${REDIS_VER}
    make -j ${CPUS} && make PREFIX=/usr/local/redis install || make_result="fail"
    if [[ $make_result == "fail" ]]; then
        return 1
    fi
    # redis-check-rdb rdbfile

    \cp redis-${REDIS_VER}/redis.conf  /usr/local/redis/etc/
    sed -i "s/daemonize no/daemonize yes/g" /usr/local/redis/etc/redis.conf
    sed -i "s/^# bind 127.0.0.1/bind 127.0.0.1/g" /usr/local/redis/etc/redis.conf
    sed -i "s/port 6379/port ${REDISPORT}/g" /usr/local/redis/etc/redis.conf
    sed -i "s#^pidfile /var/run/redis_6379.pid#pidfile /usr/local/redis/run/redis.pid#g" /usr/local/redis/etc/redis.conf
    sed -i "s/^# requirepass.*/requirepass ${REDISPWD}/g" /usr/local/redis/etc/redis.conf
    sed -i "s#logfile \"\"#logfile ${INSHOME}/wwwlogs/redis.log#g" /usr/local/redis/etc/redis.conf
    sed -i "s#dir ./#dir ${REDISHOME}/#g" /usr/local/redis/etc/redis.conf

    cat > /etc/rc.d/init.d/redis<<EOF
#! /bin/bash
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

install_mongod() {
    cat > /etc/yum.repos.d/mongodb-org-${MONGOD_VER}.repo<<EOF
[mongodb-org-6.0]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/\$releasever/mongodb-org/${MONGOD_VER}/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-${MONGOD_VER}.asc
EOF
    yum install -y mongodb-org
    systemctl start mongod.service
    systemctl enable mongod

    # firewall-cmd --zone=public --add-port=27017/tcp --permanent # mongodb默认端口号
    # firewall-cmd --reload  # 重新加载防火墙
    # firewall-cmd --zone=public --query-port=27017/tcp # 查看端口号是否开放成功，输出yes开放成功，no则失败

    # # admin数据库
    # > use admin
    # switched to db admin
    # > db.createUser({ user:"root", pwd:"123456", roles:["root"] })
    # Successfully added user: { "user" : "root", "roles" : [ "root" ] }
}

install_wkhtmltopdf() {
    wget_cache "https://github.com/wkhtmltopdf/packaging/releases/download/${WKHTMLTOX_VER}/wkhtmltox-${WKHTMLTOX_VER}.centos7.x86_64.rpm" "wkhtmltox-${WKHTMLTOX_VER}.centos7.x86_64.rpm"
    yum localinstall wkhtmltox-${WKHTMLTOX_VER}.centos7.x86_64.rpm

    mkdir -p /usr/share/fonts/chinese
    mv /root/src/fonts/* /usr/share/fonts/chinese/
    cd /usr/share/fonts/chinese
    mkfontscale && mkfontdir && fc-cache -fv
    chmod -R 755 /usr/share/fonts/chinese
    cd $CUR_DIR
    fc-list :lang=zh
}

install_java() {
    yum install -y java-11-openjdk.x86_64 java-11-openjdk-devel.x86_64
    export JAVA_HOME=/usr/lib/jvm/java-11-openjdk
    export JRE_HOME=/usr/lib/jvm/java-11-openjdk/jre

    MODULE_NAME="Tomcat"
    ins_begin
    wget_cache "https://archive.apache.org/dist/tomcat/tomcat-9/v${TOMCAT_VER}/bin/apache-tomcat-${TOMCAT_VER}.tar.gz" "apache-tomcat-${TOMCAT_VER}.tar.gz"
    tar zxf apache-tomcat-${TOMCAT_VER}.tar.gz || return 255

    cd apache-tomcat-${TOMCAT_VER}/bin
    tar zxf commons-daemon-native.tar.gz
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

setting_smtp() {
    # 修改默认邮件传输代理：alternatives --config mta
    # 查看邮件传输代理是否修改成功：alternatives --display mta

    echo_blue "提示：阿里云/腾讯云服务器封掉了 25 端口，默认方式发送邮件不成功(可以申请解封)"
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

        chmod +r /etc/msmtprc
        echo '' >> /etc/mail.rc
        echo 'set sendmail=/usr/bin/msmtp' >> /etc/mail.rc

        if [[ ${INSMUTT} == "y" || ${INSMUTT} == "Y" ]]; then
            echo '' >> /etc/Muttrc.local
            echo 'set sendmail=/usr/bin/msmtp' >> /etc/Muttrc.local
        fi
        ;;
    esac
}

install_gitlab_ci_runner() {
    curl -L https://packages.gitlab.com/install/repositories/runner/gitlab-ci-multi-runner/script.rpm.sh | bash
    yum install -y gitlab-ci-multi-runner
}

install_shellMonitor() {
    if [ -d /usr/local/shellMonitor ]; then
        echo_yellow "已存在 shellMonitor, 是否覆盖安装?"
        read -r -p "是(Y)/否(N): " REINSMONITOR
        if [[ ${REINSMONITOR} == "y" || ${REINSMONITOR} == "Y" ]]; then
            \cp /usr/local/shellMonitor/config.sh ./shellMonitor.config.bak
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
    if [ -f "$CUR_DIR/src/pnmp" ]; then
        \cp $CUR_DIR/src/pnmp /usr/local/bin/${MYNAME}
    else
        wget "https://raw.githubusercontent.com/zsenliao/initServer/master/pnmp" -O /usr/local/bin/${MYNAME}
    fi
    sed -i "s|/data|${INSHOME}|g" /usr/local/bin/${MYNAME}
    chmod +x /usr/local/bin/${MYNAME}
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

init_install() {
    yum-complete-transaction --cleanup-only
    yum history redo last

    yum -y update
    yum -y upgrade

    yum install -y firewalld firewalld-config wget gcc gcc-c++ make curl unzip zlib-devel curl-devel ncurses-devel readline-devel sqlite-devel centos-release-scl fontconfig mkfontscale

    systemctl start firewalld
    disable_selinux
    check_hosts

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
    echo "/usr/local/lib64" >> /etc/ld.so.conf.d/local.conf
    echo "/usr/local/lib" >> /etc/ld.so.conf.d/local.conf
    echo "/usr/lib64" >> /etc/ld.so.conf.d/local.conf
    echo "/usr/lib" >> /etc/ld.so.conf.d/local.conf
    ldconfig
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

if [[ ${MemTotal} -lt 3072 ]]; then
    echo_blue "内存过低，创建 SWAP 交换区..."
    fallocate -l 4G /swap  # 获取要增加的2G的SWAP文件块
    chown root:root /swap 
    chmod 0600 /swap
    mkswap /swap  # 创建SWAP文件
    swapon /swap  # 激活SWAP文件
    swapon -s  # 查看SWAP信息是否正确
    # echo "/swap swap swap defaults 0 0" >> /etc/fstab  # 添加到fstab文件中让系统引导时自动启动
fi

mkdir -p "${CUR_DIR}/src"
cd "${CUR_DIR}/src" || exit 255

echo_blue "========= 基本信息 ========="
get_server_ip
MEMINFO=$(free -h | grep Mem)
echo_info "服务器IP/名称" "${HOSTIP} / $(uname -n)"
echo_info "内存大小/空闲" "$(echo $MEMINFO|awk '{print $2}') / $(echo $MEMINFO|awk '{print $4}')"
echo_info "硬件平台/处理器类型/内核版本" "$(uname -i)($(uname -m)) / $(uname -p) / $(uname -r)"
echo_info "CPU 型号(物理/逻辑/每个核数)" "$(grep 'model name' /proc/cpuinfo|uniq|awk -F : '{print $2}'|sed 's/^[ \t]*//g'|sed 's/ \+/ /g') ($(grep 'physical id' /proc/cpuinfo|sort|uniq|wc -l) / ${CPUS} / $(grep 'cpu cores' /proc/cpuinfo|uniq|awk '{print $4}'))"
echo_info "服务器时间" "$(date '+%Y年%m月%d日 %H:%M:%S')"
echo_info "防火墙状态" "$(firewall-cmd --stat)"
echo_info "当前目录" "$(pwd)"
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

echo_yellow "更换yum源?"
read -r -p "是(Y)/否(N): " CHANGEYUM
if [[ ${CHANGEYUM} == "Y" || ${CHANGEYUM} == "Y" ]]; then
    \cp /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
    sed -e 's|^mirrorlist=|#mirrorlist=|g' \
        -e 's|^#baseurl=http://mirror.centos.org|baseurl=https://mirrors.tuna.tsinghua.edu.cn|g' \
        -i.bak \
        /etc/yum.repos.d/CentOS-*.repo
    yum makecache
fi

init_install


if [[ ${INSSTACK} != "auto" ]]; then
    for setting in "Timezone" "Hostname" "User" "SSH" "SMTP"; do
        echo_yellow "是否设置 ${setting}?"
        read -r -p "是(Y)/否(N): " SETTING_INPUT
        if [[ ${SETTING_INPUT} == "y" || ${SETTING_INPUT} == "Y" ]]; then
            setting_name=$(echo $setting | tr '[:upper:]' '[:lower:]')
            setting_${setting_name}
        fi
    done
fi


for module in "ZSH" "Vim" "Perl" "Openssl" "Htop" "Git" "CMake" "MySQL" "Redis" "Mongod" "Python3" "PHP" "Nginx" "NodeJS" "Java" "wkhtmltopdf"; do
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
    echo_yellow "是否安装 shellMonitor 系统监控工具?"
    read -r -p "是(Y)/否(N): " INSMONITOR
fi
if [[ ${INSMONITOR} == "y" || ${INSMONITOR} == "Y" ]]; then
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
