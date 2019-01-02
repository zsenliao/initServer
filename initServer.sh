#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

CUR_DIR=$(cd $(dirname $BASH_SOURCE); pwd)
MemTotal=`free -m | grep Mem | awk '{print  $2}'`
MODE=''
HOSTIP=$(curl ip.cip.cc 2>/dev/null)
start_time=$(date +%s)

CMAKEVER=3.13.2
PYTHONVER=3.7.2
NODEJSVER=10.15.0
DAEMONVER=1.19.2
NGINXVER=1.15.6
PHPVER=7.2.13
REDISVER=5.0.3
MYSQLVER=5.7.21

set_time_zone() {
    echo_blue "设置时区..."
    rm -rf /etc/localtime
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
}

get_os_name() {
    OSNAME=$(cat /etc/*-release | grep -i ^name | awk 'BEGIN{FS="=\""} {print $2}' | awk '{print $1}')
}

check_hosts() {
    if grep -Eqi '^127.0.0.1[[:space:]]*localhost' /etc/hosts; then
        echo_green "Hosts: ok!"
    else
        echo "127.0.0.1 localhost.localdomain localhost" >> /etc/hosts
    fi
    pingresult=`ping -c1 baidu.com 2>&1`
    echo_blue "${pingresult}"
    if echo "${pingresult}" | grep -q "unknown host"; then
        echo_red "DNS...fail!"
        echo_blue "Writing nameserver to /etc/resolv.conf ..."
        echo -e "nameserver 208.67.220.220\nnameserver 114.114.114.114" > /etc/resolv.conf
    else
        echo_green "DNS...ok!"
    fi
}

disable_selinux() {
    if [ -s /etc/selinux/config ]; then
        sed -i "s/^SELINUX=.*/SELINUX=disabled/g" /etc/selinux/config
    fi
}

color_text() {
    echo -e " \e[0;$2m$1\e[0m"
}

echo_red() {
    echo $(color_text "$1" "31")
}

echo_green() {
    echo $(color_text "$1" "32")
}

echo_yellow() {
    echo $(color_text "$1" "33")
}

echo_blue() {
    echo $(color_text "$1" "34")
}

ins_begin() {
    MODE=$1
    echo $(color_text "[+] 安装 $1..." "34")
}

ins_end() {
    local version=$($1 --version)
    [ $? -eq 0 ] && echo $(color_text "[√] $MODE 安装成功! 当前版本：$version" "32") || echo $(color_text "[x] $MODE 安装失败! " "31")
}

show_ver() {
    VER=$($1 2>&1)
    if [ $? -eq 0 ]; then
        echo_green "当前已安装 $2, 版本：${VER}"
        echo_yellow "是否重新编译安装?"
    else
        VER=''
        echo_yellow "是否安装 $2?"
    fi
}

set_host_name() {
    echo_yellow "[+] 修改 hostname..."
    read -r -p "请输入 hostname: " HOST_NAME
    sed -i "s/^127.0.0.1 .*/127.0.0.1 ${HOST_NAME}/g" /etc/hosts
    echo "${HOSTIP} ${HOST_NAME}" >> /etc/hosts
    echo "hostname=\"${HOST_NAME}\"" >> /etc/sysconfig/network
    echo '' > /etc/hostname
    echo ${HOST_NAME} > /etc/hostname
    /etc/init.d/network restart
    echo_blue "[!] 请检测修改是否生效:"
    cat /etc/hosts
}

add_user() {
    echo_yellow "[+] 添加用户..."
    read -r -p "请输入用户名: " USERNAME
    read -r -p "请输入用户密码: " PASSWORD
    read -r -p "请输入 ssh 证书名: " FILENAME

    if [[ -n "${USERNAME}" && -n "${PASSWORD}" ]]; then
        useradd ${USERNAME}
        echo ${PASSWORD} | passwd ${USERNAME} --stdin  &>/dev/null

        mkdir -p /home/${USERNAME}/.ssh
        chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}
        chmod -R 755 /home/${USERNAME}
        cd /home/${USERNAME}/.ssh
        if [ -z "${FILENAME}" ]; then
            FILENAME=${USERNAME}
        fi

        echo_yellow "请输入证书密码(如不要密码请直接回车)"
        su ${USERNAME} -c "ssh-keygen -t rsa -f ${FILENAME}"

        cd ${CUR_DIR}/src

        chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}
        chmod -R 755 /home/${USERNAME}
        echo_green "[√] 添加用户成功!"

        echo_yellow "是否修改 SSH 配置?"
        read -r -p "是(Y)/否(N): " SETSSH
        if [[ ${SETSSH} = "y" || ${SETSSH} = "Y" ]]; then
            ssh_setting
        fi
    fi
}

ssh_setting() {
    echo_yellow "[+] 修改 SSH 配置..."
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    echo_blue "请打开一个新的命令窗口后，通过以下指令下载证书文件："
    echo "scp ${USERNAME}@${HOSTIP}:/home/${USERNAME}/.ssh/${FILENAME} ./"
    echo_yellow "是否下载成功?"
    read -r -p "是(Y)/否(N): " DOWNFILE
    if [[ "${DOWNFILE}" = "y" || "${DOWNFILE}" = "Y" ]]; then
        sed -i "s/^PasswordAuthentication [a-z]*/#&/g; 1,/^#PasswordAuthentication [a-z]*/{s/^#PasswordAuthentication [a-z]*/PasswordAuthentication no/g}" /etc/ssh/sshd_config
    fi

    echo_yellow "是否修改 SSH 默认端口(强烈建议修改，如不修改请直接回车)?"
    read -r -p "请输入 ssh 端口: " SSHPORT
    if [ -z "${SSHPORT}" ]; then
        SSHPORT="22"
    fi

    sed -i "s/^Port [0-9]*/#&/g; 1,/^#Port [0-9]*/{s/^#Port [0-9]*/Port ${SSHPORT}/g}" /etc/ssh/sshd_config
    sed -i "s/^RSAAuthentication [a-z]*/#&/g; 1,/^#RSAAuthentication [a-z]*/{s/^#RSAAuthentication [a-z]*/RSAAuthentication yes/g}" /etc/ssh/sshd_config
    sed -i "s/^PermitRootLogin [a-z]*/#&/g; 1,/^#PermitRootLogin [a-z]*/{s/^#PermitRootLogin [a-z]*/PermitRootLogin no/g}" /etc/ssh/sshd_config
    sed -i "s/^PermitEmptyPasswords [a-z]*/#&/g; 1,/^#PermitEmptyPasswords [a-z]*/{s/^#PermitEmptyPasswords [a-z]*/PermitEmptyPasswords no/g}" /etc/ssh/sshd_config
    sed -i "s/^UsePAM [a-z]*/#&/g; 1,/^#UsePAM [a-z]*/{s/^#UsePAM [a-z]*/UsePAM no/g}" /etc/ssh/sshd_config
    sed -i "s/^StrictModes [a-z]*/#&/g; 1,/^#StrictModes [a-z]*/{s/^#StrictModes [a-z]*/StrictModes yes/g}" /etc/ssh/sshd_config
    sed -i "s/^IgnoreRhosts [a-z]*/#&/g; 1,/^#IgnoreRhosts [a-z]*/{s/^#IgnoreRhosts [a-z]*/IgnoreRhosts yes/g}" /etc/ssh/sshd_config
    sed -i "s|AuthorizedKeysFile.*|AuthorizedKeysFile .ssh/${FILENAME}.pub|g" /etc/ssh/sshd_config
    sed -i "s/^TCPKeepAlive [a-z]*/#&/g; 1,/^#TCPKeepAlive [a-z]*/{s/^#TCPKeepAlive [a-z]*/TCPKeepAlive yes/g}" /etc/ssh/sshd_config
    sed -i "s/^ClientAliveInterval [0-9]*/#&/g; 1,/^#ClientAliveInterval [0-9]*/{s/^#ClientAliveInterval [0-9]*/ClientAliveInterval 300/g}" /etc/ssh/sshd_config
    sed -i "s/^ClientAliveCountMax [0-9]/#&/g; 1,/^#ClientAliveCountMax [0-9]/{s/^#ClientAliveCountMax [0-9]/ClientAliveCountMax 3/g}" /etc/ssh/sshd_config
    sed -i "s/^PrintLastLog [a-z]*/#&/g; 1,/^#PrintLastLog [a-z]*/{s/^#PrintLastLog [a-z]*/PrintLastLog yes/g}" /etc/ssh/sshd_config
    sed -i "s/^PrintMotd [a-z]*/#&/g; 1,/#PrintMotd[a-z]*/{s/^#PrintMotd [a-z]*/PrintMotd no/g}" /etc/ssh/sshd_config
    echo "" >> /etc/ssh/sshd_config
    echo "AllowUsers ${USERNAME}" >> /etc/ssh/sshd_config

    # 开启sftp日志
    sed -i "s/sftp-server/sftp-server -l INFO -f AUTH/g" /etc/ssh/sshd_config
    echo "" >> /etc/rsyslog.conf
    echo "auth,authpriv.*                                         /var/log/sftp.log" >> /etc/rsyslog.conf

    chmod 700 /home/${USERNAME}/.ssh
    chmod 600 /home/${USERNAME}/.ssh/${FILENAME}

    # 防火墙设置
    # FIREWALL=$(firewall-cmd --state 2>/dev/null)
    # if [[ "${FIREWALL}" != "running" ]]; then
    #     systemctl start firewalld
    # fi
    if [[ "${SSHPORT}" != "22" ]]; then
        echo_blue "正在关闭 SSH 默认端口(22)..."
        firewall-cmd --permanent --remove-service=ssh
        echo_blue "正在添加 SSH 连接新端口(${SSHPORT})..."
        firewall-cmd --zone=public --add-port=${SSHPORT}/tcp --permanent
        echo_blue "正在重启防火墙"
        firewall-cmd --reload
    fi

    service sshd restart
    service rsyslog restart
    echo_green "[√] SSH 配置修改成功!"

    if [[ "${DOWNFILE}" = "y" || "${DOWNFILE}" = "Y" ]]; then
        echo_green "登录方式(根据实际情况修改证书路径，如设置了证书密码还需要输入密码)："
        echo_red "请将你的证书文件设置 600 权限： chmod 600 ${FILENAME}"
        echo "ssh -i ./${FILENAME} -p ${SSHPORT} ${USERNAME}@${HOSTIP}"
    else
        echo_green "登录方式(需要输入用户密码 ${PASSWORD})："
        echo "ssh -p ${SSHPORT} ${USERNAME}@${HOSTIP}"
    fi

    echo_blue "[!] 请链接一个新的 ssh 到服务器，看是否能连接成功"
    echo_yellow "是否连接成功?"
    read -r -p "成功(Y)/失败(N): " SSHSUSS
    if [[ "${SSHSUSS}" = "n" || "${SSHSUSS}" = "N" ]]; then
        echo_yellow "是否删除新添加的用户: ${USERNAME}?"
        read -r -p "是(Y)/否(N): " DELUSER
        if [[ "${DELUSER}" = "n" || "${DELUSER}" = "N" ]]; then
            userdel ${USERNAME}
            rm -rf /home/${USERNAME}
            echo_red "删除用户成功!"
        fi

        cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        service sshd restart
        echo_red "已复原 SSH 配置!"
    fi
}

install_git() {
    ins_begin "git"
    yum install -y autoconf zlib-devel curl-devel openssl-devel perl cpio expat-devel gettext-devel openssl zlib gcc perl-ExtUtils-MakeMaker

    wget -c https://github.com/git/git/archive/master.tar.gz -O git-master.tar.gz
    tar xzf git-master.tar.gz
    cd git-master

    make configure
    ./configure --prefix=/usr/local
    make && make install

    ins_end "git"
    cd ..
}

install_zsh() {
    ins_begin "zsh"
    yum install -y zsh
    chsh -s /bin/zsh

    echo_yellow "是否安装 oh my zsh?"
    read -r -p "是(Y)/否(N): " INSOHMYZSH
    if [[ ${INSOHMYZSH} = "y" || ${INSOHMYZSH} = "Y" ]]; then
        echo_blue "[+] 安装 oh my zsh..."
        wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | sh
        sed -i "s/ZSH_THEME=\"robbyrussell\"/ZSH_THEME=\"ys\"/g" ~/.zshrc
    fi

    echo 'export CLICOLOR=1' >> ~/.zshrc
    echo 'alias ll="ls -alF"' >> ~/.zshrc
    echo 'alias la="ls -A"' >> ~/.zshrc
    echo 'alias l="ls -CF"' >> ~/.zshrc
    echo 'alias lbys="ls -alhS"' >> ~/.zshrc
    echo 'alias lbyt="ls -alht"' >> ~/.zshrc
    echo 'alias cls="clear"' >> ~/.zshrc
    echo 'alias grep="grep --color"' >> ~/.zshrc

    echo "export PATH=/usr/local/bin:\$PATH" >> ~/.zshrc
    echo "export PATH=/usr/local/bin:\$PATH" >> ~/.bashrc

    ins_end "zsh"
}

install_vim() {
    echo_blue "[+] 升级 vim..."
    yum install -y ncurses-devel

    wget -c https://github.com/vim/vim/archive/master.tar.gz -O vim-master.tar.gz
    if [ $? -eq 0 ]; then
        yum remove -y vim
        tar zxf vim-master.tar.gz
        cd vim-master/src
        make && make install

        echo_green "[√] vim 升级成功!"
        cd ../..
    else
        echo_red "[!] vim 安装源下载失败!"
    fi

    echo_blue "[+] 安装 vim 插件..."
    curl https://raw.githubusercontent.com/wklken/vim-for-server/master/vimrc > ~/.vimrc
    echo 'alias vi="vim"' >> ~/.zshrc
    source ~/.zshrc

    mkdir -p ~/.vim/syntax

    wget -O ~/.vim/syntax/nginx.vim http://www.vim.org/scripts/download_script.php?src_id=19394
    echo "au BufRead,BufNewFile ${INSHOME}/wwwconf/nginx/*,/usr/local/nginx/conf/* if &ft == '' | setfiletype nginx | endif " >> ~/.vim/filetype.vim  

    wget -O ini.vim.zip https://www.vim.org/scripts/download_script.php?src_id=10629
    unzip ini.vim.zip && mv vim-ini-*/ini.vim ~/.vim/syntax/ini.vim
    rm -rf vim-ini-* ini.vim.zip
    echo "au BufNewFile,BufRead *.ini,*/.hgrc,*/.hg/hgrc setf ini" >> ~/.vim/filetype.vim

    wget -O php.vim.tar.gz https://www.vim.org/scripts/download_script.php?src_id=8651
    tar zxf php.vim.tar.gz && mv syntax/php.vim ~/.vim/syntax/php.vim
    rm -rf syntax php.vim.tar.gz
    echo "au BufNewFile,BufRead *.php setf php" >> ~/.vim/filetype.vim

    wget -O ~/.vim/syntax/python.wim https://www.vim.org/scripts/download_script.php?src_id=21056
    echo "au BufNewFile,BufRead *.py setf python" >> ~/.vim/filetype.vim
}

install_cmake() {
    ins_begin "CMake"
    rpm -q cmake
    yum remove -y cmake
    yum install -y gcc gcc-c++

    wget -c https://github.com/Kitware/CMake/releases/download/v${CMAKEVER}/cmake-${CMAKEVER}.tar.gz
    tar zxf cmake-${CMAKEVER}.tar.gz
    cd cmake-${CMAKEVER}

    ./bootstrap
    make && make install

    ins_end "cmake"
    cd ..
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
        echo '. "/root/.acme.sh/acme.sh.env"' >> ~/.zshrc
        source ~/.zshrc
        source ~/.bashrc

        acme.sh --upgrade --auto-upgrade

        ins_end "/root/.acme.sh/acme.sh"
    fi
}

install_python3() {
    ins_begin "Python3"
    yum install -y epel-release zlib-devel readline-devel bzip2-devel ncurses-devel sqlite-devel gdbm-devel libffi-devel

    wget -c --no-check-certificate https://www.python.org/ftp/python/${PYTHONVER}/Python-${PYTHONVER}.tgz
    tar xf Python-${PYTHONVER}.tgz
    cd Python-${PYTHONVER}

    ./configure --prefix=/usr/local/python3.7 --enable-optimizations
    make && make install

    ln -sf /usr/local/python3.7/bin/python3 /usr/local/bin/python3
    ln -sf /usr/local/python3.7/bin/2to3 /usr/local/bin/2to3
    ln -sf /usr/local/python3.7/bin/idle3 /usr/local/bin/idle3
    ln -sf /usr/local/python3.7/bin/pydoc3 /usr/local/bin/pydoc3
    ln -sf /usr/local/python3.7/bin/python3.7-config /usr/local/bin/python3.7-config
    ln -sf /usr/local/python3.7/bin/python3-config /usr/local/bin/python3-config
    ln -sf /usr/local/python3.7/bin/pyvenv /usr/local/bin/pyvenv

    curl -O https://bootstrap.pypa.io/get-pip.py
    python3 get-pip.py
    ln -sf /usr/local/python3.7/bin/pip3 /usr/local/bin/pip3
    pip3 install --upgrade pip

    echo_yellow "[!] 是否将 Python3 设置为默认 Python 解释器: "
    read -r -p "是(Y)/否(N): " DEFPYH
    if [[ ${DEFPYH} = "y" || ${DEFPYH} = "Y" ]]; then
        # rm -r /usr/bin/python
        ln -sf /usr/local/bin/python3 /usr/local/bin/python
        sed -i "s/python/python2/" /usr/bin/yum

        # rm -r /usr/bin/pip
        ln -sf /usr/local/bin/pip3 /usr/local/bin/pip
    fi

    ins_end "python3"
    ins_end "pip3"
    cd ..
}

install_uwsgi() {
    ins_begin "uwsgi"
    pip3 install uwsgi
    ln -sf /usr/local/python3.7/bin/uwsgi /usr/local/bin/uwsgi

    mkdir -p ${INSHOME}/wwwconf/uwsgi
    chown -R nobody:nobody ${INSHOME}/wwwconf

    TMPCONFDIR=${INSHOME}/wwwconf/uwsgi/

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
CONFIGDIR=${INSHOME}/wwwconf/uwsgi
PIDDIR=/tmp

iniList=\$(ls \${CONFIGDIR}/*.ini 2>/dev/null)

start() {
    echo "Starting \$DESC: "
    for i in \${iniList[@]}
    do
        SiteName=\${i:${#TMPCONFDIR}:0-4}
        pid=\$(ps aux | grep \$i | grep -v grep | awk '{ print \$13 }' | sort -mu 2>/dev/null)
        if [ ! -z "\$pid" ]; then
            echo -e "\\t\${SiteName}: \\033[33m[already running]\\033[0m"
        else
            \$DAEMON --ini \${i} 2>/dev/null
            if [ \$? -eq 0 ]; then
                echo -e "\\t\${SiteName}: \\033[32m[OK]\\033[0m"
            else
                echo -e "\\t\${SiteName}: \\033[31m[Fail]\\033[0m"
            fi
        fi
    done
}

stop() {
    echo "Stopping \$DESC: "
    for i in \${iniList[@]}
    do
        SiteName=\${i:${#TMPCONFDIR}:0-4}
        pid=\$(ps aux | grep \$i | grep -v grep | awk '{ print \$13 }' | sort -mu 2>/dev/null)
        if [ ! -z "\$pid" ]; then
            \$DAEMON --stop \${PIDDIR}/\${SiteName}.uwsgi.pid 2>/dev/null
            if [ \$? -eq 0 ]; then
                echo -e "\\t\${SiteName}: \\033[32m[OK]\\033[0m"
            else
                echo -e "\\t\${SiteName}: \\033[31m[Fail]\\033[0m"
            fi
        else
            echo -e "\\t\${SiteName}: \\033[33m[not running]\\033[0m"
        fi
    done
}

reload() {
    echo "Reloading \$DESC: "
    for i in \${iniList[@]}
    do
        SiteName=\${i:${#TMPCONFDIR}:0-4}
        pid=\$(ps aux | grep \$i | grep -v grep | awk '{ print \$13 }' | sort -mu 2>/dev/null)
        if [ ! -z "\$pid" ]; then
            \$DAEMON --reload \${PIDDIR}/\${SiteName}.uwsgi.pid 2>/dev/null
            if [ \$? -eq 0 ]; then
                echo -e "\\t\${SiteName}: \\033[32m[OK]\\033[0m"
            else
                echo -e "\\t\${SiteName}: \\033[31m[Fail]\\033[0m"
            fi
        else
            echo -e "\\t\${SiteName}: \\033[33m[not running]\\033[0m"
        fi
    done
}

status() {
    pid=\$(ps aux | grep \$DAEMON | grep -v grep | awk '{ print \$13 }' | sort -mu 2>/dev/null)
    if [ ! -z "\$pid" ]; then
        echo -e "\${DESC}: is running"
        for i in \${pid[@]}
        do
            echo -e "\\trunning application: \\033[32m\${i:${#TMPCONFDIR}:0-4}\\033[0m"
        done
    else
        echo -e "\${DESC}: \\033[33m[not application running]\\033[0m"
    fi
}

kill() {
    # killall -9 uwsgi
    echo "shutting down uWSGI service ......"
    pids=\$(ps aux | grep uwsgi | grep -v grep | awk '{ print $2 }')
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

    ins_end "uwsgi"
}

install_ikev2() {
    echo_blue "[+] 安装 one-key-ikev2..."
    install_acme

    mkdir ikev2
    cd ikev2
    wget --no-check-certificate https://raw.githubusercontent.com/quericy/one-key-ikev2-vpn/master/one-key-ikev2.sh
    chmod +x one-key-ikev2.sh

    while :;do
        echo_yellow "请输入证书主域名(主域名只能有一个)"
        read -r -p "如 zsen.club: " MAINDOMAIN
        if [ "${MAINDOMAIN}" != "" ]; then
            break
        else
            echo_red "域名不能为空！"
        fi
    done
    echo_yellow "是否绑定更多域名(如不绑定请直接回车)？"
    read -r -p "多个域名请用半角空格隔开: " MOREDOMAIN
    DAMIN="-d ${MAINDOMAIN}"$(echo ${MOREDOMAIN} | sed "s/ / -d&/g" | sed "s/^/-d &/g")

    if [ -f ~/.acme.sh/${MAINDOMAIN}/ca.cer ]; then
        cp ~/.acme.sh/${MAINDOMAIN}/ca.cer ca.cert.pem
        cp ~/.acme.sh/${MAINDOMAIN}/${MAINDOMAIN}.cer server.cert.pem
        cp ~/.acme.sh/${MAINDOMAIN}/${MAINDOMAIN}.key server.pem
    else
        echo_yellow "请选择证书验证方式"
        read -r -p "dns 或 web: " ACMETYPE
        if [[ ${ACMETYPE} = "dns" || ${ACMETYPE} = "DNS" ]]; then
            echo_yellow "你选择的是 DNS 方式验证，需要你的 DNS 服务商:"
            echo_blue "1: CloudFlare"
            echo_blue "2: DNSPod (Default)"
            echo_blue "3: CloudXNS"
            echo_blue "4: GoDaddy"
            read -r -p "请选择 (1, 2, 3, 4): " DNSERVER

            case "${DNSERVER}" in
                1)
                    read -r -p "请输入 CF_KEY: " CF_KEY
                    read -r -p "请输入 CF_Email: " CF_Email
                    export CF_KEY="${CF_KEY}"
                    export CF_Email="${CF_Email}"
                    acme.sh --issue --dns dns_cf ${DAMIN}
                    ;;
                3)
                    read -r -p "请输入 CX_Key: " CX_Key
                    read -r -p "请输入 CX_Secret: " CX_Secret
                    export CX_Key="${CX_Key}"
                    export CX_Secret="${CX_Secret}"
                    acme.sh --issue --dns dns_cx ${DAMIN}
                    ;;
                4)
                    read -r -p "请输入 GD_Key: " GD_Key
                    read -r -p "请输入 GD_Secret: " GD_Secret
                    export GD_Key="${GD_Key}"
                    export GD_Secret="${GD_Secret}"
                    acme.sh --issue --dns dns_gd ${DAMIN}
                    ;;
                *)
                    read -r -p "请输入 DP_Id: " DP_Id
                    read -r -p "请输入 DP_Key: " DP_Key
                    export DP_Id="${DP_Id}"
                    export DP_Key="${DP_Key}"
                    acme.sh --issue --dns dns_dp ${DAMIN}
                    ;;
            esac
        else
            if command -v apache2 >/dev/null 2>&1; then
                acme.sh --issue -d ${DAMIN} --apache
            elif command -v nginx >/dev/null 2>&1; then
                acme.sh --issue -d ${DAMIN} --nginx
            else
                acme.sh --issue -d ${DAMIN} --standalone
            fi
        fi
    fi

    bash one-key-ikev2.sh
    cd ..
}

install_nodejs() {
    ins_begin "Nodejs"
    wget -c https://nodejs.org/dist/v${NODEJSVER}/node-v${NODEJSVER}-linux-x64.tar.xz
    tar -xf node-v${NODEJSVER}-linux-x64.tar.xz
    mv node-v${NODEJSVER}-linux-x64 /usr/local/node
    chown root:root -R /usr/local
    ln -sf /usr/local/node/bin/node /usr/local/bin/node
    ln -sf /usr/local/node/bin/npm /usr/local/bin/npm
    ln -sf /usr/local/node/bin/npx /usr/local/bin/npx
    ins_end "node"
    ins_end "npm"
}

Do_Query() {
    echo "$1" > /tmp/.mysql.tmp
    /usr/local/mysql/bin/mysql --defaults-file=~/.my.cnf < /tmp/.mysql.tmp
    return $?
}

install_mysql() {
    # wget https://dev.mysql.com/get/mysql57-community-release-el7-11.noarch.rpm
    # rpm -Uvh mysql57-community-release-el7-11.noarch.rpm
    # yum install -y mysql-community-server
    ins_begin "MySQL"

    echo_yellow "请输入 MySQL ROOT 用户密码（直接回车将自动生成密码）"
    read -r -p "密码: " DBROOTPWD
    if [ "${DBROOTPWD}" = "" ]; then
        echo_red "没有输入密码，将采用默认密码。"
        DBROOTPWD="zsen@Club#$RANDOM"
    fi
    echo_green "MySQL ROOT 用户密码为(请记下来): ${DBROOTPWD}"

    rpm -qa | grep mysql
    rpm -e mysql mysql-libs --nodeps
    yum remove -y mysql-server mysql mysql-libs
    yum install -y ncurses-devel gcc gcc-c++ bison
    yum -y remove boost-*
    rm -rf ${INSHOME}/database/mysql
    rm -rf /usr/local/mysql

    wget -c http://www.sourceforge.net/projects/boost/files/boost/1.59.0/boost_1_59_0.tar.gz
    tar zxf boost_1_59_0.tar.gz
    mv boost_1_59_0 /usr/local/boost
    chown root:root -R /usr/local/boost

    wget -c https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-${MYSQLVER}.tar.gz
    tar zxf mysql-${MYSQLVER}.tar.gz
    cd mysql-${MYSQLVER}

    rm -f /etc/my.cnf
    groupadd mysql
    useradd -r -g mysql -s /bin/false mysql
    mkdir -p ${INSHOME}/database/mysql
    chown -R mysql:mysql ${INSHOME}/database/mysql

    if [[ ${MemTotal} -lt 1024 ]]; then
        echo_blue "内存过低，创建 SWAP 交换区..."
        dd if=/dev/zero of=/swapfile bs=1k count=2048000  # 获取要增加的2G的SWAP文件块
        mkswap /swapfile  # 创建SWAP文件
        swapon /swapfile  # 激活SWAP文件
        swapon -s  # 查看SWAP信息是否正确
        # echo "/var/swapfile swap swap defaults 0 0" >> /etc/fstab  # 添加到fstab文件中让系统引导时自动启动
    fi

    cmake . -DDOWNLOAD_BOOST=1 -DWITH_BOOST=/usr/local/boost -DMYSQL_DATADIR=${INSHOME}/database/mysql -DDEFAULT_CHARSET=utf8 -DDEFAULT_COLLATION=utf8_general_ci
    make && make install

    if [[ ${MemTotal} -lt 1024 ]]; then
        echo_blue "删除 SWAP 交换区..."
        # 删除SWAP文件块
        swapoff /swapfile
        rm -fr /swapfile
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
datadir     = ${INSHOME}/database/mysql
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
binlog_format=mixed
server-id   = 1
expire_logs_days = 10
early-plugin-load = ""

default_storage_engine = InnoDB
innodb_file_per_table = 1
innodb_data_home_dir = ${INSHOME}/database/mysql
innodb_data_file_path = ibdata1:10M:autoextend
innodb_log_group_home_dir = ${INSHOME}/database/mysql
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

    /usr/local/mysql/bin/mysqld --initialize-insecure --basedir=/usr/local/mysql --datadir=${INSHOME}/database/mysql --user=mysql
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
    # /usr/local/mysql/bin/mysql -e "grant all privileges on *.* to root@'127.0.0.1' identified by \"${DBROOTPWD}\" with grant option;"  
    # /usr/local/mysql/bin/mysql -e "grant all privileges on *.* to root@'localhost' identified by \"${DBROOTPWD}\" with grant option;"  

    /usr/local/mysql/bin/mysqladmin -u root password "${DBROOTPWD}"
    if [ $? -ne 0 ]; then
        echo_red "failed, try other way..."
        cat >~/.emptymy.cnf<<EOF
[client]
user=root
password=''
EOF
        /usr/local/mysql/bin/mysql --defaults-file=~/.emptymy.cnf -e "SET PASSWORD FOR 'root'@'localhost' = PASSWORD('${DBROOTPWD}');"
        [ $? -eq 0 ] && echo_green "Set password Sucessfully." || echo_red "Set password failed!"
        rm -f ~/.emptymy.cnf
    fi

    /etc/init.d/mysqld restart

    cat >~/.my.cnf<<EOF
[client]
user=root
password='${DBROOTPWD}'
EOF
    chmod 600 ~/.my.cnf
    Do_Query ""
    if [ $? -eq 0 ]; then
         echo_green "OK, MySQL root password correct."
    fi
    echo_blue "更新 ROOT 用户密码..."
    Do_Query "UPDATE mysql.user SET authentication_string=PASSWORD('${DBROOTPWD}') WHERE User='root';"
    [ $? -eq 0 ] && echo_green " ... Success." || echo_red " ... Failed!"
    echo_blue "删除匿名用户..."
    Do_Query "DELETE FROM mysql.user WHERE User='';"
    Do_Query "DROP USER ''@'%';"
    [ $? -eq 0 ] && echo_green " ... Success." || echo_red " ... Failed!"
    echo_blue "禁用 ROOT 远程登录..."
    Do_Query "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
    [ $? -eq 0 ] && echo_green " ... Success." || echo_red " ... Failed!"
    echo_blue "删除测试数据库..."
    Do_Query "DROP DATABASE test;"
    [ $? -eq 0 ] && echo_green " ... Success." || echo_red " ... Failed!"
    echo_blue "刷新数据库权限配置..."
    Do_Query "FLUSH PRIVILEGES;"
    [ $? -eq 0 ] && echo_green " ... Success." || echo_red " ... Failed!"

    /etc/init.d/mysqld stop

    if [ -s ~/.my.cnf ]; then
        rm -f ~/.my.cnf
    fi
    if [ -s /tmp/.mysql.tmp ]; then
        rm -f /tmp/.mysql.tmp
    fi

    ins_end "mysql"
    cd ..
}

install_start-stop-daemon() {
    ins_begin "start-stop-daemon"
    yum install -y ncurses-devel
    wget -c http://ftp.de.debian.org/debian/pool/main/d/dpkg/dpkg_${DAEMONVER}.tar.xz -O start-stop-daemon_${DAEMONVER}.tar.xz
    mkdir start-stop-daemon_${DAEMONVER}
    tar -xf start-stop-daemon_${DAEMONVER}.tar.xz -C ./start-stop-daemon_${DAEMONVER} --strip-components 1
    cd start-stop-daemon_${DAEMONVER}

    ./configure
    make
    cp utils/start-stop-daemon /usr/local/bin/

    ins_end "start-stop-daemon"
    cd ..
}
install_nginx() {
    ins_begin "Nginx"
    rpm -qa | grep httpd
    rpm -e httpd httpd-tools --nodeps
    yum remove -y httpd*
    yum install -y build-essential libpcre3 libpcre3-dev zlib1g-dev patch redhat-lsb pcre-devel
    rm -rf /usr/local/nginx

    install_start-stop-daemon
    install_acme

    git clone https://github.com/google/ngx_brotli.git
    cd ngx_brotli
    git submodule update --init
    cd ../

    wget -c  https://github.com/openssl/openssl/archive/OpenSSL_1_1_1.tar.gz
    tar xzf OpenSSL_1_1_1.tar.gz
    mv openssl-OpenSSL_1_1_1 openssl

    wget -c https://nginx.org/download/nginx-${NGINXVER}.tar.gz
    tar zxf nginx-${NGINXVER}.tar.gz
    cd nginx-${NGINXVER}
    sed -i "s/${NGINXVER}/8.8.8.8/g" src/core/nginx.h

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
    make && make install

    ln -sf /usr/local/nginx/sbin/nginx /usr/local/bin/nginx
    rm -f /usr/local/nginx/conf/nginx.conf

    mkdir -p ${INSHOME}/wwwlogs
    chmod 777 ${INSHOME}/wwwlogs

    mkdir -p ${INSHOME}/wwwroot
    chmod +w ${INSHOME}/wwwroot
    chown -R nobody:nobody ${INSHOME}/wwwroot

    mkdir -p ${INSHOME}/wwwconf/nginx
    chown -R nobody:nobody ${INSHOME}/wwwconf
    chmod +w ${INSHOME}/wwwconf

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

        #limit_conn_zone $binary_remote_addr zone=perip:10m;
        ##If enable limit_conn_zone,add "limit_conn perip 10;" to server section.

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

case "\$1" in
    start)
        echo -n "Starting \$DESC: "
        start-stop-daemon --start --quiet --pidfile \$PIDFILE --exec \$DAEMON -- \$DAEMON_OPTS || true
        if [ \$? -eq 0 ]; then
            echo -e "\\033[32m[OK]\\033[0m"
        else
            echo -e "\\033[31m[Fail]\\033[0m"
        fi
        ;;

    stop)
        echo -n "Stopping \$DESC: "
        start-stop-daemon --stop --quiet --pidfile \$PIDFILE --exec \$DAEMON || true
        if [ \$? -eq 0 ]; then
            echo -e "\\033[32m[OK]\\033[0m"
        else
            echo -e "\\033[31m[Fail]\\033[0m"
        fi
        ;;

    restart|force-reload)
        echo -n "Restarting \$DESC: "
        start-stop-daemon --stop --quiet --pidfile \$PIDFILE --exec \$DAEMON || true
        sleep 1
        start-stop-daemon --start --quiet --pidfile \$PIDFILE --exec \$DAEMON -- \$DAEMON_OPTS || true
        if [ \$? -eq 0 ]; then
            echo -e "\\033[32m[OK]\\033[0m"
        else
            echo -e "\\033[31m[Fail]\\033[0m"
        fi
        ;;

    reload)
        echo -n "Reloading \$DESC configuration: "
        start-stop-daemon --stop --signal HUP --quiet --pidfile \$PIDFILE --exec \$DAEMON || true
        if [ \$? -eq 0 ]; then
            echo -e "\\033[32m[OK]\\033[0m"
        else
            echo -e "\\033[31m[Fail]\\033[0m"
        fi
        ;;

    status)
        echo -n "\$DESC status: "
        start-stop-daemon --status --pidfile \$PIDFILE
        case "\$?" in
            0)
                echo -e "\\033[32m[is running]\\033[0m"
                ;;
            1)
                echo -e "\\033[31m[is not running and the pid file exists]\\033[0m"
                ;;
            3)
                echo -e "\\033[33m[is not running]\\033[0m"
                ;;
            4)
                echo -e "\\033[31m[unable to determine status]\\033[0m"
                ;;
        esac
        ;;

    configtest)
        echo -n "Test \$NAME configure files... "
        \$DAEMON -t
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

    echo_green "[√] Nginx 安装成功！当前版本$(nginx -v)"
    cd ..
}

install_php() {
    ins_begin "PHP"
    yum -y remove php* libzip
    rpm -qa | grep php
    rpm -e php-mysql php-cli php-gd php-common php --nodeps
    yum -y install libxslt libxslt-devel libxml2 libxml2-devel curl-devel libjpeg-devel libpng-devel freetype-devel libmcrypt-devel libmcrypt mhash mcrypt libicu-devel

    wget -c https://libzip.org/download/libzip-1.5.1.tar.gz
    tar zxf libzip-1.5.1.tar.gz
    cd libzip-1.5.1
    mkdir build
    cd build
    cmake .. && make && make install
    cd ../..

    cat > /etc/ld.so.conf.d/php.local.conf<<EOF
/usr/local/lib64
/usr/local/lib
/usr/lib
/usr/lib64
EOF
    ldconfig

    wget -c http://cn2.php.net/get/php-${PHPVER}.tar.gz/from/this/mirror -O php-${PHPVER}.tar.gz
    tar zxf php-${PHPVER}.tar.gz
    cd php-${PHPVER}
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
                --disable-rpath \
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
    make && make install

    ln -sf /usr/local/php/bin/php /usr/local/bin/php
    ln -sf /usr/local/php/bin/phpize /usr/local/bin/phpize
    ln -sf /usr/local/php/bin/pear /usr/local/bin/pear
    ln -sf /usr/local/php/bin/pecl /usr/local/bin/pecl
    ln -sf /usr/local/php/sbin/php-fpm /usr/local/bin/php-fpm
    rm -f /usr/local/php/conf.d/*

    echo_blue "Copy new php configure file..."
    mkdir -p /usr/local/php/{etc,conf.d}
    cp php.ini-production /usr/local/php/etc/php.ini

    # php extensions
    echo_blue "Modify php.ini......"
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

    echo_yellow "是否启用 Opcache? "
    read -r -p "是(Y)/否(N): " OPCACHE
    if [[ ${OPCACHE} = "y" || ${OPCACHE} = "Y" ]]; then
        sed -i "s/;opcache.enable=1/opcache.enable=1/g" /usr/local/php/etc/php.ini
        sed -i "s/;opcache.enable_cli=1/opcache.enable_cli=1/g" /usr/local/php/etc/php.ini
        sed -i "s/;opcache.memory_consumption=128/opcache.memory_consumption=192/g" /usr/local/php/etc/php.ini
        sed -i "s/;opcache.max_accelerated_files=.*/opcache.max_accelerated_files=7963/g" /usr/local/php/etc/php.ini
        sed -i "s/;opcache.interned_strings_buffer=.*/opcache.interned_strings_buffer=16/g" /usr/local/php/etc/php.ini
        sed -i "s/;opcache.revalidate_freq=.*/opcache.revalidate_freq=0/g" /usr/local/php/etc/php.ini
        echo "zend_extension=opcache.so" >> /usr/local/php/etc/php.ini

        echo_yellow "当前服务器是否生产服务器（如选择是，每次更新 PHP 代码后请重启 php-fpm）? "
        read -r -p "是(Y)/否(N): " PHPPROD
        if [[ ${PHPPROD} = "y" || ${PHPPROD} = "Y" ]]; then
            sed -i "s/;opcache.validate_timestamps=.*/opcache.validate_timestamps=0/g" /usr/local/php/etc/php.ini
        fi
    fi

    pear config-set php_ini /usr/local/php/etc/php.ini
    pecl config-set php_ini /usr/local/php/etc/php.ini

    echo_yellow "是否安装 Composer? "
    read -r -p "是(Y)/否(N): " INSCPR
    if [[ ${INSCPR} = "y" || ${INSCPR} = "Y" ]]; then
        curl -sS --connect-timeout 30 -m 60 https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
        echo_blue "composer --version"
    fi

    echo_blue "Creating new php-fpm configure file..."
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

    echo_blue "Copy php-fpm init.d file..."
    cp sapi/fpm/init.d.php-fpm /etc/init.d/php-fpm
    sed -i "s/echo \" done\"/echo -e \"\\\\033[32m[OK]\\\\033[0m\"/g" /etc/init.d/php-fpm
    sed -i "s/echo \" failed\"/echo -e \"\\\\033[31m[Fail]\\\\033[0m\"/g" /etc/init.d/php-fpm
    sed -i "s/echo \" failed. Use force-quit\"/echo -e \"\\\\033[31m[Fail]\\\\033[0m \\\\033[33mUse force-quit\\\\033[0m\"/g" /etc/init.d/php-fpm
    chmod +x /etc/init.d/php-fpm
    chkconfig --add php-fpm
    chkconfig php-fpm on

    cd ..

    if [ -s /usr/local/redis/bin/redis-server ]; then
        wget -c https://github.com/phpredis/phpredis/archive/master.zip -O phpredis-master.zip
        unzip phpredis-master.zip
        cd phpredis-master
        phpize
        ./configure --with-php-config=/usr/local/php/bin/php-config
        make && make install

        echo "extension=redis.so" >> /usr/local/php/etc/php.ini
        cd ..
    fi

    echo_yellow "是否安装 MySQL 扩展（不建议安装，请使用最新版如 MySQLi 扩展）? "
    read -r -p "是(Y)/否(N): " PHPMYSQL
    if [[ ${PHPMYSQL} = "y" || ${PHPMYSQL} = "Y" ]]; then
        wget -c --no-cookie "http://git.php.net/?p=pecl/database/mysql.git;a=snapshot;h=647c933b6cc8f3e6ce8a466824c79143a98ee151;sf=tgz" -O php-mysql.tar.gz
        mkdir ./php-mysql
        tar xzf php-mysql.tar.gz -C ./php-mysql --strip-components 1
        cd php-mysql
        phpize
        ./configure  --with-php-config=/usr/local/php/bin/php-config --with-mysql=mysqlnd
        make && make install
        echo "extension=mysql.so" >> /usr/local/php/etc/php.ini
        # sed -i "s/^error_reporting = .*/error_reporting = E_ALL & ~E_NOTICE & ~E_DEPRECATED/g" /usr/local/php/etc/php.ini
        cd ..
    fi

    sed -i "s#;open_basedir =#open_basedir = ${INSHOME}/wwwroot#g" /usr/local/php/etc/php.ini

    ins_end "php"
}

install_redis() {
    ins_begin "Redis"

    echo_yellow "请输入 Redis 安全密码（直接回车将自动生成密码）"
    read -r -p "密码: " REDISPWD
    if [ "${REDISPWD}" = "" ]; then
        echo_red "没有输入密码，将采用默认密码。"
        REDISPWD=$(echo "zsenClub#$RANDOM" | md5sum | cut -d " " -f 1)
    fi
    echo_green "Redis 安全密码为(请记下来): ${REDISPWD}"

    groupadd redis
    useradd -r -g redis -s /bin/false redis
    mkdir -p /usr/local/redis/{etc,run}
    mkdir -p ${INSHOME}/database/redis
    chown -R redis:redis ${INSHOME}/database/redis

    wget -c http://download.redis.io/releases/redis-${REDISVER}.tar.gz
    tar zxf redis-${REDISVER}.tar.gz
    cd redis-${REDISVER}
    make && make PREFIX=/usr/local/redis install

    cp redis.conf  /usr/local/redis/etc/
    sed -i "s/daemonize no/daemonize yes/g" /usr/local/redis/etc/redis.conf
    sed -i "s/^# bind 127.0.0.1/bind 127.0.0.1/g" /usr/local/redis/etc/redis.conf
    sed -i "s#^pidfile /var/run/redis_6379.pid#pidfile /usr/local/redis/run/redis.pid#g" /usr/local/redis/etc/redis.conf
    sed -i "s/^# requirepass.*/requirepass ${REDISPWD}/g" /usr/local/redis/etc/redis.conf
    sed -i "s#logfile ""#logfile ${INSHOME}/wwwlogs/redis.log#g" /usr/local/redis/etc/redis.conf
    sed -i "s#dir ./#dir ${INSHOME}/database/redis/#g" /usr/local/redis/etc/redis.conf

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

redis_pid() {
    echo \`ps aux | grep \${REDISPORT} | grep -v grep | awk '{ print \$2 }'\`
}

start() {
    pid=\$(redis_pid)
    # if [ -f "\$PIDFILE" ]; then
    echo -n "Starting \$DESC: "
    if [ -n "\$pid" ]; then
        echo -e "\\033[33m[is running with pid: \$pid]\\033[0m"
    else
        /bin/su -m -c "cd \$BASEDIR/bin && \$EXEC \$CONF" \$REDIS_USER
        if [ \$? -eq 0 ]; then
            echo -e "\\033[32m[OK]\\033[0m"
        else
            echo -e "\\033[31m[Fail]\\033[0m"
        fi
    fi
}

status() {
    pid=\$(redis_pid)
    echo -n "\$DESC status: "
    # if [ -f "\$PIDFILE" ]; then
    if [ -n "\$pid" ]; then
        echo -e "\\033[32m[is running with pid: \$pid]\\033[0m"
    else
        echo -e "\\033[33m[is not running]\\033[0m"
    fi
}

stop() {
    pid=\$(redis_pid)
    echo -n "Stopping \$DESC: "
    if [ -n "\$pid" ]; then
        \$REDIS_CLI -p \$REDISPORT -a ${REDISPWD} shutdown
        if [ \$? -eq 0 ]; then
            echo -e "\\033[32m[OK]\\033[0m"
        else
            echo -e "\\033[31m[Fail]\\033[0m"
        fi
    else
        echo "\\033[33m[is not running]\\033[0m"
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
        echo -n "Kill \$DESC: "
        killall redis-server
        pid=\$(redis_pid)
        if [ -n "\$pid" ]; then
            echo -e "\\033[31m[Fail]\\033[0m"
        else
            echo -e "\\033[32m[OK]\\033[0m"
        fi
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

    ins_end "redis-server"
    cd ..
}

register_management-tool() {
    while :;do
        echo_yellow "是否要自定义管理工具名称(如不需要，请直接回车)? "
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
    wget https://raw.githubusercontent.com/zsenliao/initServer/master/pnmp -O /usr/local/bin/${MYNAME}
    sed -i "s|/home/|${INSHOME}/|g" /usr/local/bin/${MYNAME}
    sed -i "s|/pnmp/|${MYNAME}/|g" /usr/local/bin/${MYNAME}
    chmod +x /usr/local/bin/${MYNAME}

    if [[ ${NGINX} = "y" || ${NGINX} = "Y" ]]; then
        echo_yellow "是否要添加默认站点? "
        read -r -p "是(Y)/否(N): " ADDHOST
        if [[ ${ADDHOST} = "y" || ${ADDHOST} = "Y" ]]; then
            ${MYNAME} vhost add
        fi
    fi
}

clean_install() {
    echo_yellow "是否清理安装文件?"
    read -r -p "全部(A)是(Y)/否(N): " CLRANINS
    if [[ ${CLRANINS} = "y" || ${CLRANINS} = "Y" ]]; then
        cd ${CUR_DIR}/src
        for deldir in `ls .`
        do
            if [ -d $deldir ]; then
                rm -rf $deldir
            fi
        done
        cd ${CUR_DIR}
        echo_blue "安装文件清理完成。"
    elif [[ ${CLRANINS} = "a" || ${CLRANINS} = "A" ]]; then
        cd ${CUR_DIR}
        rm -rf src
        echo_blue "安装文件清理完成。"
    fi

    echo_green "服务器环境安装配置成功！"
    echo_blue "可以通过 ${MYNAME} vhost add 来添加网站"
    echo_blue "环境管理命令："
    ${MYNAME}
    echo " "
    echo_blue "网站程序目录：${INSHOME}/wwwroot"
    echo_blue "MySQL 数据库目录：${INSHOME}/database/mysql"
    echo_blue "Redis 数据库目录：${INSHOME}/database/redis"
    echo_blue "日志目录：${INSHOME}/wwwlogs"
    echo_blue "配置文件目录：${INSHOME}/wwwconf"
    echo " "
    echo_blue "MySQL ROOT 密码：${DBROOTPWD}"
    echo_blue "Redis 安全密码：${REDISPWD}"
    echo_red "请牢记以上密码！"
    echo " "

    ${MYNAME} status
    if [ -s /bin/ss ]; then
        ss -ntl
    else
        netstat -ntl
    fi
    stop_time=$(date +%s)
    echo_blue "总共用时 $(((stop_time-start_time)/60)) 分"
}

if [[ $(id -u) != "0" ]]; then
    echo_red "错误提示: 请在 root 账户下运行此脚本!"
    exit 1
fi

set_time_zone
check_hosts
get_os_name
if [[ ${OSNAME} != "CentOS" ]]; then
    echo_red "此脚本仅适用于 CentOS 系统！"
    exit 1
fi
systemctl start firewalld

# 显示磁盘空间
df -h

echo_yellow "请输入安装目录（比如 /home 或 /data），默认 /data"
read -r -p "请输入: " INSHOME
if [ -z "${INSHOME}" ]; then
    INSHOME=/data
fi
echo_blue "系统安装目录：${INSHOME}"
mkdir -p ${INSHOME}

mkdir -p ${CUR_DIR}/src
cd ${CUR_DIR}/src

disable_selinux

yum update
yum upgrade -y
yum install -y wget gcc make curl unzip

echo_yellow "是否修改 hostname?"
read -r -p "是(Y)/否(N): " SETHOST
if [[ ${SETHOST} = "y" || ${SETHOST} = "Y" ]]; then
    set_host_name
fi

echo_yellow "是否添加用户?"
read -r -p "是(Y)/否(N): " ADDUSER
if [[ ${ADDUSER} = "y" || ${ADDUSER} = "Y" ]]; then
    add_user
fi

show_ver "cmake --version" "CMake"
if [[ $VER != "" ]]; then
    read -r -p "是(Y)/否(N): " INSCMAKE
    if [[ ${INSCMAKE} = "y" || ${INSCMAKE} = "Y" ]]; then
        install_cmake
    fi
else
    install_cmake
fi

show_ver "git --version" "Git"
if [[ $VER != "" ]]; then
    read -r -p "是(Y)/否(N): " INSGIT
    if [[ ${INSGIT} = "y" || ${INSGIT} = "Y" ]]; then
        install_git
    fi
else
    install_git
fi

show_ver "zsh --version" "zsh"
if [[ $VER != "" ]]; then
    read -r -p "是(Y)/否(N): " INSZSH
    if [[ ${INSZSH} = "y" || ${INSZSH} = "Y" ]]; then
        install_zsh
    fi
else
    install_zsh
fi

show_ver "vim --version | head -n 1" "vim"
read -r -p "是(Y)/否(N): " INSVIM
if [[ ${INSVIM} = "y" || ${INSVIM} = "Y" ]]; then
    install_vim
fi

show_ver "python3 --version" "Python3"
read -r -p "是(Y)/否(N): " INSPYTHON3
if [[ ${INSPYTHON3} = "y" || ${INSPYTHON3} = "Y" ]]; then
    install_python3
    install_uwsgi
fi

show_ver "redis-server --version" "Redis"
read -r -p "是(Y)/否(N): " INSREDIS
if [[ ${INSREDIS} = "y" || ${INSREDIS} = "Y" ]]; then
    install_redis
fi

show_ver "php --version" "PHP"
read -r -p "是(Y)/否(N): " INSPHP
if [[ ${INSPHP} = "y" || ${INSPHP} = "Y" ]]; then
    install_php
fi

show_ver "mysql --version" "MySQL"
read -r -p "是(Y)/否(N): " INSMYSQL
if [[ ${INSMYSQL} = "y" || ${INSMYSQL} = "Y" ]]; then
    install_mysql
fi

show_ver "node --version" "Nodejs"
read -r -p "是(Y)/否(N): " INSNODEJS
if [[ ${INSNODEJS} = "y" || ${INSNODEJS} = "Y" ]]; then
    install_nodejs
fi

show_ver "nginx -v" "Nginx"
read -r -p "是(Y)/否(N): " NGINX
if [[ ${NGINX} = "y" || ${NGINX} = "Y" ]]; then
    install_nginx
fi

echo_yellow "是否安装 ikev2?"
read -r -p "是(Y)/否(N): " IKEV2
if [[ ${IKEV2} = "y" || ${IKEV2} = "Y" ]]; then
    install_ikev2
fi

echo_yellow "是否启用防火墙(默认启用)?"
read -r -p "是(Y)/否(N): " FIRE
if [[ ${FIRE} = "n" || ${FIRE} = "N" ]]; then
    systemctl stop firewalld
    systemctl disable firewalld
else
    systemctl enable firewalld
    firewall-cmd --list-all
fi

register_management-tool
clean_install
