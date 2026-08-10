#!/bin/bash
# 软件工具集 - 一键部署脚本
# 用法: sudo bash deploy.sh [端口号, 默认 8104]
#
# 依赖: nginx, python3, pip3, git
# 部署架构: nginx(静态+代理) + Flask(API)

set -e

PORT=${1:-8104}
FLASK_PORT=$((PORT + 1))
PROJECT_DIR="/data/project/dct/html-tools"

echo "========================================="
echo "  软件工具集 部署脚本"
echo "  Web 端口: $PORT"
echo "  API 端口: $FLASK_PORT"
echo "========================================="

# ─── 1. 检查依赖 ──────────────────────────────────────
check_deps() {
    local missing=0
    for cmd in nginx python3 git; do
        if ! command -v $cmd &>/dev/null; then
            echo "[错误] 未找到 $cmd，请先安装"
            missing=1
        fi
    done
    [ $missing -ne 0 ] && exit 1
    echo "[OK] 依赖检查通过"
}

# ─── 1.5 创建虚拟环境 ─────────────────────────────────
setup_venv() {
    local VENV_DIR="$PROJECT_DIR/venv"
    if [ ! -d "$VENV_DIR" ]; then
        echo "[提示] 创建 Python 虚拟环境..."
        python3 -m venv "$VENV_DIR"
    fi
    source "$VENV_DIR/bin/activate"
    echo "[提示] 安装 Python 依赖 (venv)..."
    PYVER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PYTHON_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
    if [ "$PYTHON_MINOR" -le 6 ]; then
        echo "[提示] 检测到 Python 3.6，安装兼容版 Flask 2.0.3..."
        pip install --quiet "Flask==2.0.3" "Werkzeug==2.0.3" "Jinja2==3.0.3"
    elif [ "$PYTHON_MINOR" -le 7 ]; then
        echo "[提示] 检测到 Python 3.7，安装兼容版 Flask 2.2.x..."
        pip install --quiet "Flask==2.2.5" "Werkzeug==2.2.3"
    else
        echo "[提示] 安装最新 Flask + Pillow (验证码)..."
        pip install --quiet flask pillow
    fi
    echo "[OK] 虚拟环境就绪 ($VENV_DIR)"
}

# ─── 2. 克隆/更新项目 ─────────────────────────────────
setup_project() {
    mkdir -p $(dirname $PROJECT_DIR)
    if [ -d "$PROJECT_DIR/.git" ]; then
        echo "[提示] 项目已存在，执行更新..."
        cd $PROJECT_DIR && git pull
    else
        echo "[提示] 克隆项目到 $PROJECT_DIR ..."
        git clone <仓库地址> $PROJECT_DIR
    fi
    cd $PROJECT_DIR
    # 创建上传目录
    mkdir -p software_files
    echo "[OK] 项目就绪"
}

# ─── 3. 配置 Nginx ───────────────────────────────────
setup_nginx() {
    echo "[提示] 生成 Nginx 配置..."
    cat > /etc/nginx/conf.d/html-tools.conf << NGINX_EOF
server {
    listen ${PORT};
    server_name _;

    root ${PROJECT_DIR};
    index index.html;

    gzip on;
    gzip_types text/css application/javascript application/json image/svg+xml text/xml application/xml;
    gzip_min_length 1024;

    # API 代理到 Flask
    location /api/ {
        proxy_pass http://127.0.0.1:${FLASK_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Connection "";
        proxy_http_version 1.1;
        client_max_body_size 0;
        proxy_connect_timeout 60s;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        proxy_next_upstream error timeout;
    }

    # 管理后台重定向
    location = /admin/ {
        return 302 /admin/login.html;
    }

    location = /index.html {
        etag off;
        if_modified_since off;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
        add_header Pragma "no-cache";
        add_header Expires "0";
        try_files \$uri =404;
    }

    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    location /workers/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    location ~* \.(js|css|svg|txt|ico|png|jpg|jpeg|gif|webp|woff|woff2|ttf|eot|xml|json)\$ {
        etag off;
        if_modified_since off;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
        add_header Pragma "no-cache";
        add_header Expires "0";
    }

    location /software/ {
        try_files \$uri \$uri/ =404;
    }

    location /admin/ {
        try_files \$uri \$uri/ /admin/login.html;
    }

    location /tools/ {
        try_files \$uri \$uri/ /tools/\$uri =404;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    add_header X-Content-Type-Options "nosniff";
    add_header X-Frame-Options "SAMEORIGIN";
}
NGINX_EOF

    nginx -t && nginx -s reload 2>/dev/null || nginx
    echo "[OK] Nginx 配置完成 (端口 $PORT)"
}

# ─── 4. 防火墙 ───────────────────────────────────────
setup_firewall() {
    echo "[提示] 配置防火墙规则..."
    # iptables (如果策略是 DROP)
    if command -v iptables &>/dev/null; then
        iptables -C INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null || \
            iptables -I INPUT 1 -p tcp --dport $PORT -j ACCEPT
        # 尝试持久化
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
    fi
    # firewalld (CentOS/RHEL)
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=${PORT}/tcp 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    fi
    # ufw (Ubuntu/Debian)
    if command -v ufw &>/dev/null; then
        ufw allow $PORT/tcp 2>/dev/null || true
    fi
    echo "[OK] 防火墙配置完成"
}

# ─── 5. 启动 Flask ───────────────────────────────────
start_flask() {
    cd $PROJECT_DIR

    # 检查是否已在运行
    if ss -tlnp 2>/dev/null | grep -q ":${FLASK_PORT} " || \
       netstat -tlnp 2>/dev/null | grep -q ":${FLASK_PORT} "; then
        echo "[提示] Flask 已在运行 (端口 $FLASK_PORT)"
        return
    fi

    echo "[提示] 启动 Flask 后端 (端口 $FLASK_PORT)..."

    if command -v supervisorctl &>/dev/null; then
        # 如果有 supervisor，使用它管理
        echo "[提示] 使用 supervisor 管理..."
        # 需要预配置 supervisor conf
    else
        nohup $PROJECT_DIR/venv/bin/python3 server.py > /tmp/html-tools-server.log 2>&1 &
        echo $! > /tmp/html-tools-server.pid
        sleep 2
        if ss -tlnp 2>/dev/null | grep -q ":${FLASK_PORT} " || \
           netstat -tlnp 2>/dev/null | grep -q ":${FLASK_PORT} "; then
            echo "[OK] Flask 启动成功 (PID: $(cat /tmp/html-tools-server.pid))"
        else
            echo "[错误] Flask 启动失败，请查看 /tmp/html-tools-server.log"
            exit 1
        fi
    fi
}

# ─── 6. 设置管理密码 ─────────────────────────────────
setup_admin_password() {
    if [ ! -f "$PROJECT_DIR/.admin_config" ]; then
        echo "[提示] 设置管理员密码（默认: admin123）..."
        read -sp "请输入管理员密码: " ADMIN_PW
        echo ""
        if [ -z "$ADMIN_PW" ]; then
            ADMIN_PW="admin123"
        fi
        HASH=$(python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('${ADMIN_PW}'))")
        echo '{"password_hash": "'"$HASH"'", "force_change": false}' > $PROJECT_DIR/.admin_config
        chmod 600 $PROJECT_DIR/.admin_config
        echo "[OK] 管理员密码已设置"
    else
        echo "[提示] 管理员密码已配置 (.admin_config)"
        echo "如需修改: 编辑 $PROJECT_DIR/.admin_config"
    fi
}

# ─── 主流程 ──────────────────────────────────────────
main() {
    check_deps
    setup_project
    setup_venv
    setup_nginx
    setup_firewall
    start_flask
    setup_admin_password

    echo ""
    echo "========================================="
    echo "  ✅ 部署完成！"
    echo "========================================="
    echo ""
    echo "  访问地址: http://<服务器IP>:$PORT/"
    echo "  管理后台: http://<服务器IP>:$PORT/admin/"
    echo "  默认密码: admin123"
    echo ""
    echo "  管理命令:"
    echo "    重启 Flask:  kill \$(cat /tmp/html-tools-server.pid) && nohup $PROJECT_DIR/venv/bin/python3 $PROJECT_DIR/server.py > /tmp/html-tools-server.log 2>&1 &"
    echo "    查看日志:    tail -f /tmp/html-tools-server.log"
    echo "    修改端口:    编辑 /etc/nginx/conf.d/html-tools.conf 中的 listen 和 proxy_pass"
    echo ""
}

main "$@"
