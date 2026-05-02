#!/bin/bash
# اسکریپت یک‌بار نصب NovaProxy (همراه با Caddy و Cloudflare Tunnel)

set -e

# ۱. تنظیم رمز احراز هویت
echo -n "لطفاً رمز احراز هویت را وارد کنید (در صورت Enter زدن، به‌طور خودکار تولید می‌شود): "
read input_secret
if [ -z "$input_secret" ]; then
    AUTH_SECRET="SNI_$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
else
    AUTH_SECRET="$input_secret"
fi

LISTEN_PORT=443
INSTALL_DIR="/opt/sni-server"

echo "رمز احراز هویت انتخاب‌شده: $AUTH_SECRET"
echo "=== نصب‌کننده سرور VPS NovaProxy (sni-server) ==="

# ۲. بررسی دسترسی root
if [[ $EUID -ne 0 ]]; then
   echo "این اسکریپت باید با دسترسی root اجرا شود"
   exit 1
fi

# ۳. نصب Caddy
if ! command -v caddy &> /dev/null; then
    echo "در حال نصب Caddy..."
    apt install -y debian-keyring debian-archive-keyring apt-transport-https
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt update
    apt install -y caddy
fi

# ۴. نصب باینری sni-server (در اینجا فرض می‌شود فایل از قبل وجود دارد)
mkdir -p $INSTALL_DIR
# TODO: در محیط واقعی، باینری را از ریلیز دانلود کنید
# cp ./sni-server $INSTALL_DIR/

# ۵. ایجاد سرویس systemd
cat <<EOF > /etc/systemd/system/sni-server.service
[Unit]
Description=NovaProxy VPS Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/sni-server -port $LISTEN_PORT -secret $AUTH_SECRET
Restart=always
Environment=AUTH_SECRET=$AUTH_SECRET

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sni-server
# systemctl start sni-server

echo "=== نصب کامل شد ==="
echo "رمز احراز هویت: $AUTH_SECRET"
echo "پورت گوش‌دهی: $LISTEN_PORT"
echo "--------------------------------------------------"
echo "قالب آدرس مسیر: /{Token}/{TargetHost}/{Path}"
echo "نمونه درخواست: https://your.domain.com/$AUTH_SECRET/www.google.com/"
echo "--------------------------------------------------"
echo "نکته: اگر از Cloudflare Tunnel استفاده می‌کنید، دستور زیر را اجرا کنید:"
echo "  cloudflared tunnel run --token YOUR_TOKEN"
echo "و تونل را به آدرس http://localhost:$LISTEN_PORT هدایت کنید."
echo "پیکربندی پیشنهادی Caddy:"
echo "  caddy reverse-proxy --from your.domain.com --to localhost:$LISTEN_PORT"