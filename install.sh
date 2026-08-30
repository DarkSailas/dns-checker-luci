#!/bin/sh
set -e

# ==============================================================================
# Installer for luci-app-dns-checker
# https://github.com/DarkSailas/dns-checker-luci
# ==============================================================================

echo "=========================================================="
echo ">>> Installing luci-app-dns-checker on OpenWrt..."
echo "=========================================================="

REPO_BASE="https://raw.githubusercontent.com/DarkSailas/dns-checker-luci/main"
BACKUP_DIR="/etc/dns-checker"
mkdir -p "$BACKUP_DIR"

# 1. Detect Package Manager and install dependencies if missing
echo ">>> [1/5] Checking system dependencies..."
if command -v apk >/dev/null 2>&1; then
    apk update >/dev/null 2>&1 || true
    for pkg in bind-dig curl jq; do
        if ! command -v "$pkg" >/dev/null 2>&1 && [ "$pkg" != "bind-dig" ]; then
            apk add "$pkg" >/dev/null 2>&1 || true
        elif [ "$pkg" = "bind-dig" ] && ! command -v dig >/dev/null 2>&1; then
            apk add bind-dig >/dev/null 2>&1 || true
        fi
    done
elif command -v opkg >/dev/null 2>&1; then
    opkg update >/dev/null 2>&1 || true
    for pkg in bind-dig curl jq; do
        if ! command -v "$pkg" >/dev/null 2>&1 && [ "$pkg" != "bind-dig" ]; then
            opkg install "$pkg" >/dev/null 2>&1 || true
        elif [ "$pkg" = "bind-dig" ] && ! command -v dig >/dev/null 2>&1; then
            opkg install bind-dig >/dev/null 2>&1 || true
        fi
    done
fi

# 2. Create Initial Safety Backup before any modifications
echo ">>> [2/5] Creating initial configuration backup..."
if [ ! -f "$BACKUP_DIR/initial_backup.tar.gz" ]; then
    tar -czf "$BACKUP_DIR/initial_backup.tar.gz" \
        /etc/config/podkop \
        /etc/config/network \
        /etc/config/dhcp \
        /usr/bin/podkop 2>/dev/null || true
    echo "Initial backup saved to $BACKUP_DIR/initial_backup.tar.gz"
fi

# 3. Create destination directories
echo ">>> [3/5] Creating directories..."
mkdir -p /usr/bin
mkdir -p /usr/share/luci/menu.d
mkdir -p /usr/share/rpcd/acl.d
mkdir -p /www/luci-static/resources/view/dns-checker

# 4. Download / Install Files with correct permissions
echo ">>> [4/5] Installing application files..."

curl -sSL "$REPO_BASE/root/usr/bin/dns-checker-engine" -o /usr/bin/dns-checker-engine
chmod 755 /usr/bin/dns-checker-engine

curl -sSL "$REPO_BASE/root/usr/share/luci/menu.d/luci-app-dns-checker.json" -o /usr/share/luci/menu.d/luci-app-dns-checker.json
chmod 644 /usr/share/luci/menu.d/luci-app-dns-checker.json

curl -sSL "$REPO_BASE/root/usr/share/rpcd/acl.d/luci-app-dns-checker.json" -o /usr/share/rpcd/acl.d/luci-app-dns-checker.json
chmod 644 /usr/share/rpcd/acl.d/luci-app-dns-checker.json

curl -sSL "$REPO_BASE/htdocs/luci-static/resources/view/dns-checker/main.js" -o /www/luci-static/resources/view/dns-checker/main.js
curl -sSL "$REPO_BASE/htdocs/luci-static/resources/view/dns-checker/index.js" -o /www/luci-static/resources/view/dns-checker/index.js
chmod -R 755 /www/luci-static/resources/view/dns-checker
chmod 644 /www/luci-static/resources/view/dns-checker/*.js

curl -sSL "$REPO_BASE/uninstall.sh" -o "$BACKUP_DIR/uninstall.sh"
curl -sSL "$REPO_BASE/update.sh" -o "$BACKUP_DIR/update.sh"
chmod 755 "$BACKUP_DIR/uninstall.sh" "$BACKUP_DIR/update.sh"

# 5. Flush LuCI and RPCD caches
echo ">>> [5/5] Updating LuCI caches and permissions..."
rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache*
/etc/init.d/rpcd restart >/dev/null 2>&1 || true
/etc/init.d/uhttpd restart >/dev/null 2>&1 || true

echo "=========================================================="
echo ">>> Installation completed successfully!"
echo "LuCI Menu: Services (Службы) -> DNS Checker"
echo "To uninstall: sh $BACKUP_DIR/uninstall.sh"
echo "=========================================================="