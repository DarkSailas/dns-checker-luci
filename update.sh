#!/bin/sh
# ==============================================================================
# Updater for luci-app-dns-checker
# https://github.com/DarkSailas/dns-checker-luci
# ==============================================================================

set -e

REPO_BASE="https://raw.githubusercontent.com/DarkSailas/dns-checker-luci/main"
BACKUP_DIR="/etc/dns-checker"

echo "=========================================================="
echo ">>> Updating luci-app-dns-checker..."
echo "=========================================================="

mkdir -p /www/luci-static/resources/view/dns-checker

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

curl -sSL "$REPO_BASE/uninstall.sh" -o "$BACKUP_DIR/uninstall.sh" 2>/dev/null || true
curl -sSL "$REPO_BASE/update.sh" -o "$BACKUP_DIR/update.sh" 2>/dev/null || true
chmod 755 "$BACKUP_DIR/uninstall.sh" "$BACKUP_DIR/update.sh" 2>/dev/null || true

echo ">>> Refreshing LuCI caches..."
rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache*
/etc/init.d/rpcd restart >/dev/null 2>&1 || true
/etc/init.d/uhttpd restart >/dev/null 2>&1 || true

echo "=========================================================="
echo ">>> luci-app-dns-checker successfully updated!"
echo "=========================================================="