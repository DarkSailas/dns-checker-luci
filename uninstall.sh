#!/bin/sh
# ==============================================================================
# Uninstaller for luci-app-dns-checker
# https://github.com/DarkSailas/dns-checker-luci
# ==============================================================================

set -e

BACKUP_DIR="/etc/dns-checker"
RESTORE_CONFIG=1

for arg in "$@"; do
    case "$arg" in
        --no-restore) RESTORE_CONFIG=0 ;;
    esac
done

echo "=========================================================="
echo ">>> Removing luci-app-dns-checker..."
echo "=========================================================="

if [ "$RESTORE_CONFIG" -eq 1 ] && [ -f "$BACKUP_DIR/initial_backup.tar.gz" ]; then
    echo ">>> Restoring original network and podkop configuration..."
    tar -xzf "$BACKUP_DIR/initial_backup.tar.gz" -C / 2>/dev/null || true
    /etc/init.d/dnsmasq restart >/dev/null 2>&1 || true
    /etc/init.d/podkop restart >/dev/null 2>&1 || true
    echo ">>> Initial configuration successfully restored!"
else
    echo ">>> Preserving current network and podkop configuration."
fi

echo ">>> Removing application files..."
rm -f /usr/bin/dns-checker-engine
rm -f /usr/share/luci/menu.d/luci-app-dns-checker.json
rm -f /usr/share/rpcd/acl.d/luci-app-dns-checker.json
rm -rf /www/luci-static/resources/view/dns-checker
rm -rf /etc/config/dns-checker
rm -rf "$BACKUP_DIR"

echo ">>> Cleaning LuCI caches..."
rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache*
/etc/init.d/rpcd restart >/dev/null 2>&1 || true
/etc/init.d/uhttpd restart >/dev/null 2>&1 || true

echo "=========================================================="
echo ">>> luci-app-dns-checker has been completely removed."
echo "=========================================================="