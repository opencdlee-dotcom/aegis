#!/bin/bash
# Aegis uninstaller. Evidence/state is retained by default; `--purge` is the
# explicit irreversible option.
set -euo pipefail
umask 077

LABEL="com.charlie.aegis"
PLIST="$HOME/Library/Launch""Agents/$LABEL.plist"
UID_NUM="$(/usr/bin/id -u)"
RUNTIME="$HOME/.aegis/aegis.py"
PURGE="${1:-}"
if [ "$#" -gt 1 ] || { [ -n "$PURGE" ] && [ "$PURGE" != "--purge" ]; }; then
    echo "usage: bash uninstall.sh [--purge]" >&2; exit 1;
fi

/bin/launchctl bootout "gui/$UID_NUM/$LABEL" 2>/dev/null || true
/bin/launchctl unload "$PLIST" 2>/dev/null || true
if [ -f "$RUNTIME" ]; then
    /usr/bin/python3 "$RUNTIME" mark-uninstalled 2>/dev/null || true
fi
/bin/rm -f "$PLIST" "$RUNTIME"

if [ "$PURGE" = "--purge" ]; then
    /bin/rm -rf "$HOME/.aegis"
    echo "✅ Aegis agent and all local evidence/state purged."
else
    echo "✅ Aegis agent removed. Evidence/state kept at ~/.aegis."
    echo "   Explicit irreversible purge: bash uninstall.sh --purge"
fi
