#!/bin/bash
# Aegis uninstaller - removes the launchd agent. Leaves ~/.aegis state intact
# (delete it yourself with `rm -rf ~/.aegis` if you want a clean slate).
set -euo pipefail

LABEL="com.charlie.aegis"
PLIST="$HOME/Library/Launch""Agents/$LABEL.plist"
UID_NUM="$(id -u)"

launchctl bootout "gui/$UID_NUM/$LABEL" 2>/dev/null || true
launchctl unload "$PLIST" 2>/dev/null || true
rm -f "$PLIST"

echo "✅ Aegis agent removed. State kept at ~/.aegis (rm -rf to purge)."
