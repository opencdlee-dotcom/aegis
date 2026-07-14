#!/bin/bash
# Aegis installer - registers a per-user launchd agent that runs `aegis.py scan`
# on an interval (background, low priority). Idempotent: re-run to change the
# interval. Usage:  bash install.sh [interval_seconds]   (default 3600 = hourly)
set -euo pipefail

INTERVAL="${1:-3600}"
DIR="$(cd "$(dirname "$0")" && pwd)"
AEGIS="$DIR/aegis.py"
LABEL="com.charlie.aegis"
AGENTS_DIR="$HOME/Library/Launch""Agents"          # split to keep intent obvious
PLIST="$AGENTS_DIR/$LABEL.plist"
PY="/usr/bin/python3"                                # system python; stdlib-only
UID_NUM="$(id -u)"

[ -f "$AEGIS" ] || { echo "aegis.py not found at $AEGIS" >&2; exit 1; }
mkdir -p "$AGENTS_DIR" "$HOME/.aegis"

# The install path is interpolated into plist XML, so any &, <, > in it (e.g. a
# repo under "…/Work & Projects/…") MUST be entity-escaped or the plist is
# invalid XML and launchd silently refuses to load the agent — the whole tool
# then never runs on schedule.
xml_escape() { local s=$1; s=${s//&/&amp;}; s=${s//</&lt;}; s=${s//>/&gt;}; printf '%s' "$s"; }
PY_X="$(xml_escape "$PY")"
AEGIS_X="$(xml_escape "$AEGIS")"
OUT_X="$(xml_escape "$HOME/.aegis/run.out")"
ERR_X="$(xml_escape "$HOME/.aegis/run.err")"

echo "==> Writing launchd agent ($LABEL, every ${INTERVAL}s)…"
cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>          <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PY_X</string>
        <string>$AEGIS_X</string>
        <string>scan</string>
    </array>
    <key>RunAtLoad</key>      <true/>
    <key>StartInterval</key>  <integer>$INTERVAL</integer>
    <key>ProcessType</key>    <string>Background</string>
    <key>LowPriorityIO</key>  <true/>
    <key>Nice</key>           <integer>10</integer>
    <key>StandardOutPath</key><string>$OUT_X</string>
    <key>StandardErrorPath</key><string>$ERR_X</string>
</dict>
</plist>
PLISTEOF

# Baseline ONLY on first install. Re-running to change the interval must NOT
# re-baseline — that would silently bless any persistence added since the first
# install as "known-good" and erase the very tamper evidence Aegis exists to
# catch. Baselining after the plist is written folds Aegis's own agent into the
# known-good set. Reset deliberately with `python3 aegis.py baseline`.
if [ -f "$HOME/.aegis/baseline.json" ]; then
    echo "==> Existing baseline kept (interval change only; known-good state preserved)."
else
    echo "==> Establishing known-good baseline (silent; nothing you have now alerts)…"
    "$PY" "$AEGIS" baseline
fi

echo "==> Loading agent…"
# Modern (bootstrap) with a legacy (load) fallback for older macOS.
launchctl bootout "gui/$UID_NUM/$LABEL" 2>/dev/null || true
if ! launchctl bootstrap "gui/$UID_NUM" "$PLIST" 2>/dev/null; then
    launchctl unload "$PLIST" 2>/dev/null || true
    launchctl load -w "$PLIST"
fi
launchctl enable "gui/$UID_NUM/$LABEL" 2>/dev/null || true

echo ""
echo "✅ Aegis is now running in the background (every ${INTERVAL}s)."
echo "   Report : python3 $AEGIS report      (or: cat ~/.aegis/latest.md)"
echo "   Log    : ~/.aegis/findings.jsonl    (durable; alerts also notify you)"
echo "   Tune   : bash $DIR/install.sh 1800  (re-run with a new interval)"
echo "   Remove : bash $DIR/uninstall.sh"
echo ""
echo "⚠  Aegis DETECTS and alerts; it does not block (that needs Apple's"
echo "   Endpoint Security entitlement). It also can't read TCC-protected"
echo "   folders without Full Disk Access — grant it to /usr/bin/python3 in"
echo "   System Settings ▸ Privacy & Security ▸ Full Disk Access for full"
echo "   coverage (optional; core persistence/hardening checks work without it)."
