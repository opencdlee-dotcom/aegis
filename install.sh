#!/bin/bash
# Aegis installer - registers a per-user launchd agent. Two modes, idempotent
# (re-run to change mode or interval):
#   bash install.sh [interval_seconds]        scan on an interval (default 3600)
#   bash install.sh watch [interval_seconds]  event-driven: kqueue rescan within
#                                             seconds of a change to a watched
#                                             path; [interval] = full-scan floor
#                                             (default 600). launchd KeepAlive.
set -euo pipefail
umask 077

MODE="scan"
if [ "${1:-}" = "watch" ]; then MODE="watch"; shift; fi
INTERVAL="${1:-$([ "$MODE" = "watch" ] && echo 600 || echo 3600)}"
[ "$#" -le 1 ] || { echo "usage: bash install.sh [watch] [interval_seconds]" >&2; exit 1; }
case "$INTERVAL" in
    ''|*[!0-9]*) echo "interval must be a whole number of seconds" >&2; exit 1;;
esac
[ "$INTERVAL" -ge 60 ] || { echo "interval must be at least 60 seconds" >&2; exit 1; }
DIR="$(cd "$(dirname "$0")" && pwd)"
AEGIS="$DIR/aegis.py"
LABEL="com.charlie.aegis"
AGENTS_DIR="$HOME/Library/Launch""Agents"          # split to keep intent obvious
PLIST="$AGENTS_DIR/$LABEL.plist"
PY="/usr/bin/python3"                                # system python; stdlib-only
PLUTIL="/usr/bin/plutil"
LAUNCHCTL="/bin/launchctl"
if [ -n "${AEGIS_TEST_LAUNCHCTL:-}" ]; then
    [ "${AEGIS_TESTING:-}" = "1" ] || {
        echo "AEGIS_TEST_LAUNCHCTL is test-only" >&2; exit 1;
    }
    LAUNCHCTL="$AEGIS_TEST_LAUNCHCTL"
fi
UID_NUM="$(/usr/bin/id -u)"
# The launchd agent runs this INSTALLED COPY, never the repo file. Reason: a repo
# under ~/Documents/… sits in a TCC-protected location, and a launchd-spawned
# python3 has no Full Disk Access, so it gets "Operation not permitted" merely
# OPENING the script — the whole monitor then fails every scheduled run with no
# signal (observed in the wild). ~/.aegis is NOT TCC-protected (the agent already
# writes its logs there), so a copy here runs with zero setup. Manual `python3
# aegis.py …` from the repo still works (your shell has TCC access). Trade-off:
# the agent runs a snapshot — RE-RUN install.sh after editing aegis.py to update it.
RUNTIME="$HOME/.aegis/aegis.py"
ERROR_FILE="$HOME/.aegis/install-error.txt"

install_failed() {
    rc=$?
    if [ "$rc" -ne 0 ]; then
        /bin/mkdir -p "$HOME/.aegis"
        printf 'Aegis install failed (exit %s) at %s\n' "$rc" "$(/bin/date -u)" > "$ERROR_FILE"
        echo "Aegis install failed; durable detail: $ERROR_FILE" >&2
    fi
    exit "$rc"
}
trap install_failed EXIT

[ -f "$AEGIS" ] || { echo "aegis.py not found at $AEGIS" >&2; exit 1; }
[ "$(/usr/bin/uname -s)" = "Darwin" ] || { echo "Aegis requires macOS" >&2; exit 1; }
[ -x "$PY" ] || { echo "system Python not found: $PY" >&2; exit 1; }
"$PY" -c 'import select, sqlite3, sys; assert sys.version_info >= (3, 9); assert hasattr(select, "kqueue")'
/bin/mkdir -p "$AGENTS_DIR" "$HOME/.aegis"
/bin/chmod 700 "$HOME/.aegis"
# Atomic refresh: launchd can see either the complete prior runtime or complete
# new runtime, never a partially copied program.
/bin/cp "$AEGIS" "$RUNTIME.new"
/bin/chmod 700 "$RUNTIME.new"
/bin/mv -f "$RUNTIME.new" "$RUNTIME"
"$PY" "$RUNTIME" preflight

# The install path is interpolated into plist XML, so any &, <, > in it (e.g. a
# repo under "…/Work & Projects/…") MUST be entity-escaped or the plist is
# invalid XML and launchd silently refuses to load the agent — the whole tool
# then never runs on schedule.
xml_escape() { local s=$1; s=${s//&/&amp;}; s=${s//</&lt;}; s=${s//>/&gt;}; printf '%s' "$s"; }
PY_X="$(xml_escape "$PY")"
AEGIS_X="$(xml_escape "$RUNTIME")"                   # agent runs the TCC-safe copy
OUT_X="$(xml_escape "$HOME/.aegis/run.out")"
ERR_X="$(xml_escape "$HOME/.aegis/run.err")"

# scan mode: launchd fires a one-shot scan every StartInterval seconds.
# watch mode: launchd keeps a persistent `aegis.py watch` alive (KeepAlive);
# the process itself is event-driven via kqueue with INTERVAL as its full-scan
# floor, so a change to a watched path is scanned within seconds.
if [ "$MODE" = "watch" ]; then
    PROG_TAIL="        <string>watch</string>
        <string>$INTERVAL</string>"
    SCHEDULE="    <key>KeepAlive</key>      <true/>"
    DESC="event-driven watch; full scan every ${INTERVAL}s"
else
    PROG_TAIL="        <string>scan</string>"
    SCHEDULE="    <key>StartInterval</key>  <integer>$INTERVAL</integer>"
    DESC="every ${INTERVAL}s"
fi

echo "==> Writing launchd agent ($LABEL, $DESC)…"
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
$PROG_TAIL
    </array>
    <key>RunAtLoad</key>      <true/>
$SCHEDULE
    <key>ProcessType</key>    <string>Background</string>
    <key>LowPriorityIO</key>  <true/>
    <key>Nice</key>           <integer>10</integer>
    <key>ThrottleInterval</key><integer>30</integer>
    <key>StandardOutPath</key><string>$OUT_X</string>
    <key>StandardErrorPath</key><string>$ERR_X</string>
</dict>
</plist>
PLISTEOF
"$PLUTIL" -lint "$PLIST" >/dev/null

# Baseline ONLY on first install. Re-running to change the interval must NOT
# re-baseline — that would silently bless any persistence added since the first
# install as "known-good" and erase the very tamper evidence Aegis exists to
# catch. Baselining after the plist is written folds Aegis's own agent into the
# known-good set. Reset deliberately with `python3 aegis.py baseline`.
if [ -f "$HOME/.aegis/baseline.json" ]; then
    echo "==> Existing baseline kept (interval change only; known-good state preserved)."
else
    echo "==> Adopting initial baseline as UNVERIFIED (review before marking trusted)…"
    "$PY" "$RUNTIME" baseline-unverified
fi

echo "==> Loading agent…"
# Modern (bootstrap) with a legacy (load) fallback for older macOS.
"$LAUNCHCTL" bootout "gui/$UID_NUM/$LABEL" 2>/dev/null || true
if ! "$LAUNCHCTL" bootstrap "gui/$UID_NUM" "$PLIST" 2>/dev/null; then
    "$LAUNCHCTL" unload "$PLIST" 2>/dev/null || true
    "$LAUNCHCTL" load -w "$PLIST"
fi
"$LAUNCHCTL" enable "gui/$UID_NUM/$LABEL" 2>/dev/null || true
"$LAUNCHCTL" print "gui/$UID_NUM/$LABEL" >/dev/null
/bin/rm -f "$ERROR_FILE"
trap - EXIT

echo ""
echo "✅ Aegis is now running in the background ($DESC)."
echo "   Report : python3 $AEGIS report      (or: cat ~/.aegis/latest.md)"
echo "   Log    : ~/.aegis/findings.jsonl    (durable; alerts also notify you)"
echo "   Tune   : bash $DIR/install.sh 1800        (interval scans)"
echo "            bash $DIR/install.sh watch       (event-driven, rescan in seconds)"
echo "   Remove : bash $DIR/uninstall.sh"
echo ""
echo "⚠  Aegis DETECTS and alerts; it does not block (that needs Apple's"
echo "   Endpoint Security entitlement). The agent runs a TCC-safe copy at"
echo "   ~/.aegis/aegis.py, so persistence/process/hardening/history/BTM checks"
echo "   work with NO Full Disk Access. Do not give /usr/bin/python3 Full Disk Access:"
echo "   would grant the same access to unrelated scripts. Run 'aegis.py doctor'"
echo "   to see inaccessible coverage. FDA waits for a dedicated signed Aegis app."
echo "   Re-run this installer after editing aegis.py."
