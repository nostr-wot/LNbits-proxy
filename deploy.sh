#!/usr/bin/env bash
#
# Deploy the provisioning proxy and the monitor from a git checkout.
#
# Production previously ran files copied onto the box by hand, which is how it
# ended up carrying changes that existed nowhere in git. This script makes the
# checkout the source of truth: it refuses to run from a dirty tree, records
# what it replaced, and verifies the service afterwards.
#
#   ./deploy.sh              deploy from origin/main
#   ./deploy.sh --dry-run    show what would change, touch nothing
#   ./deploy.sh --ref <ref>  deploy a specific ref (for a rollback)
#
set -euo pipefail

PROVISION_DIR="${PROVISION_DIR:-/srv/zaps-provision}"
MONITOR_DIR="${MONITOR_DIR:-/srv/zaps-monitor}"
PM2_APP="${PM2_APP:-zaps-provision}"
BASE_URL="${DEPLOY_SMOKE_URL:-https://zaps.nostr-wot.com}"
REF="origin/main"
DRY_RUN=0
STAMP="$(date +%Y%m%d-%H%M%S)"

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --ref) REF="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

say() { printf '\n== %s\n' "$*"; }
run() { if [ "$DRY_RUN" -eq 1 ]; then echo "  would run: $*"; else "$@"; fi; }

cd "$(dirname "$0")"

say "Checking the working tree"
if [ -n "$(git status --porcelain)" ]; then
  echo "  refusing to deploy: uncommitted changes present" >&2
  git status --short >&2
  exit 1
fi
git fetch --quiet origin
git rev-parse --verify --quiet "$REF" >/dev/null || { echo "  no such ref: $REF" >&2; exit 1; }
echo "  deploying $REF ($(git rev-parse --short "$REF"))"
run git checkout --quiet --detach "$REF"

say "Installing dependencies and running checks"
run npm ci --omit=dev --silent
run node --check server.js
run node --check nwc-connections.mjs
run node --check monitor/monitor.mjs
# Tests need dev deps; skip them here and rely on CI plus a pre-deploy `npm test`.

say "Comparing against what is live"
for f in server.js nwc-connections.mjs; do
  if [ ! -f "$PROVISION_DIR/$f" ]; then
    echo "  $f is not installed yet and will be created"
  elif diff -q "$f" "$PROVISION_DIR/$f" >/dev/null; then
    echo "  $f unchanged"
  else
    echo "  $f differs and will be replaced"
  fi
done

say "Backing up the live files"
for f in server.js nwc-connections.mjs; do
  [ -f "$PROVISION_DIR/$f" ] && run cp -a "$PROVISION_DIR/$f" "$PROVISION_DIR/$f.bak-$STAMP"
done
[ -f "$MONITOR_DIR/monitor.mjs" ] && run cp -a "$MONITOR_DIR/monitor.mjs" "$MONITOR_DIR/monitor.mjs.bak-$STAMP"
[ -f "$MONITOR_DIR/cleanup.py" ] && run cp -a "$MONITOR_DIR/cleanup.py" "$MONITOR_DIR/cleanup.py.bak-$STAMP"
echo "  backup stamp: $STAMP"

say "Installing the proxy into $PROVISION_DIR"
run install -m 0644 server.js "$PROVISION_DIR/server.js"
run install -m 0644 nwc-connections.mjs "$PROVISION_DIR/nwc-connections.mjs"
run install -m 0644 package.json "$PROVISION_DIR/package.json"
run install -m 0644 package-lock.json "$PROVISION_DIR/package-lock.json"

say "Installing the monitor into $MONITOR_DIR"
run mkdir -p "$MONITOR_DIR"
run install -m 0755 monitor/monitor.mjs "$MONITOR_DIR/monitor.mjs"
run install -m 0755 monitor/cleanup.py "$MONITOR_DIR/cleanup.py"

say "Installing the phoenixd watchdog"
run install -m 0755 monitor/check-phoenixd.sh /usr/local/bin/check-phoenixd.sh
run install -m 0644 monitor/check-phoenixd.service /etc/systemd/system/check-phoenixd.service
run install -m 0644 monitor/check-phoenixd.timer /etc/systemd/system/check-phoenixd.timer
run systemctl daemon-reload
run systemctl enable --now check-phoenixd.timer

say "Restarting $PM2_APP only"
# Deliberately not LNbits or phoenixd: a proxy change never needs those bounced.
run pm2 restart "$PM2_APP" --update-env
run sleep 4

if [ "$DRY_RUN" -eq 1 ]; then
  say "Dry run complete, nothing was changed"
  exit 0
fi

say "Verifying"
fail=0
check() {
  local label="$1" expected="$2"; shift 2
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' -m 15 "$@")"
  if [ "$code" = "$expected" ]; then
    printf '  ok    %-34s HTTP %s\n' "$label" "$code"
  else
    printf '  FAIL  %-34s HTTP %s (expected %s)\n' "$label" "$code" "$expected"
    fail=1
  fi
}
check "public challenge"    200 "$BASE_URL/api/provision/challenge"
check "wallet auth (no key)" 401 "$BASE_URL/api/v1/wallet"
check "nwc (no key)"         401 "$BASE_URL/api/nwc/connections"
check "unknown path"         404 "$BASE_URL/api/nope"

if ! pm2 describe "$PM2_APP" | grep -q "online"; then
  echo "  FAIL  $PM2_APP is not online"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  cat >&2 <<EOF

Deploy verification FAILED. To roll back:
  cp -a $PROVISION_DIR/server.js.bak-$STAMP $PROVISION_DIR/server.js
  cp -a $PROVISION_DIR/nwc-connections.mjs.bak-$STAMP $PROVISION_DIR/nwc-connections.mjs
  pm2 restart $PM2_APP --update-env
EOF
  exit 1
fi

say "Deployed $(git rev-parse --short HEAD), backups stamped $STAMP"
