#!/bin/sh
#
# Cron entry point for the monitor.
#
# cron runs with almost no environment, so the configuration is loaded from an
# env file here rather than being baked into monitor.mjs. Keep that file at
# mode 600: it holds the alert provider's API key.
#
#   */5 * * * * /srv/zaps-monitor/run-monitor.sh >> /srv/zaps-monitor/cron.log 2>&1
#
set -e

ENV_FILE="${MONITOR_ENV_FILE:-/srv/zaps-monitor/zaps-monitor.env}"
MONITOR_DIR="$(dirname "$0")"
NODE_BIN="${MONITOR_NODE:-/usr/bin/node}"

if [ ! -r "$ENV_FILE" ]; then
  echo "monitor: cannot read $ENV_FILE; refusing to run unconfigured" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

exec "$NODE_BIN" "$MONITOR_DIR/monitor.mjs"
