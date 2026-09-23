#!/bin/bash
# Monitors phoenixd health and restarts it if the HTTP API is unresponsive.
# Checks the /getinfo endpoint. If it fails twice in a row, restarts phoenixd.

PHOENIX_PASSWORD=$(grep http-password /home/phoenixd/.phoenix/phoenix.conf | head -1 | cut -d= -f2)
LOG_TAG="phoenixd-monitor"
MAX_RETRIES=2
RETRY_DELAY=10

check_api() {
    response=$(curl -s -m 10 -o /dev/null -w "%{http_code}" \
        -u ":${PHOENIX_PASSWORD}" http://127.0.0.1:9740/getinfo 2>/dev/null)
    [ "$response" = "200" ]
}

# First check
if check_api; then
    exit 0
fi

logger -t "$LOG_TAG" "WARNING: phoenixd API check failed, retrying in ${RETRY_DELAY}s..."
sleep "$RETRY_DELAY"

# Second check (confirm it's really down, not just a blip)
if check_api; then
    logger -t "$LOG_TAG" "phoenixd recovered on retry, no action needed"
    exit 0
fi

logger -t "$LOG_TAG" "ERROR: phoenixd API unresponsive after ${MAX_RETRIES} checks, restarting..."
systemctl restart phoenixd

sleep 10

if check_api; then
    logger -t "$LOG_TAG" "phoenixd restarted successfully and API is responding"
else
    logger -t "$LOG_TAG" "CRITICAL: phoenixd still unresponsive after restart"
fi
