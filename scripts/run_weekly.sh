#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$PROJECT_DIR/config"
LOG_DIR="$PROJECT_DIR/logs"
STATE_DIR="$PROJECT_DIR/state"
DB_FILE="$STATE_DIR/breaches.db"
EMAIL_FILE="$CONFIG_DIR/all_employees.txt"
LOG_FILE="$LOG_DIR/breach_collector.log"
PYTHON_SCRIPT="$SCRIPT_DIR/breach_collector.py"
MAX_RETRIES=3
RETRY_DELAY=60
log_info() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$LOG_FILE"; }
log_error() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$LOG_FILE"; }
mkdir -p "$LOG_DIR" "$STATE_DIR"
log_info "SECEOKNIGHT Weekly Scan Started"
EMAIL_COUNT=$(grep -v '^#' "$EMAIL_FILE" | grep -v '^$' | wc -l)
log_info "Scanning $EMAIL_COUNT employees"
ATTEMPT=1
START_TIME=$(date +%s)
while [ $ATTEMPT -le $MAX_RETRIES ]; do
    if python3 "$PYTHON_SCRIPT" --config "$CONFIG_DIR/breach_sources.yml" --db "$DB_FILE" --log "$LOG_FILE" --scan-type "weekly" --email-file "$EMAIL_FILE"; then
        END_TIME=$(date +%s)
        DURATION=$((END_TIME - START_TIME))
        log_info "✅ Weekly scan completed successfully (${DURATION}s)"
        exit 0
    else
        log_error "Scan attempt $ATTEMPT/$MAX_RETRIES failed"
        if [ $ATTEMPT -lt $MAX_RETRIES ]; then
            log_info "Retrying in ${RETRY_DELAY}s..."
            sleep $RETRY_DELAY
        fi
    fi
    ATTEMPT=$((ATTEMPT + 1))
done
log_error "❌ Weekly scan failed after $MAX_RETRIES attempts"
exit 1
