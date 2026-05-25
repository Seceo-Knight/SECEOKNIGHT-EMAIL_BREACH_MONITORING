#!/bin/bash
PROJECT_DIR="$(cd "$(dirname "$(dirname "${BASH_SOURCE[0]}")")" && pwd)"
STATE_DIR="$PROJECT_DIR/state"
LOG_DIR="$PROJECT_DIR/logs"
CONFIG_DIR="$PROJECT_DIR/config"
DB_FILE="$STATE_DIR/breaches.db"
echo "================================"
echo "SECEOKNIGHT Health Check"
echo "================================"
echo ""
echo "📊 Database:"
if [ -f "$DB_FILE" ]; then
    SIZE=$(du -h "$DB_FILE" | cut -f1)
    BREACHES=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM breaches" 2>/dev/null || echo "error")
    echo "  ✅ Location: $DB_FILE"
    echo "  ✅ Size: $SIZE"
    echo "  ✅ Breaches recorded: $BREACHES"
fi
echo ""
echo "⏰ Timers:"
if systemctl is-enabled seceoknight-daily.timer >/dev/null 2>&1; then
    echo "  ✅ Daily timer: enabled"
fi
if systemctl is-enabled seceoknight-weekly.timer >/dev/null 2>&1; then
    echo "  ✅ Weekly timer: enabled"
fi
echo ""
echo "📝 Logs:"
if [ -f "$LOG_DIR/breach_collector.log" ]; then
    LINES=$(wc -l < "$LOG_DIR/breach_collector.log")
    echo "  ✅ Log lines: $LINES"
fi
echo ""
echo "💾 Disk Space:"
AVAILABLE=$(df "$PROJECT_DIR" | awk 'NR==2 {print $4}')
PERCENT=$(df "$PROJECT_DIR" | awk 'NR==2 {print $5}')
echo "  ✅ Available: $((AVAILABLE / 1024))MB ($PERCENT used)"
echo ""
echo "================================"
echo "Health check complete!"
echo "================================"
