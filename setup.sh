#!/bin/bash
set -e
GREEN='\033[0;32m'
NC='\033[0m'
SECEOKNIGHT_DIR="/opt/seceoknight/breach-monitor"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "SECEOKNIGHT SETUP"
echo "================="

if [[ $EUID -ne 0 ]]; then
    echo "❌ This script must be run as root"
    echo "Usage: sudo bash setup.sh"
    exit 1
fi

# Create directories
echo "Creating directories..."
mkdir -p $SECEOKNIGHT_DIR/{config,lib,scripts,logs,state/backup}
chown -R root:root $SECEOKNIGHT_DIR
chmod 755 $SECEOKNIGHT_DIR

# Install OS package for the sqlite3 CLI (health_check.sh and manual
# queries shell out to the `sqlite3` binary - this is separate from
# Python's built-in sqlite3 module, which the collector itself uses and
# which is always present). Without this, health_check.sh silently
# prints "error" for the breach count even though the database is fine.
echo "Installing sqlite3 CLI..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y sqlite3 >/dev/null
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y sqlite >/dev/null
elif command -v yum >/dev/null 2>&1; then
    yum install -y sqlite >/dev/null
else
    echo "  ⚠️  Unknown package manager - install a sqlite3 CLI package manually"
fi

# Install Python dependencies (pinned - see requirements.txt)
echo "Installing Python dependencies..."
pip3 install --quiet -r requirements.txt
# NOTE: the "xposedornot" PyPI package was previously installed here but
# is unused - lib/xposedornot_adapter.py talks to the API directly via
# `requests`. Removed to reduce unnecessary supply-chain surface.

# Copy library files
echo "Deploying Python libraries..."
cp -r lib/* $SECEOKNIGHT_DIR/lib/

# Copy scripts
echo "Deploying scripts..."
cp scripts/*.py $SECEOKNIGHT_DIR/scripts/
cp scripts/*.sh $SECEOKNIGHT_DIR/scripts/
chmod 750 $SECEOKNIGHT_DIR/scripts/*.sh
chmod 750 $SECEOKNIGHT_DIR/scripts/*.py

# Copy config files
echo "Deploying configuration..."
cp config/*.example $SECEOKNIGHT_DIR/config/

# Setup systemd timers
echo "Setting up systemd timers..."
cat > /etc/systemd/system/seceoknight-daily.service << 'EOF'
[Unit]
Description=SECEOKNIGHT Daily Breach Scan
After=network-online.target
[Service]
Type=oneshot
ExecStart=/opt/seceoknight/breach-monitor/scripts/run_daily.sh
User=root
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/seceoknight-daily.timer << 'EOF'
[Unit]
Description=SECEOKNIGHT Daily Timer
Requires=seceoknight-daily.service
[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true
[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/seceoknight-weekly.service << 'EOF'
[Unit]
Description=SECEOKNIGHT Weekly Breach Scan
After=network-online.target
[Service]
Type=oneshot
ExecStart=/opt/seceoknight/breach-monitor/scripts/run_weekly.sh
User=root
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/seceoknight-weekly.timer << 'EOF'
[Unit]
Description=SECEOKNIGHT Weekly Timer
Requires=seceoknight-weekly.service
[Timer]
OnCalendar=Sun *-*-* 03:00:00
Persistent=true
[Install]
WantedBy=timers.target
EOF

chmod 644 /etc/systemd/system/seceoknight-*.{service,timer}
systemctl daemon-reload
systemctl enable seceoknight-daily.timer seceoknight-weekly.timer
systemctl start seceoknight-daily.timer seceoknight-weekly.timer

# Setup log rotation
echo "Setting up log rotation..."
cat > /etc/logrotate.d/seceoknight << 'EOF'
/opt/seceoknight/breach-monitor/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
EOF

echo ""
echo "================="
echo "✅ INSTALLATION COMPLETE!"
echo "================="
echo ""
echo "Configuration:"
echo "  - Critical emails: /opt/seceoknight/breach-monitor/config/critical_emails.txt"
echo "  - All employees: /opt/seceoknight/breach-monitor/config/all_employees.txt"
echo ""
echo "Next:"
echo "  1. Add employee emails to the config files above"
echo "  2. Check system: /opt/seceoknight/breach-monitor/scripts/health_check.sh"
echo ""
echo "Scheduling:"
echo "  - Daily scan: 2 AM"
echo "  - Weekly scan: Sunday 3 AM"
echo ""
