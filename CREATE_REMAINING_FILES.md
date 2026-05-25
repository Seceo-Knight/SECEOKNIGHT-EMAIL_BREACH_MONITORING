# Create Remaining Files

**Copy-paste the following files into CLEAN_PACKAGE folder:**

---

## 📝 File: setup.sh

Create file: `CLEAN_PACKAGE/setup.sh`
Make executable: `chmod +x setup.sh`

```bash
#!/bin/bash
set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
SECEOKNIGHT_DIR="/opt/seceoknight/breach-monitor"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
print_header() { echo -e "${BLUE}========================================${NC}\n${BLUE}$1${NC}\n${BLUE}========================================${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
check_root() { if [[ $EUID -ne 0 ]]; then print_error "This script must be run as root"; echo "Usage: sudo bash setup.sh"; exit 1; fi; }
check_python() { if ! command -v python3 &> /dev/null; then print_error "Python3 not found"; exit 1; fi; PYTHON_VERSION=$(python3 --version | awk '{print $2}'); print_success "Python $PYTHON_VERSION found"; }
create_directories() { print_header "STEP 1: Creating Directory Structure"; mkdir -p $SECEOKNIGHT_DIR/{config,lib,scripts,logs,state/backup}; chown -R root:root $SECEOKNIGHT_DIR; chmod 755 $SECEOKNIGHT_DIR; print_success "Directory structure created"; }
install_dependencies() { print_header "STEP 2: Installing Dependencies"; pip3 install --quiet xposedornot requests pyyaml python-dateutil; print_success "Dependencies installed"; }
deploy_python_files() { print_header "STEP 3: Deploying Python Libraries"; for file in lib/*.py; do if [ -f "$REPO_DIR/$file" ]; then cp "$REPO_DIR/$file" "$SECEOKNIGHT_DIR/$file"; chmod 640 "$SECEOKNIGHT_DIR/$file"; print_success "Deployed: $(basename $file)"; fi; done; }
deploy_scripts() { print_header "STEP 4: Deploying Scripts"; for file in scripts/*.py scripts/*.sh; do if [ -f "$REPO_DIR/$file" ]; then cp "$REPO_DIR/$file" "$SECEOKNIGHT_DIR/$file"; chmod 750 "$SECEOKNIGHT_DIR/$file"; print_success "Deployed: $(basename $file)"; fi; done; }
deploy_config_files() { print_header "STEP 5: Deploying Configuration Files"; for file in config/*.example; do if [ -f "$REPO_DIR/$file" ]; then cp "$REPO_DIR/$file" "$SECEOKNIGHT_DIR/$(basename $file .example)"; chmod 640 "$SECEOKNIGHT_DIR/$(basename $file .example)"; print_success "Deployed: $(basename $file)"; fi; done; }
setup_systemd_timers() { print_header "STEP 6: Setting Up Systemd Timers"; cat > /etc/systemd/system/seceoknight-daily.service << 'EOF'
[Unit]
Description=SECEOKNIGHT Daily Breach Scan
After=network-online.target
[Service]
Type=oneshot
ExecStart=/opt/seceoknight/breach-monitor/scripts/run_daily.sh
User=root
StandardOutput=journal
StandardError=journal
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
StandardOutput=journal
StandardError=journal
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
print_success "Timers created and enabled"; }
setup_log_rotation() { print_header "STEP 7: Setting Up Log Rotation"; cat > /etc/logrotate.d/seceoknight << 'EOF'
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
chmod 644 /etc/logrotate.d/seceoknight
print_success "Log rotation configured"; }
print_summary() { print_header "INSTALLATION COMPLETE ✅"; echo ""; echo "📁 Installation paths:"; echo "   Config: $SECEOKNIGHT_DIR/config/"; echo "   Scripts: $SECEOKNIGHT_DIR/scripts/"; echo "   Logs: $SECEOKNIGHT_DIR/logs/"; echo ""; echo "⏰ Automated scans:"; echo "   Daily: 2 AM (critical employees)"; echo "   Weekly: Sunday 3 AM (all employees)"; echo ""; echo "🚀 Next steps:"; echo "   1. Add emails to critical_emails.txt"; echo "   2. Add emails to all_employees.txt"; echo "   3. Run: $SECEOKNIGHT_DIR/scripts/health_check.sh"; echo ""; print_success "System is ready!"; }
main() { print_header "SECEOKNIGHT AUTOMATED SETUP"; check_root; check_python; echo ""; create_directories; echo ""; install_dependencies; echo ""; deploy_python_files; echo ""; deploy_scripts; echo ""; deploy_config_files; echo ""; setup_systemd_timers; echo ""; setup_log_rotation; echo ""; print_summary; }
main
exit 0
```

---

## 📝 File: scripts/breach_collector.py

[Copy from COPY-PASTE-TEMPLATE.md - Section "📝 CREATE: scripts/breach_collector.py"]

---

## 📝 File: scripts/run_daily.sh

[Copy from COPY-PASTE-TEMPLATE.md - Section "📝 CREATE: scripts/run_daily.sh"]

---

## 📝 File: scripts/run_weekly.sh

[Copy from COPY-PASTE-TEMPLATE.md - Section "📝 CREATE: scripts/run_weekly.sh"]

---

## 📝 File: scripts/health_check.sh

[Copy from COPY-PASTE-TEMPLATE.md - Section "📝 CREATE: scripts/health_check.sh"]

---

## 📝 File: config/breach_sources.yml.example

[Copy from COPY-PASTE-TEMPLATE.md - Section "📝 CREATE: config/breach_sources.yml.example"]

---

## 📝 File: config/critical_emails.txt.example

[Copy from COPY-PASTE-TEMPLATE.md - Section "📝 CREATE: config/critical_emails.txt.example"]

---

## 📝 File: config/all_employees.txt.example

[Copy from COPY-PASTE-TEMPLATE.md - Section "📝 CREATE: config/all_employees.txt.example"]

---

## 📝 File: wazuh/decoder.xml

[Copy from COPY-PASTE-TEMPLATE.md - Section "📝 CREATE: wazuh/decoder.xml"]

---

## 📝 File: wazuh/rules.xml

[Copy from COPY-PASTE-TEMPLATE.md - Section "📝 CREATE: wazuh/rules.xml"]

---

## 📝 File: wazuh/ossec.conf.snippet

[Copy from COPY-PASTE-TEMPLATE.md - Section "📝 CREATE: wazuh/ossec.conf.snippet"]

---

**Note:** Go to COPY-PASTE-TEMPLATE.md in /outputs (same folder) for the actual code content to copy
