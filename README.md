# 🛡️ SECEOKNIGHT Breach Monitoring System

**Production-ready email breach detection with Wazuh SIEM integration**

Automatically scans your company's emails against breach databases and alerts you in Wazuh when breaches are found.

---

## ✨ Features

✅ **Multi-Source Monitoring** - XposedOrNot (free) + HIBP (free/paid)
✅ **Automated Scans** - Daily 2 AM (critical) + Weekly Sunday 3 AM (all employees)
✅ **Real-Time Alerts** - Appears instantly in Wazuh dashboard
✅ **Smart Severity** - CVSS-based (0-10), not keyword-dependent
✅ **Production-Ready** - Rate limiting, circuit breaker, error handling
✅ **Easy Setup** - One-command installation

---

## 🚀 Quick Start

```bash
git clone git@github.com:Seceo-Knight/SECEOKNIGHT-BREACH_MONITORING.git
cd SECEOKNIGHT-BREACH_MONITORING
sudo bash setup.sh
sudo nano /opt/seceoknight/breach-monitor/config/critical_emails.txt
sudo nano /opt/seceoknight/breach-monitor/config/all_employees.txt
# Done! System runs automatically
```

---

## 📋 Requirements

- **OS**: Ubuntu 20.04+, Debian 10+, CentOS 7+, RHEL 7+
- **Python**: 3.7+
- **Disk**: 2GB minimum
- **Network**: Outbound HTTPS to APIs
- **Root**: Required for setup

---

## 🔧 Installation

### Automated (Recommended)

```bash
sudo bash setup.sh
```

Script will:
- Create `/opt/seceoknight/breach-monitor/` directories
- Install Python dependencies
- Deploy all files
- Setup systemd timers (daily 2 AM, weekly Sunday 3 AM)
- Configure log rotation
- Verify installation

### Manual Installation

```bash
# 1. Create directories
sudo mkdir -p /opt/seceoknight/breach-monitor/{lib,scripts,config,logs,state/backup}
sudo chown -R root:root /opt/seceoknight/breach-monitor

# 2. Install dependencies
sudo pip3 install xposedornot requests pyyaml python-dateutil

# 3. Copy files
sudo cp -r lib/* /opt/seceoknight/breach-monitor/lib/
sudo cp -r scripts/* /opt/seceoknight/breach-monitor/scripts/
sudo cp config/*.example /opt/seceoknight/breach-monitor/config/
sudo chmod 750 /opt/seceoknight/breach-monitor/scripts/*.sh
sudo chmod 750 /opt/seceoknight/breach-monitor/scripts/*.py

# 4. Create email files
sudo touch /opt/seceoknight/breach-monitor/config/critical_emails.txt
sudo touch /opt/seceoknight/breach-monitor/config/all_employees.txt
```

---

## ⚙️ Configuration

### Add Critical Employees (Daily 2 AM Scans)

```bash
sudo nano /opt/seceoknight/breach-monitor/config/critical_emails.txt
```

Add one email per line:
```
ceo@company.com
ciso@company.com
admin@company.com
```

### Add All Employees (Weekly Sunday 3 AM Scans)

```bash
sudo nano /opt/seceoknight/breach-monitor/config/all_employees.txt
```

Add complete employee list (one per line).

### Configure Breach Sources (Optional)

```bash
sudo nano /opt/seceoknight/breach-monitor/config/breach_sources.yml
```

**Current setup (free tier):**
- XposedOrNot: enabled (60 requests/hour)
- HIBP: enabled (1.5 req/sec free, 10+ req/sec paid)

**To add HIBP paid API key later:**
1. Get key from: https://haveibeenpwned.com/API/v3
2. Edit breach_sources.yml and add api_key
3. Restart: `sudo systemctl restart seceoknight-daily.timer seceoknight-weekly.timer`

---

## 📊 Operations

### Health Check

```bash
sudo /opt/seceoknight/breach-monitor/scripts/health_check.sh
```

### View Logs

```bash
# Recent activity
sudo tail -100 /opt/seceoknight/breach-monitor/logs/breach_collector.log

# Follow live
sudo tail -f /opt/seceoknight/breach-monitor/logs/breach_collector.log
```

### Manual Scan

```bash
sudo /opt/seceoknight/breach-monitor/scripts/run_daily.sh
sudo /opt/seceoknight/breach-monitor/scripts/run_weekly.sh
```

### Check Timers

```bash
sudo systemctl status seceoknight-daily.timer
sudo systemctl status seceoknight-weekly.timer
```

### Query Database

```bash
sudo sqlite3 /opt/seceoknight/breach-monitor/state/breaches.db

SELECT email, source, severity_label FROM breaches;
SELECT severity_label, COUNT(*) FROM breaches GROUP BY severity_label;
SELECT * FROM breaches WHERE detection_time > datetime('now', '-7 days');
.exit
```

---

## 🚨 Wazuh Integration

### Step 1: Deploy Decoder (Wazuh Server)

```bash
sudo cp wazuh/decoder.xml /var/ossec/etc/decoders/seceoknight.xml
sudo chown root:wazuh /var/ossec/etc/decoders/seceoknight.xml
sudo chmod 640 /var/ossec/etc/decoders/seceoknight.xml
```

### Step 2: Deploy Rules (Wazuh Server)

```bash
sudo cp wazuh/rules.xml /var/ossec/etc/rules/seceoknight.xml
sudo chown root:wazuh /var/ossec/etc/rules/seceoknight.xml
sudo chmod 640 /var/ossec/etc/rules/seceoknight.xml
```

### Step 3: Configure Monitoring (SECEOKNIGHT Server)

Edit `/var/ossec/etc/ossec.conf`, add before `</ossec_config>`:

```xml
<localfile>
    <log_format>json</log_format>
    <location>/opt/seceoknight/breach-monitor/logs/breach_collector.log</location>
</localfile>
```

Restart: `sudo systemctl restart wazuh-agent`

### Step 4: Restart Wazuh (Wazuh Server)

```bash
sudo systemctl restart wazuh-manager
```

### Test

```bash
echo "test@example.com" | sudo tee -a /opt/seceoknight/breach-monitor/config/critical_emails.txt
sudo /opt/seceoknight/breach-monitor/scripts/run_daily.sh
# Check Wazuh dashboard for alerts (rule 100601-100604)
```

---

## 🔍 Troubleshooting

### Scans Not Running

```bash
sudo systemctl enable seceoknight-daily.timer seceoknight-weekly.timer
sudo systemctl start seceoknight-daily.timer seceoknight-weekly.timer
```

### Python Errors

```bash
sudo pip3 install xposedornot requests pyyaml python-dateutil
```

### Wazuh Alerts Missing

Check: decoder loaded, rules loaded, file monitored, agents restarted

```bash
sudo grep -r "seceoknight" /var/ossec/etc/decoders/
sudo grep -r "100601" /var/ossec/etc/rules/
sudo grep "breach_collector.log" /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent wazuh-manager
```

---

## ❓ FAQ

**Q: Does this store passwords?**
A: No. Only checks if emails appear in public breach databases.

**Q: Is my employee list private?**
A: Yes. Stays on YOUR server. Never leaves.

**Q: Can I add more sources?**
A: Yes. Adapter pattern allows easy additions. No code changes.

**Q: What if API fails?**
A: Circuit breaker handles failures. Retries automatically.

**Q: Manual scan?**
A: Yes. `sudo /opt/seceoknight/breach-monitor/scripts/run_daily.sh`

**Q: How much disk?**
A: Usually 100-500MB. Database grows ~1-5 MB per 1000 employees/week.

**Q: Export data?**
A: Yes. `sqlite3 ... ".mode csv" ".headers on" "SELECT * FROM breaches;" > export.csv`

---

## 🔐 Security

✅ Keep updated
✅ Review logs regularly
✅ Use SSH for GitHub (not tokens)
✅ Rotate API keys annually
✅ Keep Wazuh updated
✅ Backup database weekly

---

## 📄 License

MIT License - Free to use, modify, distribute.

---

## 📞 Support

**Questions?** Check logs: `sudo tail -f /opt/seceoknight/breach-monitor/logs/breach_collector.log`

**Email:** vaibhavhandekar3@gmail.com

**Status:** Production Ready ✅

Made with ❤️ for SECEOKNIGHT
