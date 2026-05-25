#!/usr/bin/env python3
import sys, json, logging, yaml, time
from datetime import datetime
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from rate_limiter import RateLimiter
from breach_adapter import BreachEvent
from xposedornot_adapter import XposedOrNotAdapter
from hibp_adapter import HaveIBeenPwnedAdapter
from database import SECEOKnightDatabase

logger = logging.getLogger(__name__)

class BreachCollector:
    def __init__(self, config_file, db_path, log_file):
        self.config = self._load_config(config_file)
        self.db = SECEOKnightDatabase(db_path)
        self.adapters = self._init_adapters()
        self.log_file = log_file
        self._setup_logging(log_file)

    def _load_config(self, config_file):
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)

    def _init_adapters(self):
        adapters = []
        sources = self.config.get("breach_sources", {})
        if sources.get("xposedornot", {}).get("enabled"):
            adapters.append(XposedOrNotAdapter(sources["xposedornot"]))
        if sources.get("hibp", {}).get("enabled"):
            adapters.append(HaveIBeenPwnedAdapter(sources["hibp"]))
        logger.info(f"Initialized {len(adapters)} adapters")
        return adapters

    def _setup_logging(self, log_file):
        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter('{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}'))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    def check_email(self, email):
        events = []
        for adapter in self.adapters:
            if not adapter.enabled:
                continue
            try:
                limiter = RateLimiter(adapter.rate_limit)
                if not limiter.wait_if_needed():
                    logger.warning(f"Circuit breaker open for {adapter.source_name}")
                    continue
                breaches = adapter.check_email(email)
                if breaches:
                    events.extend(breaches)
                    limiter.record_success()
                else:
                    limiter.record_success()
            except Exception as e:
                logger.error(f"Error checking {email} on {adapter.source_name}: {e}")
        return events

    def run_daily_scan(self, email_file):
        self._run_scan("daily", email_file)

    def run_weekly_scan(self, email_file):
        self._run_scan("weekly", email_file)

    def _run_scan(self, scan_type, email_file):
        start_time = time.time()
        emails = self._load_emails(email_file)
        breaches_found = 0
        logger.info(f"Starting {scan_type} scan for {len(emails)} emails")
        for email in emails:
            self.db.add_email(email)
            events = self.check_email(email)
            if events:
                breaches_found += len(events)
                for event in events:
                    self.db.record_breach(event.to_dict())
                    self._log_event(event)
        duration = time.time() - start_time
        self.db.record_scan(scan_type, len(emails), breaches_found, duration)
        logger.info(f"Scan complete: {breaches_found} breaches found in {duration:.2f}s")

    def _load_emails(self, email_file):
        emails = []
        try:
            with open(email_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        emails.append(line)
        except FileNotFoundError:
            logger.error(f"Email file not found: {email_file}")
        return emails

    def _log_event(self, event):
        log_entry = event.to_dict()
        logger.info(json.dumps(log_entry))

def main():
    import argparse
    parser = argparse.ArgumentParser(description="SECEOKNIGHT Breach Collector")
    parser.add_argument("--config", default="/opt/seceoknight/breach-monitor/config/breach_sources.yml")
    parser.add_argument("--db", default="/opt/seceoknight/breach-monitor/state/breaches.db")
    parser.add_argument("--log", default="/opt/seceoknight/breach-monitor/logs/breach_collector.log")
    parser.add_argument("--scan-type", choices=["daily", "weekly"], required=True)
    parser.add_argument("--email-file", required=True)
    args = parser.parse_args()
    collector = BreachCollector(args.config, args.db, args.log)
    if args.scan_type == "daily":
        collector.run_daily_scan(args.email_file)
    else:
        collector.run_weekly_scan(args.email_file)

if __name__ == "__main__":
    main()
