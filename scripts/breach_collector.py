#!/usr/bin/env python3
"""
SECEOKNIGHT Breach Collector - Aggregated by Email
Logs all breaches for an email in ONE alert (not separate per breach)
"""
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
        # Log raw JSON only (no wrapper)
        handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    def check_email(self, email):
        """Check email against all adapters and return aggregated results"""
        all_events = []

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
                    all_events.extend(breaches)
                    limiter.record_success()
                else:
                    limiter.record_success()
            except Exception as e:
                logger.error(f"Error checking {email} on {adapter.source_name}: {e}")

        return all_events

    def run_daily_scan(self, email_file):
        self._run_scan("daily", email_file)

    def run_weekly_scan(self, email_file):
        self._run_scan("weekly", email_file)

    def _run_scan(self, scan_type, email_file):
        """Run scan and aggregate breaches by email"""
        start_time = time.time()
        emails = self._load_emails(email_file)
        total_breaches_found = 0

        logger.info(f"Starting {scan_type} scan for {len(emails)} emails")

        for email in emails:
            self.db.add_email(email)

            # Get all breaches for this email
            events = self.check_email(email)

            if events:
                total_breaches_found += len(events)

                # Store each breach in database
                for event in events:
                    self.db.record_breach(event.to_dict())

                # AGGREGATED: Log all breaches for this email in ONE entry
                self._log_aggregated_event(email, events)
            else:
                # Email has no breaches - log as clean
                self._log_clean_email(email)

        duration = time.time() - start_time
        self.db.record_scan(scan_type, len(emails), total_breaches_found, duration)
        logger.info(f"Scan complete: {total_breaches_found} breaches found in {duration:.2f}s")

    def _log_aggregated_event(self, email, events):
        """Log all breaches for an email in a single JSON entry"""
        if not events:
            return

        # Find highest severity among all breaches for this email
        severity_levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        max_severity = max([severity_levels.get(e.severity_label, 1) for e in events])
        severity_map = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
        max_severity_label = severity_map[max_severity]

        # Check if ANY breach is credential breach
        has_credential_breach = any(e.is_credential_breach for e in events)

        # Collect all breach IDs
        breach_ids = [e.breach_id for e in events]

        # Collect all data categories (unique)
        all_categories = set()
        for event in events:
            if event.data_categories:
                all_categories.update(event.data_categories)

        # Create aggregated log entry
        aggregated_entry = {
            "email": email,
            "breach_count": len(events),
            "breach_ids": breach_ids,
            "severity_label": max_severity_label,
            "severity_score": max([e.severity_score for e in events]),
            "is_credential_breach": has_credential_breach,
            "is_pii_breach": any(e.is_pii_breach for e in events),
            "data_categories": list(all_categories),
            "affected_records": sum([e.affected_records for e in events]),
            "source": "aggregated",
            "scan_timestamp": datetime.now().isoformat()
        }

        # Log as single JSON line
        logger.info(json.dumps(aggregated_entry))

    def _log_clean_email(self, email):
        """Log when email has no breaches found"""
        clean_entry = {
            "email": email,
            "breach_count": 0,
            "breach_ids": [],
            "breach_status": "clean",
            "severity_label": "CLEAN",
            "is_credential_breach": False,
            "scan_timestamp": datetime.now().isoformat()
        }

        logger.info(json.dumps(clean_entry))

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


def main():
    import argparse

    parser = argparse.ArgumentParser(description="SECEOKNIGHT Breach Collector - Aggregated")
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
