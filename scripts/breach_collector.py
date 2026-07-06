#!/usr/bin/env python3
"""
SECEOKNIGHT Breach Collector - Aggregated by Email (Enterprise Edition)
Logs all breaches for an email in ONE alert (not separate per breach)

CHANGE LOG (enterprise hardening pass):
- RateLimiter/CircuitBreaker are now created ONCE per adapter (in
  _init_adapters) and persist for the lifetime of the scan, instead of a
  fresh instance being created on every single per-email call. Previously
  the circuit breaker could never accumulate failures (state was
  discarded immediately) and record_failure() was never even invoked -
  it was fully non-functional dead code.
- Tri-state result handling: adapter.check_email() can now raise
  AdapterCheckIncomplete (rate-limited/timeout/error after retries).
  This is now logged as a distinct "unknown" scan_status, never folded
  into "clean" - a confirmed production bug (test@yahoo.com was
  rate-limited and silently reported as CLEAN in Wazuh).
- Alert deduplication: only breach rows that db.record_breach() reports
  as genuinely NEW are included in the aggregated Wazuh log line. Known,
  previously-alerted breaches are still counted in scan stats but do not
  re-trigger Wazuh rules on every daily/weekly run.
"""
import sys, json, logging, yaml, time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from rate_limiter import RateLimiter
from breach_adapter import BreachEvent, AdapterCheckIncomplete
from xposedornot_adapter import XposedOrNotAdapter
from hibp_adapter import HaveIBeenPwnedAdapter
from database import SECEOKnightDatabase

logger = logging.getLogger(__name__)


class BreachCollector:
    def __init__(self, config_file, db_path, log_file):
        self.config = self._load_config(config_file)
        self.db = SECEOKnightDatabase(db_path)
        self.adapters = self._init_adapters()
        self.limiters = self._init_limiters()
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

    def _init_limiters(self):
        """One RateLimiter (with its own persistent circuit breaker) per
        adapter, created ONCE for the life of this scan run - not per
        email. This is what lets the circuit breaker actually accumulate
        failures and open."""
        limiters = {}
        for adapter in self.adapters:
            limiters[adapter.source_name] = RateLimiter(
                requests_per_second=adapter.rate_limit,
                failure_threshold=5,
            )
        return limiters

    def _setup_logging(self, log_file):
        handler = logging.FileHandler(log_file)
        # Log raw JSON only (no wrapper)
        handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    def check_email(self, email):
        """
        Check email against all adapters.

        Returns:
            (new_events, known_event_count, incomplete_sources) where
            - new_events: BreachEvents just inserted for the first time
              (should be logged/alerted)
            - known_event_count: breach hits found but already known from
              a prior scan (not re-alerted, still counted in stats)
            - incomplete_sources: list of adapter source names that could
              not complete their check this run (circuit open / API
              failure) - the email's true status for these sources is
              UNKNOWN, not clean.
        """
        new_events = []
        known_event_count = 0
        incomplete_sources = []

        for adapter in self.adapters:
            if not adapter.enabled:
                continue

            limiter = self.limiters[adapter.source_name]

            if not limiter.wait_if_needed():
                logger.warning(
                    f"Circuit breaker OPEN for {adapter.source_name} - "
                    f"skipping {email}, marking incomplete"
                )
                incomplete_sources.append(adapter.source_name)
                continue

            try:
                breaches = adapter.check_email(email)
                limiter.record_success()
            except AdapterCheckIncomplete as e:
                limiter.record_failure()
                logger.warning(f"Incomplete check for {email} on {adapter.source_name}: {e}")
                incomplete_sources.append(adapter.source_name)
                continue
            except Exception as e:
                limiter.record_failure()
                logger.error(f"Unexpected error checking {email} on {adapter.source_name}: {e}")
                incomplete_sources.append(adapter.source_name)
                continue

            for event in breaches:
                is_new = self.db.record_breach(event.to_dict())
                if is_new:
                    new_events.append(event)
                else:
                    known_event_count += 1

        return new_events, known_event_count, incomplete_sources

    def run_daily_scan(self, email_file):
        self._run_scan("daily", email_file)

    def run_weekly_scan(self, email_file):
        self._run_scan("weekly", email_file)

    def _run_scan(self, scan_type, email_file):
        """Run scan and aggregate breaches by email"""
        start_time = time.time()
        emails = self._load_emails(email_file)
        total_breaches_found = 0
        total_new_breaches = 0
        total_incomplete = 0

        logger.info(f"Starting {scan_type} scan for {len(emails)} emails")

        for email in emails:
            self.db.add_email(email)

            new_events, known_count, incomplete_sources = self.check_email(email)
            total_breaches_found += len(new_events) + known_count

            if new_events:
                total_new_breaches += len(new_events)
                self._log_aggregated_event(email, new_events, known_count, incomplete_sources)
            elif incomplete_sources:
                # Could not confirm status on at least one source - this
                # must NOT be logged as clean.
                total_incomplete += 1
                self._log_incomplete_email(email, incomplete_sources, known_count)
            else:
                # All enabled sources affirmatively confirmed zero breaches
                # (new or previously known).
                self._log_clean_email(email, known_count)

        duration = time.time() - start_time
        self.db.record_scan(
            scan_type, len(emails), total_breaches_found, duration,
            new_breaches_found=total_new_breaches,
            incomplete_checks=total_incomplete,
        )
        logger.info(
            f"Scan complete: {total_new_breaches} NEW breaches, "
            f"{total_breaches_found} total hits, {total_incomplete} incomplete checks, "
            f"{duration:.2f}s"
        )

    def _log_aggregated_event(self, email, new_events, known_count, incomplete_sources):
        """Log NEW breaches for an email in a single JSON entry. Known
        (already-alerted) breaches are summarized by count only, not
        re-emitted as fresh alert-triggering fields."""
        severity_levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        max_severity = max(severity_levels.get(e.severity_label, 1) for e in new_events)
        severity_map = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
        max_severity_label = severity_map[max_severity]

        has_credential_breach = any(e.is_credential_breach for e in new_events)
        has_plaintext_password = any(e.password_risk == "plaintext" for e in new_events)

        breach_ids = [e.breach_id for e in new_events]

        all_categories = set()
        for event in new_events:
            if event.data_categories:
                all_categories.update(event.data_categories)

        aggregated_entry = {
            "email": email,
            "scan_status": "breach_found",
            "breach_count": len(new_events),
            "known_breach_count": known_count,
            "breach_ids": breach_ids,
            "severity_label": max_severity_label,
            "severity_score": max(e.severity_score for e in new_events),
            "is_credential_breach": has_credential_breach,
            "has_plaintext_password": has_plaintext_password,
            "is_pii_breach": any(e.is_pii_breach for e in new_events),
            "data_categories": list(all_categories),
            "affected_records": sum(e.affected_records for e in new_events),
            "incomplete_sources": incomplete_sources,
            "source": "aggregated",
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(json.dumps(aggregated_entry))

    def _log_clean_email(self, email, known_count=0):
        """Log when ALL enabled sources affirmatively confirmed no new
        breaches for this email."""
        clean_entry = {
            "email": email,
            "scan_status": "clean",
            "breach_count": 0,
            "known_breach_count": known_count,
            "breach_ids": [],
            "breach_status": "clean",
            "severity_label": "CLEAN",
            "is_credential_breach": False,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(json.dumps(clean_entry))

    def _log_incomplete_email(self, email, incomplete_sources, known_count=0):
        """Log when at least one source could not complete its check.
        This is deliberately a DIFFERENT scan_status than 'clean' so
        Wazuh (and anyone reading the DB) can tell 'verified safe' apart
        from 'we don't actually know yet'."""
        entry = {
            "email": email,
            "scan_status": "unknown",
            "breach_count": 0,
            "known_breach_count": known_count,
            "breach_ids": [],
            "severity_label": "UNKNOWN",
            "is_credential_breach": False,
            "incomplete_sources": incomplete_sources,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(json.dumps(entry))

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
