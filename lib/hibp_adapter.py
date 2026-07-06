"""
SECEOKNIGHT Have I Been Pwned Adapter
File: lib/hibp_adapter.py
Purpose: Integration with HIBP API (free and paid tiers)

CHANGE LOG (enterprise hardening pass):
- Severity now derived from HIBP's real `DataClasses` field (e.g.
  ["Passwords", "Email addresses"]) and `IsSensitive` flag via the shared
  BreachAdapter.score_structured(), instead of keyword-guessing over the
  whole stringified breach dict.
- 429 / timeout / connection errors now retry with backoff and raise
  AdapterCheckIncomplete after exhausting retries, instead of returning
  None. Previously, `check_email()` returning None on a rate-limit was
  indistinguishable from "not found" to the caller - the exact same bug
  confirmed in production for the XposedOrNot adapter.
- 401 (bad API key) is treated as a hard configuration error and also
  raises AdapterCheckIncomplete, since we cannot determine breach status
  without a working key - previously it silently returned None (= false
  "clean").
"""

import logging
import time
from typing import List
import requests

from breach_adapter import BreachAdapter, BreachEvent, AdapterCheckIncomplete

logger = logging.getLogger(__name__)


class HaveIBeenPwnedAdapter(BreachAdapter):
    """Have I Been Pwned API integration."""

    API_BASE = "https://haveibeenpwned.com/api/v3"
    BREACHES_ENDPOINT = f"{API_BASE}/breachedaccount"

    def __init__(self, config: dict):
        """
        Initialize adapter.

        Automatically detects tier:
        - api_key=None → Free tier (~1.5 req/sec, per HIBP's documented limit)
        - api_key="key" → Paid tier (10+ req/sec)
        """
        super().__init__(config)
        self.source_name = "hibp"
        self.api_key = config.get("api_key")
        self.max_retries = int(config.get("max_retries", 3) or 3)
        self.timeout = int(config.get("timeout", 10) or 10)
        self.last_request_time = 0

        if self.api_key:
            logger.info("Using HIBP PAID tier (API key configured)")
        else:
            logger.info("Using HIBP FREE tier (no API key)")

    def _throttle(self):
        elapsed = time.time() - self.last_request_time
        min_delay = 1.0 / self.rate_limit if self.rate_limit else 0
        if elapsed < min_delay:
            time.sleep(min_delay - elapsed)
        self.last_request_time = time.time()

    def _backoff_sleep(self, attempt: int):
        delay = min(2 ** attempt, 30)
        time.sleep(delay)

    def check_email(self, email: str) -> List[BreachEvent]:
        """
        Check if email is in HIBP database.

        Returns:
            [] if HIBP affirmatively returned 404 (confirmed no breach).

        Raises:
            AdapterCheckIncomplete if the check could not be completed
            (rate limited, timeout, bad API key, server error).
        """
        if not self.enabled:
            logger.debug(f"{self.source_name} is disabled, skipping")
            return []

        headers = {"User-Agent": "SECEOKNIGHT/1.0"}
        if self.api_key:
            headers["hibp-api-key"] = self.api_key

        last_error = "unknown"
        attempts = self.max_retries + 1

        for attempt in range(attempts):
            self._throttle()

            try:
                response = requests.get(
                    self.BREACHES_ENDPOINT,
                    params={"email": email, "truncateResponse": "false"},
                    headers=headers,
                    timeout=self.timeout,
                )
            except requests.exceptions.Timeout:
                last_error = "timeout"
                logger.warning(f"[{attempt + 1}/{attempts}] Timeout checking {email} on {self.source_name}")
                if attempt < attempts - 1:
                    self._backoff_sleep(attempt)
                continue
            except requests.exceptions.RequestException as e:
                last_error = f"request_error: {e}"
                logger.warning(f"[{attempt + 1}/{attempts}] Request error checking {email}: {e}")
                if attempt < attempts - 1:
                    self._backoff_sleep(attempt)
                continue

            if response.status_code == 404:
                logger.debug(f"{email} not found on {self.source_name} (confirmed clean)")
                return []

            if response.status_code == 200:
                try:
                    return self._parse_breaches(email, response.json())
                except ValueError:
                    last_error = "invalid_json"
                    logger.error(f"Invalid JSON from {self.source_name} for {email}")
                    break

            if response.status_code == 429:
                last_error = "rate_limited"
                retry_after = response.headers.get("Retry-After")
                logger.warning(
                    f"[{attempt + 1}/{attempts}] Rate limited by {self.source_name} "
                    f"(Retry-After={retry_after})"
                )
                if attempt < attempts - 1:
                    if retry_after and retry_after.isdigit():
                        time.sleep(min(int(retry_after), 60))
                    else:
                        self._backoff_sleep(attempt)
                continue

            if response.status_code == 401:
                last_error = "invalid_api_key"
                logger.error(
                    f"Invalid HIBP API key - cannot verify breach status for {email}. "
                    f"Treating as INCOMPLETE, not clean."
                )
                break  # config error, retrying won't help

            if response.status_code in (500, 502, 503, 504):
                last_error = f"server_error_{response.status_code}"
                logger.warning(
                    f"[{attempt + 1}/{attempts}] {self.source_name} server error "
                    f"{response.status_code} for {email}"
                )
                if attempt < attempts - 1:
                    self._backoff_sleep(attempt)
                continue

            last_error = f"http_{response.status_code}"
            logger.error(f"Unexpected status {response.status_code} from {self.source_name}")
            break

        logger.error(
            f"Giving up checking {email} on {self.source_name} after {attempts} "
            f"attempt(s) - last_error={last_error}. Marking as INCOMPLETE, not clean."
        )
        raise AdapterCheckIncomplete(f"{self.source_name}: {last_error}")

    def _parse_breaches(self, email: str, breaches: list) -> List[BreachEvent]:
        if not breaches:
            logger.debug(f"No breaches found for {email} on {self.source_name} (confirmed clean)")
            return []

        events = []
        for breach in breaches:
            categories = breach.get("DataClasses", []) or []
            is_sensitive = bool(breach.get("IsSensitive", False))

            severity_score, severity_label, is_cred, is_pii = self.score_structured(
                categories, password_risk="unknown", is_sensitive=is_sensitive
            )

            event = self._create_breach_event(
                email=email,
                breach_id=breach.get("Name", "unknown"),
                severity_score=severity_score,
                severity_label=severity_label,
                data_categories=categories or ["unknown"],
                is_credential=is_cred,
                is_pii=is_pii,
                password_risk="unknown",  # HIBP doesn't expose hash-strength info
                affected_records=breach.get("PwnCount", 0),
                raw_exposed_data=";".join(categories),
                raw_response={"breach": breach},
            )
            events.append(event)
            logger.info(f"Found breach for {email}: {event}")

        return events
