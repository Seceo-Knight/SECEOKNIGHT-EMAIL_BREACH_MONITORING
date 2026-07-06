"""
SECEOKNIGHT XposedOrNot Adapter - Enterprise Edition
File: lib/xposedornot_adapter.py
Purpose: Integration with XposedOrNot's breach-analytics API.

CHANGE LOG (enterprise hardening pass, verified against
https://xposedornot.com/api_doc, checked Jul 2026):
- Switched from GET /v1/check-email/{email} to GET /v1/breach-analytics
  ?email={email}. The old endpoint only returns an array of breach NAMES
  (e.g. "Adobe"), which carries no information about what was actually
  exposed - severity scoring on that payload was effectively guessing.
  breach-analytics returns structured per-breach fields (`xposed_data`,
  `password_risk`, `xposed_records`) that make real severity scoring
  possible.
- Confirmed XposedOrNot's documented limit is 2 requests/second per IP
  (not the 60/hour figure previously assumed in this project's README).
  Configured rate_limit is clamped to this ceiling defensively.
- 429 / timeout / 5xx responses now trigger real retry with exponential
  backoff (previously: a single non-retried 5s sleep, then give up).
  After retries are exhausted, raises AdapterCheckIncomplete instead of
  returning an empty list - this was the root cause of confirmed
  false-CLEAN results in production (test@yahoo.com was rate-limited and
  silently logged as "no breaches found").
- "Not found" (email genuinely clean) is now detected correctly for this
  endpoint: the API returns HTTP 200 with all-null fields for a clean
  email, NOT a 404. The old code path assumed 404 == not-found, which
  is a check-email-endpoint-specific behavior that does not apply here.

CHANGE LOG (2nd pass, based on a live production incident):
- XposedOrNot returns a structured 429 body distinguishing a routine
  rate-limit from a punitive "violation history" block (their abuse
  system, xGuardian) - e.g. {"error":"Request dropped due to violation
  history","violation_count":7,"drop_percentage":"80%"}. We observed
  live that retrying into an ACTIVE violation-history block just adds
  more violations and prolongs the penalty rather than helping - the
  penalty clears with elapsed wall-clock time, not with slower request
  pacing. So: on detecting this specific signal, we now (a) stop
  retrying immediately for that email instead of burning the remaining
  attempts into a confirmed block, and (b) set a hard-block cooldown
  (default 30 minutes) during which every subsequent check on this
  adapter instance fails fast with AdapterCheckIncomplete and makes NO
  further HTTP requests at all, for the rest of this scan run.
- Default rate_limit lowered (see config/breach_sources.yml.example)
  to add more headroom below the documented 2 req/s ceiling, reducing
  how often this situation gets triggered in the first place.
"""

import logging
import time
from typing import List
import requests

from breach_adapter import BreachAdapter, BreachEvent, AdapterCheckIncomplete

logger = logging.getLogger(__name__)


class XposedOrNotAdapter(BreachAdapter):
    """XposedOrNot breach-analytics API integration."""

    API_BASE = "https://api.xposedornot.com"
    ANALYTICS_ENDPOINT = f"{API_BASE}/v1/breach-analytics"

    # Documented at https://xposedornot.com/api_doc - "Rate Limit: 2 requests
    # per second per IP". Config values above this are clamped.
    DOCUMENTED_RATE_LIMIT = 2.0

    def __init__(self, config: dict):
        """Initialize adapter from config."""
        super().__init__(config)
        self.source_name = "xposedornot"
        self.last_request_time = 0
        self.max_retries = int(config.get("max_retries", 3) or 3)
        self.timeout = int(config.get("timeout", 10) or 10)

        # How long to stop hitting the API entirely after we've been told
        # (via a structured 429 body) that we're in an active abuse-penalty
        # window. Configurable via `hard_block_cooldown_seconds` in
        # breach_sources.yml; defaults to 30 minutes.
        self.hard_block_cooldown = int(config.get("hard_block_cooldown_seconds", 1800) or 1800)
        self.hard_block_until = 0.0  # epoch timestamp; 0 = not blocked

        if self.rate_limit > self.DOCUMENTED_RATE_LIMIT:
            logger.warning(
                f"Configured rate_limit={self.rate_limit}/s exceeds XposedOrNot's "
                f"documented ceiling of {self.DOCUMENTED_RATE_LIMIT}/s - clamping to "
                f"avoid tripping the vendor's abuse detection (xGuardian)."
            )
            self.rate_limit = self.DOCUMENTED_RATE_LIMIT

        logger.info(
            f"Initialized {self.source_name} adapter "
            f"(breach-analytics endpoint, {self.rate_limit} req/s, "
            f"max_retries={self.max_retries})"
        )

    def _throttle(self):
        """Enforce minimum spacing between requests (persists across calls
        on this adapter instance, unlike the collector-level limiter which
        used to be recreated per call)."""
        elapsed = time.time() - self.last_request_time
        min_delay = 1.0 / self.rate_limit
        if elapsed < min_delay:
            time.sleep(min_delay - elapsed)
        self.last_request_time = time.time()

    def _backoff_sleep(self, attempt: int):
        delay = min(2 ** attempt, 30)
        logger.debug(f"Backing off {delay}s before retry (attempt {attempt + 1})")
        time.sleep(delay)

    def check_email(self, email: str) -> List[BreachEvent]:
        """
        Check if email is exposed on XposedOrNot using breach-analytics.

        Returns:
            [] if the API affirmatively confirmed no breach (HTTP 200,
            all-null body).

        Raises:
            AdapterCheckIncomplete if the check could not be completed
            after retries. Callers MUST NOT treat this as "clean".
        """
        if not self.enabled:
            logger.debug(f"{self.source_name} is disabled, skipping")
            return []

        now = time.time()
        if now < self.hard_block_until:
            remaining = int(self.hard_block_until - now)
            logger.warning(
                f"{self.source_name} is in a confirmed abuse-penalty cooldown "
                f"({remaining}s remaining) - skipping {email} with NO API call "
                f"to avoid adding further violations."
            )
            raise AdapterCheckIncomplete(f"{self.source_name}: hard_blocked ({remaining}s remaining)")

        last_error = "unknown"
        attempts = self.max_retries + 1

        for attempt in range(attempts):
            self._throttle()

            try:
                response = requests.get(
                    self.ANALYTICS_ENDPOINT,
                    params={"email": email},
                    timeout=self.timeout,
                    headers={"User-Agent": "SECEOKNIGHT/1.0"},
                )
            except requests.exceptions.Timeout:
                last_error = "timeout"
                logger.warning(
                    f"[{attempt + 1}/{attempts}] Timeout checking {email} on {self.source_name}"
                )
                if attempt < attempts - 1:
                    self._backoff_sleep(attempt)
                continue
            except requests.exceptions.RequestException as e:
                last_error = f"request_error: {e}"
                logger.warning(
                    f"[{attempt + 1}/{attempts}] Request error for {email}: {e}"
                )
                if attempt < attempts - 1:
                    self._backoff_sleep(attempt)
                continue

            if response.status_code == 200:
                try:
                    return self._parse_analytics(email, response.json())
                except ValueError:
                    last_error = "invalid_json"
                    logger.error(f"Invalid JSON from {self.source_name} for {email}")
                    break

            if response.status_code == 404:
                # This endpoint's documented "no data found" status.
                logger.debug(f"{email} not found on {self.source_name} (404)")
                return []

            if response.status_code == 429:
                last_error = "rate_limited"
                try:
                    detail = response.json().get("detail", {})
                except ValueError:
                    detail = {}

                if isinstance(detail, dict) and "violation_count" in detail:
                    # This is XposedOrNot's punitive abuse-penalty response,
                    # not a routine rate limit. We confirmed live that
                    # retrying into this state just adds more violations and
                    # prolongs the block - it clears with elapsed time, not
                    # with more (even slower) requests. Stop immediately:
                    # don't burn remaining retry attempts, and don't let any
                    # other email checked on this adapter instance hit the
                    # API again until the cooldown passes.
                    violations = detail.get("violation_count")
                    drop_pct = detail.get("drop_percentage", "unknown")
                    self.hard_block_until = time.time() + self.hard_block_cooldown
                    logger.error(
                        f"{self.source_name} confirmed abuse-penalty active "
                        f"({violations} violations, {drop_pct} drop rate) - "
                        f"NOT retrying, and pausing all further {self.source_name} "
                        f"requests for {self.hard_block_cooldown}s to let it clear."
                    )
                    last_error = f"hard_blocked ({violations} violations, {drop_pct} drop)"
                    break

                logger.warning(
                    f"[{attempt + 1}/{attempts}] Rate limited (429) by "
                    f"{self.source_name} checking {email}"
                )
                if attempt < attempts - 1:
                    self._backoff_sleep(attempt)
                continue

            if response.status_code in (500, 502, 503, 504):
                last_error = f"server_error_{response.status_code}"
                logger.warning(
                    f"[{attempt + 1}/{attempts}] {self.source_name} server error "
                    f"{response.status_code} for {email}"
                )
                if attempt < attempts - 1:
                    self._backoff_sleep(attempt)
                continue

            # Unexpected status code - don't retry, don't silently swallow.
            last_error = f"http_{response.status_code}"
            logger.error(
                f"Unexpected status {response.status_code} from {self.source_name} "
                f"for {email}"
            )
            break

        logger.error(
            f"Giving up checking {email} on {self.source_name} after {attempts} "
            f"attempt(s) - last_error={last_error}. Marking as INCOMPLETE, not clean."
        )
        raise AdapterCheckIncomplete(f"{self.source_name}: {last_error}")

    def _parse_analytics(self, email: str, data: dict) -> List[BreachEvent]:
        """Parse a breach-analytics response into BreachEvents."""
        exposed = data.get("ExposedBreaches")
        if not exposed or not exposed.get("breaches_details"):
            logger.debug(f"No breaches found for {email} on {self.source_name} (confirmed clean)")
            return []

        events = []
        for detail in exposed["breaches_details"]:
            breach_id = detail.get("breach", "unknown")
            xposed_data_str = detail.get("xposed_data", "") or ""
            categories = [c.strip() for c in xposed_data_str.split(";") if c.strip()]
            password_risk = (detail.get("password_risk") or "unknown").lower()
            records = detail.get("xposed_records", 0) or 0

            severity_score, severity_label, is_cred, is_pii = self.score_structured(
                categories, password_risk
            )

            event = self._create_breach_event(
                email=email,
                breach_id=breach_id,
                severity_score=severity_score,
                severity_label=severity_label,
                data_categories=categories or ["unknown"],
                is_credential=is_cred,
                is_pii=is_pii,
                password_risk=password_risk,
                affected_records=records,
                raw_exposed_data=xposed_data_str,
                raw_response={"detail": detail},
            )
            events.append(event)
            logger.info(
                f"Found breach for {email}: {event} "
                f"(domain={detail.get('domain')}, verified={detail.get('verified')})"
            )

        return events
