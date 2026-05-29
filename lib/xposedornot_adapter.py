"""
SECEOKNIGHT XposedOrNot Adapter - FINAL WORKING VERSION
File: lib/xposedornot_adapter.py
Purpose: Integration with XposedOrNot API (free tier)
FIXED: Handles API response as array of strings, not objects
"""

import logging
import time
from typing import Optional, List
import requests
from datetime import datetime

from breach_adapter import BreachAdapter, BreachEvent

logger = logging.getLogger(__name__)


class XposedOrNotAdapter(BreachAdapter):
    """XposedOrNot API integration."""

    API_BASE = "https://api.xposedornot.com"
    API_ENDPOINT = f"{API_BASE}/v1/check-email"

    def __init__(self, config: dict):
        """Initialize adapter from config."""
        super().__init__(config)
        self.source_name = "xposedornot"
        self.last_request_time = 0
        logger.info(f"Initialized {self.source_name} adapter")

    def _rate_limit(self):
        """Enforce rate limiting between requests."""
        elapsed = time.time() - self.last_request_time
        min_delay = 1.0 / self.rate_limit

        if elapsed < min_delay:
            time.sleep(min_delay - elapsed)

        self.last_request_time = time.time()

    def check_email(self, email: str) -> Optional[List[BreachEvent]]:
        """
        Check if email is exposed on XposedOrNot.

        Args:
            email: Email to check

        Returns:
            List of BreachEvent objects or empty list if not found/error
        """
        if not self.enabled:
            logger.debug(f"{self.source_name} is disabled, skipping")
            return []

        # ENFORCE RATE LIMIT BEFORE REQUEST
        self._rate_limit()

        try:
            logger.debug(f"Checking {email} on {self.source_name}")

            # Make API request with CORRECT ENDPOINT
            response = requests.get(
                f"{self.API_ENDPOINT}/{email}",
                timeout=10,
                headers={"User-Agent": "SECEOKNIGHT/1.0"}
            )

            # Handle rate limit responses (IP banned)
            if response.status_code == 429:
                try:
                    data = response.json()
                    detail = data.get("detail", {})

                    if isinstance(detail, dict) and "violation_count" in detail:
                        violations = detail.get("violation_count")
                        drop_pct = detail.get("drop_percentage", "unknown")
                        logger.warning(
                            f"IP rate limited with {violations} violations ({drop_pct} drop rate). "
                            f"Wait 1-2 hours before retrying."
                        )
                    else:
                        logger.warning(f"Rate limited by {self.source_name} - waiting 5s...")
                        time.sleep(5.0)
                except:
                    logger.warning(f"Rate limited by {self.source_name} - waiting 5s...")
                    time.sleep(5.0)

                return []

            # Handle not found (email not in breaches)
            if response.status_code == 404:
                logger.debug(f"{email} not found on {self.source_name}")
                return []

            # Handle unexpected status codes
            if response.status_code != 200:
                logger.error(f"Unexpected status {response.status_code} from {self.source_name}")
                return []

            # Parse successful response
            data = response.json()

            # Check for error response
            if "Error" in data:
                logger.debug(f"API error for {email}: {data['Error']}")
                return []

            # FIX: Handle breaches as array of strings, not objects
            if not data or not data.get("breaches"):
                logger.debug(f"No breaches found for {email}")
                return []

            breaches_list = data.get("breaches", [])

            # If breaches is empty list
            if not breaches_list:
                logger.debug(f"No breaches found for {email}")
                return []

            # breaches_list is a list containing one element: an array of breach names
            # e.g., [["Adobe", "LinkedIn", "ShareThis", ...]]
            if isinstance(breaches_list, list) and len(breaches_list) > 0:
                breach_names = breaches_list[0]  # Get the array of names

                if not breach_names:
                    logger.debug(f"No breaches found for {email}")
                    return []

                # Convert each breach name to BreachEvent
                events = []
                for breach_name in breach_names:
                    event = self._create_breach_event(
                        email=email,
                        breach_id=breach_name,  # Use the breach name directly
                        raw_data={"name": breach_name},
                        affected_records=0,  # Unknown from this API
                        raw_response=data
                    )
                    events.append(event)
                    logger.info(f"Found breach for {email}: {event}")

                return events if events else []

            return []

        except requests.exceptions.Timeout:
            logger.error(f"Timeout checking {email} on {self.source_name}")
            return []
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error checking {email}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error checking {email}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return []
