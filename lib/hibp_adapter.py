"""
SECEOKNIGHT Have I Been Pwned Adapter
File: lib/hibp_adapter.py
Purpose: Integration with HIBP API (free and paid tiers)
"""

import logging
from typing import Optional, List
import requests

from breach_adapter import BreachAdapter, BreachEvent

logger = logging.getLogger(__name__)


class HaveIBeenPwnedAdapter(BreachAdapter):
    """Have I Been Pwned API integration."""

    API_BASE = "https://haveibeenpwned.com/api/v3"
    BREACHES_ENDPOINT = f"{API_BASE}/breachedaccount"

    def __init__(self, config: dict):
        """
        Initialize adapter.

        Automatically detects tier:
        - api_key=None → Free tier (1.5 req/sec)
        - api_key="key" → Paid tier (10+ req/sec)
        """
        super().__init__(config)
        self.source_name = "hibp"
        self.api_key = config.get("api_key")

        if self.api_key:
            logger.info(f"Using HIBP PAID tier (API key configured)")
        else:
            logger.info(f"Using HIBP FREE tier (no API key)")

    def check_email(self, email: str) -> Optional[List[BreachEvent]]:
        """
        Check if email is in HIBP database.

        Args:
            email: Email to check

        Returns:
            List of BreachEvent objects or None if not found/error
        """
        if not self.enabled:
            logger.debug(f"{self.source_name} is disabled, skipping")
            return None

        try:
            logger.debug(f"Checking {email} on {self.source_name}")

            # Build headers
            headers = {"User-Agent": "SECEOKNIGHT/1.0"}
            if self.api_key:
                headers["hibp-api-key"] = self.api_key

            # Make API request
            response = requests.get(
                self.BREACHES_ENDPOINT,
                params={"email": email},
                headers=headers,
                timeout=10
            )

            # Handle responses
            if response.status_code == 404:
                logger.debug(f"{email} not found on {self.source_name}")
                return None

            if response.status_code == 429:
                logger.warning(f"Rate limited by {self.source_name}")
                return None

            if response.status_code == 401:
                logger.error(f"Invalid HIBP API key")
                return None

            if response.status_code != 200:
                logger.error(f"Unexpected status {response.status_code} from {self.source_name}")
                return None

            # Parse response
            breaches = response.json()

            if not breaches:
                logger.debug(f"No breaches found for {email}")
                return None

            # Convert each breach to BreachEvent
            events = []
            for breach in breaches:
                event = self._create_breach_event(
                    email=email,
                    breach_id=breach.get("Name", "unknown"),
                    raw_data=breach,
                    affected_records=breach.get("PwnCount", 0),
                    raw_response={"breaches": breaches}
                )
                events.append(event)
                logger.info(f"Found breach for {email}: {event}")

            return events if events else None

        except requests.exceptions.Timeout:
            logger.error(f"Timeout checking {email} on {self.source_name}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error checking {email}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return None
