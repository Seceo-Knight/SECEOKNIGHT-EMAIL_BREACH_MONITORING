"""
SECEOKNIGHT XposedOrNot Adapter
File: lib/xposedornot_adapter.py
Purpose: Integration with XposedOrNot API (free tier - 60 requests/hour)
"""

import logging
from typing import Optional, List
import requests

from breach_adapter import BreachAdapter, BreachEvent

logger = logging.getLogger(__name__)


class XposedOrNotAdapter(BreachAdapter):
    """XposedOrNot API integration."""

    API_BASE = "https://api.xposedornot.com"
    API_ENDPOINT = f"{API_BASE}/v4/check"

    def __init__(self, config: dict):
        """Initialize adapter from config."""
        super().__init__(config)
        self.source_name = "xposedornot"
        logger.info(f"Initialized {self.source_name} adapter")

    def check_email(self, email: str) -> Optional[List[BreachEvent]]:
        """
        Check if email is exposed on XposedOrNot.

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

            # Make API request
            response = requests.get(
                self.API_ENDPOINT,
                params={"email": email},
                timeout=10,
                headers={"User-Agent": "SECEOKNIGHT/1.0"}
            )

            # Handle responses
            if response.status_code == 404:
                logger.debug(f"{email} not found on {self.source_name}")
                return None

            if response.status_code == 429:
                logger.warning(f"Rate limited by {self.source_name}")
                return None

            if response.status_code != 200:
                logger.error(f"Unexpected status {response.status_code} from {self.source_name}")
                return None

            # Parse response
            data = response.json()

            if not data or not data.get("breaches"):
                logger.debug(f"No breaches found for {email}")
                return None

            # Convert each breach to BreachEvent
            events = []
            for breach in data["breaches"]:
                event = self._create_breach_event(
                    email=email,
                    breach_id=breach.get("name", "unknown"),
                    raw_data=breach,
                    affected_records=breach.get("affected_records", 0),
                    raw_response=data
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
