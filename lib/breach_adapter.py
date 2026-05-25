"""
SECEOKNIGHT Breach Adapter Module
File: lib/breach_adapter.py
Purpose: Base adapter class and standardized BreachEvent data structure
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class BreachEvent:
    """Standardized breach event data structure."""

    # Source and email
    source: str  # "xposedornot", "hibp", etc.
    email: str
    breach_id: str

    # Severity (CVSS-based, 0-10)
    severity_score: float  # 0.0-10.0
    severity_label: str    # "CRITICAL", "HIGH", "MEDIUM", "LOW"

    # Data exposed
    data_categories: List[str] = field(default_factory=list)
    # Examples: ["credentials", "pii", "financial", "government_id", "biometric"]
    raw_exposed_data: str = ""
    affected_records: int = 0

    # Flags
    is_credential_breach: bool = False
    is_pii_breach: bool = False

    # Metadata
    detection_timestamp: datetime = field(default_factory=datetime.utcnow)
    raw_response: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "source": self.source,
            "email": self.email,
            "breach_id": self.breach_id,
            "severity_score": self.severity_score,
            "severity_label": self.severity_label,
            "data_categories": self.data_categories,
            "affected_records": self.affected_records,
            "is_credential_breach": self.is_credential_breach,
            "is_pii_breach": self.is_pii_breach,
            "detection_timestamp": self.detection_timestamp.isoformat(),
        }

    def __str__(self):
        return (
            f"BreachEvent(email={self.email}, source={self.source}, "
            f"severity={self.severity_label}, affected={self.affected_records})"
        )


class BreachAdapter(ABC):
    """Base adapter for breach detection sources."""

    def __init__(self, config: dict):
        """
        Args:
            config: Source configuration dict
        """
        self.config = config
        self.enabled = config.get("enabled", False)
        self.rate_limit = config.get("rate_limit", 1.0)
        self.priority = config.get("priority", 10)
        self.source_name = config.get("name", self.__class__.__name__)

    @abstractmethod
    def check_email(self, email: str) -> Optional[List[BreachEvent]]:
        """
        Check if email is in a breach.

        Args:
            email: Email address to check

        Returns:
            List of BreachEvent objects if breaches found, else None
        """
        pass

    def _normalize_severity(self, breach_data: dict) -> tuple:
        """
        Calculate severity using CVSS approach based on data exposed.

        Returns:
            (severity_score, severity_label, is_credential_breach, is_pii_breach)
        """
        score = 0.0
        is_credential = False
        is_pii = False
        data_cats = []

        # Check for credentials (highest severity)
        credential_keywords = [
            "password", "passwords", "credential", "credentials", "hash",
            "account", "login", "authentication", "auth", "secret"
        ]
        for keyword in credential_keywords:
            if keyword.lower() in str(breach_data).lower():
                score = max(score, 9.0)
                is_credential = True
                if "credentials" not in data_cats:
                    data_cats.append("credentials")
                break

        # Government IDs (high severity)
        gov_keywords = ["ssn", "social security", "passport", "driver", "license"]
        for keyword in gov_keywords:
            if keyword.lower() in str(breach_data).lower():
                score = max(score, 8.5)
                if "government_id" not in data_cats:
                    data_cats.append("government_id")
                break

        # Financial data (high severity)
        fin_keywords = [
            "credit", "card", "cvv", "payment", "bank", "account",
            "financial", "transaction"
        ]
        for keyword in fin_keywords:
            if keyword.lower() in str(breach_data).lower():
                score = max(score, 8.0)
                if "financial" not in data_cats:
                    data_cats.append("financial")
                break

        # Personal info (medium severity)
        personal_keywords = [
            "name", "address", "phone", "phone number", "email", "email address",
            "personal", "profile", "information"
        ]
        for keyword in personal_keywords:
            if keyword.lower() in str(breach_data).lower():
                score = max(score, 5.0)
                is_pii = True
                if "pii" not in data_cats:
                    data_cats.append("pii")
                break

        # Default if nothing matched
        if score == 0.0:
            score = 3.0  # Unknown
            data_cats.append("unknown")

        # Determine label
        if score >= 8.5:
            label = "CRITICAL"
        elif score >= 7.5:
            label = "HIGH"
        elif score >= 5.0:
            label = "MEDIUM"
        else:
            label = "LOW"

        logger.debug(
            f"Severity calculated: {score} ({label}), "
            f"credential={is_credential}, pii={is_pii}, categories={data_cats}"
        )

        return score, label, is_credential, is_pii, data_cats

    def _create_breach_event(
        self,
        email: str,
        breach_id: str,
        raw_data: dict,
        affected_records: int = 0,
        raw_response: dict = None
    ) -> BreachEvent:
        """
        Create standardized BreachEvent from raw API response.

        Args:
            email: Email address
            breach_id: Breach identifier
            raw_data: Raw breach data
            affected_records: Number of affected records
            raw_response: Original API response

        Returns:
            BreachEvent object
        """
        severity_score, severity_label, is_cred, is_pii, data_cats = (
            self._normalize_severity(raw_data)
        )

        event = BreachEvent(
            source=self.source_name,
            email=email,
            breach_id=breach_id,
            severity_score=severity_score,
            severity_label=severity_label,
            data_categories=data_cats,
            raw_exposed_data=str(raw_data),
            affected_records=affected_records,
            is_credential_breach=is_cred,
            is_pii_breach=is_pii,
            raw_response=raw_response or {},
        )

        logger.info(f"Created {event}")
        return event

    def get_status(self) -> dict:
        """Get adapter status."""
        return {
            "name": self.source_name,
            "enabled": self.enabled,
            "rate_limit": self.rate_limit,
            "priority": self.priority,
        }
