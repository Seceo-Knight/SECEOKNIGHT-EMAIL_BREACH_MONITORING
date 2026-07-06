"""
SECEOKNIGHT Breach Adapter Module
File: lib/breach_adapter.py
Purpose: Base adapter class, standardized BreachEvent data structure, and
         structured (evidence-based) severity scoring.

CHANGE LOG (enterprise hardening pass):
- Added AdapterCheckIncomplete exception: adapters raise this when a check
  could not be completed (rate limited / timeout / server error) after
  exhausting retries. Callers MUST treat this differently from "no breach
  found" - previously these were silently collapsed into a false "clean"
  result. See scripts/breach_collector.py for how this is now handled.
- Added score_structured(): scores severity using real, structured fields
  the source APIs already provide (exposed data-type list + password
  storage risk), instead of regex/keyword-guessing over a stringified
  Python dict. The old keyword-based _normalize_severity() is kept only
  as a documented fallback for future adapters that don't supply
  structured fields - it is no longer used by the bundled adapters.
- BreachEvent gained a `password_risk` field and to_dict() now emits
  `data_exposed` (previously database.py read a key that was never
  produced, so the column was always blank).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


class AdapterCheckIncomplete(Exception):
    """
    Raised by an adapter when it could not determine whether an email
    appears in a breach (rate limited, timed out, or the source returned
    a server error) after exhausting its retry budget.

    Callers MUST NOT treat this the same as "no breach found". Doing so
    silently converts "we don't know" into a false-negative "clean"
    result, which is the single worst failure mode for a breach monitor.
    """
    pass


@dataclass
class BreachEvent:
    """Standardized breach event data structure."""

    # Source and email
    source: str  # "xposedornot", "hibp", etc.
    email: str
    breach_id: str

    # Severity (CVSS-like approach, 0-10)
    severity_score: float  # 0.0-10.0
    severity_label: str    # "CRITICAL", "HIGH", "MEDIUM", "LOW"

    # Data exposed
    data_categories: List[str] = field(default_factory=list)
    # Examples: ["credentials", "pii", "financial", "government_id", "biometric"]
    raw_exposed_data: str = ""
    affected_records: int = 0

    # How the breach's stored password (if any) was protected. One of:
    # "plaintext", "easytocrack", "hardtocrack", "unknown". Only meaningful
    # when a credential/password category is present.
    password_risk: str = "unknown"

    # Flags
    is_credential_breach: bool = False
    is_pii_breach: bool = False

    # Metadata
    detection_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_response: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization / DB storage."""
        return {
            "source": self.source,
            "email": self.email,
            "breach_id": self.breach_id,
            "severity_score": self.severity_score,
            "severity_label": self.severity_label,
            "data_categories": self.data_categories,
            # database.py's `breaches.data_exposed` column reads this key -
            # previously this key didn't exist in to_dict()'s output at all,
            # so the column was silently always blank.
            "data_exposed": ";".join(self.data_categories) if self.data_categories else "",
            "password_risk": self.password_risk,
            "affected_records": self.affected_records,
            "is_credential_breach": self.is_credential_breach,
            "is_pii_breach": self.is_pii_breach,
            "detection_timestamp": self.detection_timestamp.isoformat(),
        }

    def __str__(self):
        return (
            f"BreachEvent(email={self.email}, source={self.source}, "
            f"severity={self.severity_label}, password_risk={self.password_risk}, "
            f"affected={self.affected_records})"
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
    def check_email(self, email: str) -> List[BreachEvent]:
        """
        Check if email is in a breach.

        Args:
            email: Email address to check

        Returns:
            List of BreachEvent objects. An empty list means the source
            AFFIRMATIVELY confirmed no breach (HTTP 200 / equivalent, zero
            results) - i.e. "clean", not "we didn't check".

        Raises:
            AdapterCheckIncomplete: if the check could not be completed
            after retries (rate limited, timeout, server error). Callers
            must surface this as "unknown", never as "clean".
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Structured (evidence-based) severity scoring
    # ------------------------------------------------------------------
    @staticmethod
    def score_structured(
        data_categories: List[str],
        password_risk: str = "unknown",
        is_sensitive: bool = False,
    ) -> tuple:
        """
        Score severity using real, structured "what was exposed" data that
        the source API already provides (e.g. XposedOrNot's `xposed_data`
        field, HIBP's `DataClasses`) - NOT a keyword search over a
        stringified dict, which is unreliable (a bare breach name like
        {"name": "Adobe"} contains no information about what Adobe's
        breach actually exposed, and can spuriously match on structural
        text like the literal dict key "name").

        Args:
            data_categories: list of exposed data type strings, e.g.
                ["Email addresses", "Passwords", "Usernames"]
            password_risk: "plaintext" | "easytocrack" | "hardtocrack" |
                "unknown" - how well (if at all) an exposed password was
                protected. Only meaningful if a password category exists.
            is_sensitive: source-flagged as an especially damaging /
                sensitive breach (e.g. HIBP's IsSensitive).

        Returns:
            (severity_score, severity_label, is_credential_breach, is_pii_breach)
        """
        categories_lower = [c.lower() for c in (data_categories or [])]
        joined = " ".join(categories_lower)
        password_risk = (password_risk or "unknown").lower()

        has_password = any(
            kw in joined for kw in ("password", "pwd", "credential", "auth")
        )
        has_gov_id = any(
            kw in joined
            for kw in ("social security", "ssn", "passport", "driver", "national id", "government id", "tax id")
        )
        has_financial = any(
            kw in joined
            for kw in ("credit card", "debit card", "cvv", "bank account", "payment", "financial", "iban")
        )
        has_pii = any(
            kw in joined
            for kw in (
                "email", "name", "phone", "address", "date of birth", "gender",
                "location", "ip address", "username",
            )
        )

        is_credential = False
        is_pii = False

        if has_password:
            is_credential = True
            if password_risk == "plaintext":
                score = 10.0
            elif password_risk == "easytocrack":
                score = 9.5
            elif password_risk == "hardtocrack":
                score = 8.0
            else:  # unknown crack difficulty - a leaked password is serious regardless
                score = 8.5
        elif has_gov_id:
            score = 8.5
        elif has_financial:
            score = 8.0
        elif has_pii:
            score = 5.0
            is_pii = True
        elif categories_lower:
            # Source gave us categories, just none we specifically recognize
            # (e.g. only "Usernames" or "Geographic locations").
            score = 3.5
        else:
            # No structured category data at all - lowest confidence.
            score = 2.0

        if is_sensitive:
            score = max(score, 8.5)

        if score >= 8.5:
            label = "CRITICAL"
        elif score >= 7.5:
            label = "HIGH"
        elif score >= 5.0:
            label = "MEDIUM"
        else:
            label = "LOW"

        logger.debug(
            f"Structured severity: {score} ({label}), credential={is_credential}, "
            f"pii={is_pii}, password_risk={password_risk}, categories={data_categories}"
        )

        return score, label, is_credential, is_pii

    # ------------------------------------------------------------------
    # Legacy fallback scorer - kept ONLY for adapters that cannot supply
    # structured category data. Not used by the bundled xposedornot/hibp
    # adapters anymore. Known weakness: matches keywords against a
    # stringified dict, which can false-positive on the dict's own key
    # names rather than actual content (e.g. {"name": "Adobe"} contains
    # the literal substring "name", which is also a PII keyword).
    # ------------------------------------------------------------------
    def _normalize_severity(self, breach_data: dict) -> tuple:
        """
        Legacy keyword-guessing severity fallback.

        Returns:
            (severity_score, severity_label, is_credential_breach, is_pii_breach, data_categories)
        """
        score = 0.0
        is_credential = False
        is_pii = False
        data_cats = []
        text = str(breach_data).lower()

        credential_keywords = [
            "password", "passwords", "credential", "credentials", "hash",
            "authentication", "auth", "secret"
        ]
        if any(k in text for k in credential_keywords):
            score = max(score, 9.0)
            is_credential = True
            data_cats.append("credentials")

        gov_keywords = ["ssn", "social security", "passport", "driver", "license"]
        if any(k in text for k in gov_keywords):
            score = max(score, 8.5)
            data_cats.append("government_id")

        fin_keywords = ["credit card", "cvv", "payment", "bank account", "financial", "transaction"]
        if any(k in text for k in fin_keywords):
            score = max(score, 8.0)
            data_cats.append("financial")

        personal_keywords = ["address", "phone number", "personal", "profile"]
        if any(k in text for k in personal_keywords):
            score = max(score, 5.0)
            is_pii = True
            data_cats.append("pii")

        if score == 0.0:
            score = 3.0
            data_cats.append("unknown")

        if score >= 8.5:
            label = "CRITICAL"
        elif score >= 7.5:
            label = "HIGH"
        elif score >= 5.0:
            label = "MEDIUM"
        else:
            label = "LOW"

        return score, label, is_credential, is_pii, data_cats

    def _create_breach_event(
        self,
        email: str,
        breach_id: str,
        severity_score: float,
        severity_label: str,
        data_categories: List[str],
        is_credential: bool,
        is_pii: bool,
        password_risk: str = "unknown",
        affected_records: int = 0,
        raw_exposed_data: str = "",
        raw_response: dict = None,
    ) -> BreachEvent:
        """Create a standardized BreachEvent from already-scored data."""
        event = BreachEvent(
            source=self.source_name,
            email=email,
            breach_id=breach_id,
            severity_score=severity_score,
            severity_label=severity_label,
            data_categories=data_categories,
            raw_exposed_data=raw_exposed_data or str(data_categories),
            affected_records=affected_records,
            password_risk=password_risk,
            is_credential_breach=is_credential,
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
