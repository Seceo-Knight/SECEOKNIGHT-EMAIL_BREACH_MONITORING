"""
SECEOKNIGHT Database Module
File: lib/database.py
Purpose: SQLite database management with audit trails and statistics
"""

import sqlite3
import logging
from datetime import datetime
from typing import List, Optional, Dict

logger = logging.getLogger(__name__)


class SECEOKnightDatabase:
    """SQLite database for SECEOKNIGHT."""

    def __init__(self, db_path: str):
        """Initialize database."""
        self.db_path = db_path
        self.conn = None
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")

        cursor = self.conn.cursor()

        # Emails table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_scanned TIMESTAMP,
                scan_count INTEGER DEFAULT 0
            )
        """)

        # Breaches table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS breaches (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL,
                source TEXT NOT NULL,
                breach_id TEXT NOT NULL,
                severity_score REAL NOT NULL,
                severity_label TEXT NOT NULL,
                data_exposed TEXT,
                affected_records INTEGER DEFAULT 0,
                is_credential_breach INTEGER DEFAULT 0,
                is_pii_breach INTEGER DEFAULT 0,
                detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                alerted INTEGER DEFAULT 0,
                alert_time TIMESTAMP,
                FOREIGN KEY(email) REFERENCES emails(email),
                UNIQUE(email, source, breach_id)
            )
        """)

        # Scan history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY,
                scan_type TEXT NOT NULL,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                emails_scanned INTEGER DEFAULT 0,
                breaches_found INTEGER DEFAULT 0,
                duration_seconds REAL DEFAULT 0,
                status TEXT DEFAULT 'success'
            )
        """)

        # Statistics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY,
                stat_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_breaches INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                credential_breaches INTEGER DEFAULT 0,
                unique_breaches_today INTEGER DEFAULT 0
            )
        """)

        self.conn.commit()
        logger.info(f"Database initialized: {self.db_path}")

    def add_email(self, email: str):
        """Add email to tracking list."""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO emails (email) VALUES (?)",
                (email,)
            )
            self.conn.commit()
            logger.debug(f"Added email to tracking: {email}")
        except Exception as e:
            logger.error(f"Error adding email: {e}")

    def record_breach(self, breach_data: dict):
        """
        Record a detected breach.

        Args:
            breach_data: Dict with breach information
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO breaches (
                    email, source, breach_id, severity_score, severity_label,
                    data_exposed, affected_records, is_credential_breach, is_pii_breach
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                breach_data.get("email"),
                breach_data.get("source"),
                breach_data.get("breach_id"),
                breach_data.get("severity_score", 0.0),
                breach_data.get("severity_label", "UNKNOWN"),
                breach_data.get("data_exposed", ""),
                breach_data.get("affected_records", 0),
                1 if breach_data.get("is_credential_breach") else 0,
                1 if breach_data.get("is_pii_breach") else 0,
            ))
            self.conn.commit()
            logger.info(f"Recorded breach: {breach_data['email']} - {breach_data['source']}")
        except Exception as e:
            logger.error(f"Error recording breach: {e}")

    def get_new_breaches(self, hours: int = 24) -> List[Dict]:
        """Get breaches detected in last N hours."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM breaches
                WHERE detection_time > datetime('now', '-' || ? || ' hours')
                ORDER BY severity_score DESC
            """, (hours,))
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error getting new breaches: {e}")
            return []

    def mark_breach_alerted(self, breach_id: int):
        """Mark breach as alerted."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE breaches
                SET alerted = 1, alert_time = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (breach_id,))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Error marking breach as alerted: {e}")

    def record_scan(self, scan_type: str, emails_scanned: int, breaches_found: int, duration: float):
        """Record scan completion."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO scan_history
                (scan_type, emails_scanned, breaches_found, duration_seconds)
                VALUES (?, ?, ?, ?)
            """, (scan_type, emails_scanned, breaches_found, duration))
            self.conn.commit()
            logger.info(
                f"Recorded {scan_type} scan: "
                f"{emails_scanned} emails, "
                f"{breaches_found} breaches, "
                f"{duration:.2f}s"
            )
        except Exception as e:
            logger.error(f"Error recording scan: {e}")

    def get_statistics(self) -> Dict:
        """Get system statistics."""
        try:
            cursor = self.conn.cursor()

            # Total breaches by severity
            cursor.execute("SELECT severity_label, COUNT(*) as count FROM breaches GROUP BY severity_label")
            severity_counts = {row['severity_label']: row['count'] for row in cursor.fetchall()}

            # Total unique breaches
            cursor.execute("SELECT COUNT(DISTINCT breach_id) as count FROM breaches")
            total_unique = cursor.fetchone()['count']

            # Credential breaches
            cursor.execute("SELECT COUNT(*) as count FROM breaches WHERE is_credential_breach = 1")
            credential_count = cursor.fetchone()['count']

            # Recent scans
            cursor.execute("""
                SELECT COUNT(*) as count, SUM(duration_seconds) as total_duration
                FROM scan_history
                WHERE scan_time > datetime('now', '-7 days')
            """)
            recent = cursor.fetchone()

            return {
                "total_unique_breaches": total_unique,
                "credential_breaches": credential_count,
                "by_severity": severity_counts,
                "recent_scans": recent['count'] or 0,
                "total_scan_time_7d": recent['total_duration'] or 0,
            }
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            logger.info("Database closed")
