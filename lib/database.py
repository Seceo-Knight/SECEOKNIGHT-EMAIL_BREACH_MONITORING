"""
SECEOKNIGHT Database Module
File: lib/database.py
Purpose: SQLite database management with audit trails and statistics

CHANGE LOG (enterprise hardening pass):
- Added _migrate_schema(): safely ALTERs an already-existing `breaches`
  table to add the `password_risk` column via PRAGMA table_info() checks.
  CREATE TABLE IF NOT EXISTS is a no-op on an existing table, so a plain
  schema bump would NOT have reached a live database that already had
  rows in it - this migration path is required to not lose/orphan
  existing production data.
- record_breach() now returns True/False (was this genuinely a NEW
  breach row, or did it already exist) using cursor.rowcount from the
  INSERT OR IGNORE. This is what makes alert deduplication possible:
  previously nothing distinguished "just found this today" from
  "still have this from 3 weeks ago", so every scan re-logged (and
  Wazuh re-alerted on) every historical breach every single time.
- New rows are marked alerted=1 / alert_time=NOW at insert time, since
  the collector only calls record_breach() for events it's about to log.
  mark_breach_alerted() is kept for any future manual/backfill use.
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
        self._migrate_schema()

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
                password_risk TEXT DEFAULT 'unknown',
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
                new_breaches_found INTEGER DEFAULT 0,
                incomplete_checks INTEGER DEFAULT 0,
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

    def _migrate_schema(self):
        """
        Additive-only migration for databases created before this version.
        Safe to run every startup - checks PRAGMA table_info() before
        altering, so it's a no-op on an already-current schema.
        """
        migrations = [
            ("breaches", "password_risk", "TEXT DEFAULT 'unknown'"),
            ("scan_history", "new_breaches_found", "INTEGER DEFAULT 0"),
            ("scan_history", "incomplete_checks", "INTEGER DEFAULT 0"),
        ]
        cursor = self.conn.cursor()
        for table, column, coltype in migrations:
            cursor.execute(f"PRAGMA table_info({table})")
            existing_columns = {row["name"] for row in cursor.fetchall()}
            if column not in existing_columns:
                logger.info(f"Migrating schema: adding {table}.{column}")
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
        self.conn.commit()

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

    def record_breach(self, breach_data: dict) -> bool:
        """
        Record a detected breach.

        Args:
            breach_data: Dict with breach information (BreachEvent.to_dict())

        Returns:
            True if this was a genuinely NEW (email, source, breach_id)
            combination just inserted; False if it already existed (a
            repeat detection from a prior scan). Callers should only
            log/alert on rows where this returns True, to avoid
            re-alerting on breaches that have already been surfaced.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO breaches (
                    email, source, breach_id, severity_score, severity_label,
                    data_exposed, password_risk, affected_records,
                    is_credential_breach, is_pii_breach, alerted, alert_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
            """, (
                breach_data.get("email"),
                breach_data.get("source"),
                breach_data.get("breach_id"),
                breach_data.get("severity_score", 0.0),
                breach_data.get("severity_label", "UNKNOWN"),
                breach_data.get("data_exposed", ""),
                breach_data.get("password_risk", "unknown"),
                breach_data.get("affected_records", 0),
                1 if breach_data.get("is_credential_breach") else 0,
                1 if breach_data.get("is_pii_breach") else 0,
            ))
            self.conn.commit()
            is_new = cursor.rowcount > 0
            if is_new:
                logger.info(f"Recorded NEW breach: {breach_data['email']} - {breach_data['source']} - {breach_data.get('breach_id')}")
            else:
                logger.debug(f"Breach already known (skipped re-alert): {breach_data['email']} - {breach_data.get('breach_id')}")
            return is_new
        except Exception as e:
            logger.error(f"Error recording breach: {e}")
            return False

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
        """Mark breach as alerted (manual/backfill use - normal flow marks
        this automatically at insert time in record_breach())."""
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

    def record_scan(
        self,
        scan_type: str,
        emails_scanned: int,
        breaches_found: int,
        duration: float,
        new_breaches_found: int = 0,
        incomplete_checks: int = 0,
    ):
        """Record scan completion."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO scan_history
                (scan_type, emails_scanned, breaches_found, new_breaches_found,
                 incomplete_checks, duration_seconds)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (scan_type, emails_scanned, breaches_found, new_breaches_found,
                  incomplete_checks, duration))
            self.conn.commit()
            logger.info(
                f"Recorded {scan_type} scan: "
                f"{emails_scanned} emails, "
                f"{breaches_found} total breach hits ({new_breaches_found} new), "
                f"{incomplete_checks} incomplete checks, "
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

            # Plaintext password exposures (worst case)
            cursor.execute("SELECT COUNT(*) as count FROM breaches WHERE password_risk = 'plaintext'")
            plaintext_count = cursor.fetchone()['count']

            # Recent scans
            cursor.execute("""
                SELECT COUNT(*) as count, SUM(duration_seconds) as total_duration,
                       SUM(incomplete_checks) as total_incomplete
                FROM scan_history
                WHERE scan_time > datetime('now', '-7 days')
            """)
            recent = cursor.fetchone()

            return {
                "total_unique_breaches": total_unique,
                "credential_breaches": credential_count,
                "plaintext_password_breaches": plaintext_count,
                "by_severity": severity_counts,
                "recent_scans": recent['count'] or 0,
                "total_scan_time_7d": recent['total_duration'] or 0,
                "incomplete_checks_7d": recent['total_incomplete'] or 0,
            }
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            logger.info("Database closed")
