"""
Persistent SQLite database layer for CyberShield: Login Event Monitor.
Handles concurrent access with WAL mode and thread locks.
"""

import sqlite3
import os
import json
import threading
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from models import format_utc_timestamp

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybershield.db")
_db_lock = threading.Lock()


def get_connection() -> sqlite3.Connection:
    """Creates a configured sqlite3 connection with dict-like row access."""
    conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 10000;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """Initializes all database tables and indexes if they do not exist."""
    with _db_lock:
        conn = get_connection()
        cursor = conn.cursor()

        # 1. Events Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                account_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_account ON events (account_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_status ON events (status);")

        # 2. Rejected Events Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rejected_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT,
                payload TEXT NOT NULL,
                reason TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
        """)

        # 3. Account Statistics Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS account_stats (
                account_id TEXT PRIMARY KEY,
                total_attempts INTEGER DEFAULT 0,
                successful_logins INTEGER DEFAULT 0,
                failed_logins INTEGER DEFAULT 0,
                first_event_time TEXT,
                latest_event_time TEXT,
                risk_level TEXT DEFAULT 'LOW',
                alert_count INTEGER DEFAULT 0,
                updated_at TEXT NOT NULL
            );
        """)

        # 4. Account Distinct Sources Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS account_sources (
                account_id TEXT NOT NULL,
                source TEXT NOT NULL,
                PRIMARY KEY (account_id, source)
            );
        """)

        # 5. Alerts Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                account_id TEXT,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                reason TEXT NOT NULL,
                related_events TEXT,
                status TEXT DEFAULT 'OPEN',
                reviewed_at TEXT,
                notes TEXT
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_account ON alerts (account_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);")

        # 6. Detection Rule Configs Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rule_configs (
                rule_name TEXT PRIMARY KEY,
                enabled INTEGER DEFAULT 1,
                config_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)

        # 7. System Settings Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        """)

        # Default Settings
        cursor.execute("""
            INSERT OR IGNORE INTO system_settings (key, value)
            VALUES ('unknown_account_policy', 'AUTO_CREATE');
        """)
        cursor.execute("""
            INSERT OR IGNORE INTO system_settings (key, value)
            VALUES ('polling_interval_ms', '1000');
        """)

        conn.commit()
        conn.close()


def save_event(event_dict: Dict[str, Any]) -> bool:
    """
    Saves an event. Returns True if inserted, False if duplicate event_id.
    """
    with _db_lock:
        conn = get_connection()
        try:
            now_iso = format_utc_timestamp()
            conn.execute("""
                INSERT INTO events (event_id, account_id, timestamp, source, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                event_dict["event_id"],
                event_dict["account_id"],
                event_dict["timestamp"],
                event_dict["source"],
                event_dict["status"],
                event_dict.get("created_at") or now_iso
            ))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Duplicate event_id
            return False
        finally:
            conn.close()


def check_event_exists(event_id: str) -> bool:
    """Checks whether an event_id is already in the database."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM events WHERE event_id = ? LIMIT 1", (event_id,))
        return cursor.fetchone() is not None
    finally:
        conn.close()


def save_rejected_event(event_id: Optional[str], payload: Dict[str, Any], reason: str, rule_name: str) -> int:
    """Records a rejected or malformed event."""
    with _db_lock:
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO rejected_events (event_id, payload, reason, rule_name, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (
                event_id or "UNKNOWN",
                json.dumps(payload),
                reason,
                rule_name,
                format_utc_timestamp()
            ))
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()


def update_account_stats(stats_dict: Dict[str, Any], new_source: Optional[str] = None):
    """Updates account statistics and records sources in SQLite atomically."""
    with _db_lock:
        conn = get_connection()
        try:
            now_iso = format_utc_timestamp()
            conn.execute("""
                INSERT INTO account_stats (
                    account_id, total_attempts, successful_logins, failed_logins,
                    first_event_time, latest_event_time, risk_level, alert_count, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(account_id) DO UPDATE SET
                    total_attempts = excluded.total_attempts,
                    successful_logins = excluded.successful_logins,
                    failed_logins = excluded.failed_logins,
                    first_event_time = excluded.first_event_time,
                    latest_event_time = excluded.latest_event_time,
                    risk_level = excluded.risk_level,
                    alert_count = excluded.alert_count,
                    updated_at = excluded.updated_at
            """, (
                stats_dict["account_id"],
                stats_dict.get("total_attempts", 0),
                stats_dict.get("successful_logins", 0),
                stats_dict.get("failed_logins", 0),
                stats_dict.get("first_event_time"),
                stats_dict.get("latest_event_time"),
                stats_dict.get("risk_level", "LOW"),
                stats_dict.get("alert_count", 0),
                now_iso
            ))

            if new_source:
                conn.execute("""
                    INSERT OR IGNORE INTO account_sources (account_id, source)
                    VALUES (?, ?)
                """, (stats_dict["account_id"], new_source))

            conn.commit()
        finally:
            conn.close()


def save_alert(alert_dict: Dict[str, Any]) -> bool:
    """Saves an alert if not already present."""
    with _db_lock:
        conn = get_connection()
        try:
            related_str = json.dumps(alert_dict.get("related_events", []))
            conn.execute("""
                INSERT INTO alerts (
                    alert_id, account_id, rule_name, severity, timestamp,
                    reason, related_events, status, reviewed_at, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_dict["alert_id"],
                alert_dict.get("account_id"),
                alert_dict["rule_name"],
                alert_dict["severity"],
                alert_dict["timestamp"],
                alert_dict["reason"],
                related_str,
                alert_dict.get("status", "OPEN"),
                alert_dict.get("reviewed_at"),
                alert_dict.get("notes")
            ))

            # Increment alert count on account
            if alert_dict.get("account_id"):
                conn.execute("""
                    UPDATE account_stats
                    SET alert_count = alert_count + 1
                    WHERE account_id = ?
                """, (alert_dict["account_id"],))

            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()


def update_alert_status(alert_id: str, status: str, notes: Optional[str] = None) -> bool:
    """Updates the review status and notes for an alert."""
    with _db_lock:
        conn = get_connection()
        try:
            now_iso = format_utc_timestamp()
            cursor = conn.cursor()
            if notes is not None:
                cursor.execute("""
                    UPDATE alerts
                    SET status = ?, notes = ?, reviewed_at = ?
                    WHERE alert_id = ?
                """, (status, notes, now_iso, alert_id))
            else:
                cursor.execute("""
                    UPDATE alerts
                    SET status = ?, reviewed_at = ?
                    WHERE alert_id = ?
                """, (status, now_iso, alert_id))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()


def get_all_events(limit: int = 100, offset: int = 0, account_id: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves list of events ordered by timestamp descending."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        query = "SELECT * FROM events"
        params: List[Any] = []
        conditions = []
        if account_id:
            conditions.append("account_id = ?")
            params.append(account_id)
        if status:
            conditions.append("status = ?")
            params.append(status)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_account_events(account_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Fetches events for a specific account sorted chronologically."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM events
            WHERE account_id = ?
            ORDER BY timestamp ASC, id ASC
            LIMIT ?
        """, (account_id, limit))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_account_stats_list() -> List[Dict[str, Any]]:
    """Retrieves all account statistics with their distinct source list."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.*, 
                   (SELECT COUNT(*) FROM account_sources src WHERE src.account_id = s.account_id) as source_count
            FROM account_stats s
            ORDER BY s.failed_logins DESC, s.alert_count DESC, s.total_attempts DESC
        """)
        accounts = [dict(row) for row in cursor.fetchall()]

        # Attach distinct sources list
        for acc in accounts:
            cursor.execute("SELECT source FROM account_sources WHERE account_id = ?", (acc["account_id"],))
            acc["distinct_sources"] = [r["source"] for r in cursor.fetchall()]
            total = acc.get("total_attempts", 0)
            failed = acc.get("failed_logins", 0)
            acc["failure_rate"] = round((failed / total * 100), 1) if total > 0 else 0.0

        return accounts
    finally:
        conn.close()


def get_alerts(
    limit: int = 100,
    offset: int = 0,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    rule_name: Optional[str] = None,
    account_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieves alerts with filtering."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        query = "SELECT * FROM alerts"
        conditions = []
        params: List[Any] = []

        if status and status != "ALL":
            conditions.append("status = ?")
            params.append(status)
        if severity and severity != "ALL":
            conditions.append("severity = ?")
            params.append(severity)
        if rule_name and rule_name != "ALL":
            conditions.append("rule_name = ?")
            params.append(rule_name)
        if account_id:
            conditions.append("account_id = ?")
            params.append(account_id)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY timestamp DESC, alert_id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        alerts = []
        for row in cursor.fetchall():
            d = dict(row)
            try:
                d["related_events"] = json.loads(d.get("related_events") or "[]")
            except Exception:
                d["related_events"] = []
            alerts.append(d)
        return alerts
    finally:
        conn.close()


def get_dashboard_aggregates() -> Dict[str, Any]:
    """Computes comprehensive dashboard summary numbers directly from SQLite."""
    conn = get_connection()
    try:
        cursor = conn.cursor()

        # Total, Success, Failures
        cursor.execute("""
            SELECT 
                COUNT(*) as total_events,
                SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) as total_success,
                SUM(CASE WHEN status = 'FAILURE' THEN 1 ELSE 0 END) as total_failure
            FROM events;
        """)
        event_stats = cursor.fetchone()
        total_events = event_stats["total_events"] or 0
        total_success = event_stats["total_success"] or 0
        total_failure = event_stats["total_failure"] or 0

        # Rejected events count
        cursor.execute("SELECT COUNT(*) as rejected_count FROM rejected_events;")
        rejected_count = cursor.fetchone()["rejected_count"] or 0

        # Alerts count
        cursor.execute("""
            SELECT 
                COUNT(*) as total_alerts,
                SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_alerts,
                SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_alerts,
                SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END) as open_alerts
            FROM alerts;
        """)
        alert_stats = cursor.fetchone()
        total_alerts = alert_stats["total_alerts"] or 0
        critical_alerts = alert_stats["critical_alerts"] or 0
        high_alerts = alert_stats["high_alerts"] or 0
        open_alerts = alert_stats["open_alerts"] or 0

        # Suspicious / Flagged accounts count (HIGH or CRITICAL risk, or failed_logins >= 5)
        cursor.execute("""
            SELECT COUNT(*) as flagged_count 
            FROM account_stats 
            WHERE risk_level IN ('HIGH', 'CRITICAL') OR failed_logins >= 5 OR alert_count > 0;
        """)
        flagged_count = cursor.fetchone()["flagged_count"] or 0

        # Account failure breakdown for bar chart (top 6 failing accounts)
        cursor.execute("""
            SELECT account_id, failed_logins, successful_logins
            FROM account_stats
            WHERE failed_logins > 0
            ORDER BY failed_logins DESC
            LIMIT 7;
        """)
        top_failing_accounts = [dict(row) for row in cursor.fetchall()]

        # Activity by 1-minute bucket for line chart (last 15 buckets)
        cursor.execute("""
            SELECT 
                substr(timestamp, 12, 5) as time_bucket,
                SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) as successes,
                SUM(CASE WHEN status = 'FAILURE' THEN 1 ELSE 0 END) as failures
            FROM events
            GROUP BY time_bucket
            ORDER BY time_bucket DESC
            LIMIT 12;
        """)
        timeline_buckets = [dict(row) for row in cursor.fetchall()]
        timeline_buckets.reverse()  # chronological order

        return {
            "total_events": total_events,
            "total_success": total_success,
            "total_failure": total_failure,
            "rejected_count": rejected_count,
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "open_alerts": open_alerts,
            "flagged_accounts": flagged_count,
            "top_failing_accounts": top_failing_accounts,
            "timeline": timeline_buckets
        }
    finally:
        conn.close()


def get_rule_configs() -> Dict[str, Dict[str, Any]]:
    """Fetches stored rule configs."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT rule_name, enabled, config_json FROM rule_configs;")
        configs = {}
        for row in cursor.fetchall():
            try:
                cfg = json.loads(row["config_json"])
            except Exception:
                cfg = {}
            configs[row["rule_name"]] = {
                "enabled": bool(row["enabled"]),
                "config": cfg
            }
        return configs
    finally:
        conn.close()


def save_rule_config(rule_name: str, enabled: bool, config_dict: Dict[str, Any]):
    """Persists a rule configuration update."""
    with _db_lock:
        conn = get_connection()
        try:
            now_iso = format_utc_timestamp()
            conn.execute("""
                INSERT INTO rule_configs (rule_name, enabled, config_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(rule_name) DO UPDATE SET
                    enabled = excluded.enabled,
                    config_json = excluded.config_json,
                    updated_at = excluded.updated_at
            """, (rule_name, 1 if enabled else 0, json.dumps(config_dict), now_iso))
            conn.commit()
        finally:
            conn.close()


def get_system_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    """Reads a system setting."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def set_system_setting(key: str, value: str):
    """Sets a system setting."""
    with _db_lock:
        conn = get_connection()
        try:
            conn.execute("""
                INSERT INTO system_settings (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """, (key, value))
            conn.commit()
        finally:
            conn.close()


def reset_database():
    """Resets all events, alerts, rejected logs, and account stats for a clean demo state."""
    with _db_lock:
        conn = get_connection()
        try:
            conn.execute("DELETE FROM events;")
            conn.execute("DELETE FROM rejected_events;")
            conn.execute("DELETE FROM account_stats;")
            conn.execute("DELETE FROM account_sources;")
            conn.execute("DELETE FROM alerts;")
            conn.commit()
        finally:
            conn.close()
