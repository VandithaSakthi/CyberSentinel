"""
Data models and validation logic for CyberShield: Login Event Monitor.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
import re


VALID_STATUSES = {"SUCCESS", "FAILURE"}
VALID_SEVERITIES = {"INFORMATIONAL", "MEDIUM", "HIGH", "CRITICAL"}
VALID_ALERT_STATUSES = {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}

# Supported synthetic accounts
DEFAULT_SYNTHETIC_ACCOUNTS = {
    "user101", "user102", "user103", "user104", "user105",
    "user106", "user107", "user108", "user109", "user110"
}

# Supported simulated sources
KNOWN_SOURCES = [
    "web-portal-us",
    "mobile-app-ios",
    "mobile-app-android",
    "api-gateway",
    "vpn-internal",
    "legacy-auth-service",
    "oauth-client"
]


@dataclass
class Event:
    event_id: str
    account_id: str
    timestamp: str  # ISO 8601 UTC, e.g. "2026-10-27T12:00:00Z"
    source: str
    status: str     # "SUCCESS" or "FAILURE"
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Alert:
    alert_id: str
    account_id: Optional[str]
    rule_name: str
    severity: str    # "INFORMATIONAL", "MEDIUM", "HIGH", "CRITICAL"
    timestamp: str   # ISO 8601 UTC
    reason: str
    related_events: List[str] = field(default_factory=list)
    status: str = "OPEN"  # "OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"
    reviewed_at: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AccountStats:
    account_id: str
    total_attempts: int = 0
    successful_logins: int = 0
    failed_logins: int = 0
    first_event_time: Optional[str] = None
    latest_event_time: Optional[str] = None
    distinct_sources: List[str] = field(default_factory=list)
    risk_level: str = "LOW"
    alert_count: int = 0
    updated_at: Optional[str] = None

    def calculate_risk(self) -> str:
        """
        Calculates dynamic risk level based on failure count, failure rate, and alert count.
        """
        if self.alert_count >= 3 or self.failed_logins >= 10:
            return "CRITICAL"
        elif self.alert_count >= 1 or self.failed_logins >= 5:
            return "HIGH"
        elif self.failed_logins >= 2:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["failure_rate"] = round((self.failed_logins / self.total_attempts * 100), 1) if self.total_attempts > 0 else 0.0
        return d


def parse_iso_timestamp(ts_str: Any) -> Optional[datetime]:
    """
    Safely parse ISO8601 timestamp string into a UTC datetime object.
    Returns None if parsing fails.
    """
    if not isinstance(ts_str, str) or not ts_str.strip():
        return None
    
    clean_str = ts_str.strip()
    # Normalize Z to +00:00 for fromisoformat
    if clean_str.endswith("Z") or clean_str.endswith("z"):
        clean_str = clean_str[:-1] + "+00:00"
        
    try:
        dt = datetime.fromisoformat(clean_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        # Fallback regex for common format YYYY-MM-DD HH:MM:SS
        try:
            dt = datetime.strptime(clean_str, "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None


def format_utc_timestamp(dt: Optional[datetime] = None) -> str:
    """Format UTC datetime to standard ISO 8601 string."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
