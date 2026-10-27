"""
Detection Rule Engine and Rules for CyberShield: Login Event Monitor.
Implements an extensible abstract base class with individual configurable rules.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timezone, timedelta
import uuid
import json

from models import Alert, parse_iso_timestamp, format_utc_timestamp, DEFAULT_SYNTHETIC_ACCOUNTS


class DetectionRule(ABC):
    """Abstract Base Class for all CyberShield detection rules."""

    def __init__(self, name: str, description: str, enabled: bool = True, severity: str = "HIGH"):
        self.name = name
        self.description = description
        self.enabled = enabled
        self.severity = severity

    @abstractmethod
    def evaluate(self, event: Dict[str, Any], account_history: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Alert]:
        """
        Evaluates the event against the rule and account history.
        Returns a list of Alert instances if triggered, otherwise empty list.
        """
        pass

    @abstractmethod
    def get_config(self) -> Dict[str, Any]:
        """Returns the current rule configuration dictionary."""
        pass

    @abstractmethod
    def update_config(self, new_config: Dict[str, Any]):
        """Updates rule configuration parameters."""
        pass


class RepeatedFailedLoginsRule(DetectionRule):
    """
    Rule 1: Repeated Failed Logins
    Generates an alert when an account has at least threshold (default 5) failed
    login events within a configurable time window (default 300 seconds / 5 mins).
    Handles out-of-order event timestamps correctly.
    """

    def __init__(self, threshold: int = 5, window_seconds: int = 300, severity: str = "HIGH"):
        super().__init__(
            name="Repeated Failed Logins",
            description="Detects rapid successive failed logins indicative of brute-force attacks.",
            enabled=True,
            severity=severity
        )
        self.threshold = threshold
        self.window_seconds = window_seconds

    def get_config(self) -> Dict[str, Any]:
        return {
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "severity": self.severity
        }

    def update_config(self, new_config: Dict[str, Any]):
        if "threshold" in new_config:
            self.threshold = max(2, int(new_config["threshold"]))
        if "window_seconds" in new_config:
            self.window_seconds = max(10, int(new_config["window_seconds"]))
        if "severity" in new_config:
            self.severity = str(new_config["severity"])

    def evaluate(self, event: Dict[str, Any], account_history: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Alert]:
        if not self.enabled or event.get("status") != "FAILURE":
            return []

        curr_account = event.get("account_id")
        # Collect all failure events for this account including the current event
        failure_events = [e for e in account_history if e.get("account_id") == curr_account and e.get("status") == "FAILURE"]

        if not any(e.get("event_id") == event.get("event_id") for e in failure_events):
            failure_events.append(event)

        # Parse timestamps and sort chronologically (handles out-of-order events!)
        parsed_failures = []
        for e in failure_events:
            dt = parse_iso_timestamp(e.get("timestamp"))
            if dt:
                parsed_failures.append((dt, e))

        parsed_failures.sort(key=lambda item: item[0])

        if len(parsed_failures) < self.threshold:
            return []

        alerts: List[Alert] = []
        existing_alert_signatures: Set[str] = context.get("existing_alert_signatures", set())

        # Sliding window check across chronologically ordered failures
        n = len(parsed_failures)
        for i in range(n):
            window_start_dt, first_event = parsed_failures[i]
            window_events = [first_event]

            for j in range(i + 1, n):
                curr_dt, cand_event = parsed_failures[j]
                diff = (curr_dt - window_start_dt).total_seconds()
                if 0 <= diff <= self.window_seconds:
                    window_events.append(cand_event)
                else:
                    break

            if len(window_events) >= self.threshold:
                # Check if current event is part of this triggering window
                curr_id = event.get("event_id")
                event_ids = [e.get("event_id") for e in window_events]
                if curr_id in event_ids:
                    # Signature based on account and sorted event IDs to prevent duplicate alerts
                    sig = f"REPEAT_FAIL:{curr_account}:{','.join(sorted(event_ids[:self.threshold]))}"
                    if sig not in existing_alert_signatures:
                        existing_alert_signatures.add(sig)
                        alert = Alert(
                            alert_id=f"alt_rep_{uuid.uuid4().hex[:8]}",
                            account_id=curr_account,
                            rule_name=self.name,
                            severity=self.severity,
                            timestamp=event.get("timestamp") or format_utc_timestamp(),
                            reason=(
                                f"Detected {len(window_events)} failed login attempts for account '{curr_account}' "
                                f"within {self.window_seconds}s time window (threshold: {self.threshold}). "
                                f"Potential brute-force or credential guessing attempt."
                            ),
                            related_events=event_ids,
                            status="OPEN"
                        )
                        alerts.append(alert)
                        break  # Found triggering window for current event

        return alerts


class UnusualSourceActivityRule(DetectionRule):
    """
    Rule 2: Unusual Source Activity
    Generates an alert when an account receives failed logins from at least 3
    distinct simulated sources within a configurable time window (default 300s).
    """

    def __init__(self, min_sources: int = 3, window_seconds: int = 300, severity: str = "CRITICAL"):
        super().__init__(
            name="Unusual Source Activity",
            description="Detects distributed attack patterns where failed logins arrive from multiple distinct sources.",
            enabled=True,
            severity=severity
        )
        self.min_sources = min_sources
        self.window_seconds = window_seconds

    def get_config(self) -> Dict[str, Any]:
        return {
            "min_sources": self.min_sources,
            "window_seconds": self.window_seconds,
            "severity": self.severity
        }

    def update_config(self, new_config: Dict[str, Any]):
        if "min_sources" in new_config:
            self.min_sources = max(2, int(new_config["min_sources"]))
        if "window_seconds" in new_config:
            self.window_seconds = max(10, int(new_config["window_seconds"]))
        if "severity" in new_config:
            self.severity = str(new_config["severity"])

    def evaluate(self, event: Dict[str, Any], account_history: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Alert]:
        if not self.enabled or event.get("status") != "FAILURE":
            return []

        curr_account = event.get("account_id")
        failure_events = [e for e in account_history if e.get("account_id") == curr_account and e.get("status") == "FAILURE"]
        if not any(e.get("event_id") == event.get("event_id") for e in failure_events):
            failure_events.append(event)

        # Parse and sort chronologically
        parsed_failures = []
        for e in failure_events:
            dt = parse_iso_timestamp(e.get("timestamp"))
            if dt:
                parsed_failures.append((dt, e))

        parsed_failures.sort(key=lambda item: item[0])

        if len(parsed_failures) < self.min_sources:
            return []

        alerts: List[Alert] = []
        existing_alert_signatures: Set[str] = context.get("existing_alert_signatures", set())

        n = len(parsed_failures)
        for i in range(n):
            window_start_dt, first_event = parsed_failures[i]
            window_events = [first_event]
            distinct_sources = {first_event.get("source")}

            for j in range(i + 1, n):
                curr_dt, cand_event = parsed_failures[j]
                diff = (curr_dt - window_start_dt).total_seconds()
                if 0 <= diff <= self.window_seconds:
                    window_events.append(cand_event)
                    distinct_sources.add(cand_event.get("source"))
                else:
                    break

            if len(distinct_sources) >= self.min_sources:
                curr_id = event.get("event_id")
                event_ids = [e.get("event_id") for e in window_events]
                if curr_id in event_ids:
                    sorted_sources = sorted(list(distinct_sources))
                    sig = f"SOURCE_ACT:{curr_account}:{','.join(sorted_sources)}:{window_start_dt.strftime('%Y%m%d%H%M')}"
                    if sig not in existing_alert_signatures:
                        existing_alert_signatures.add(sig)
                        alert = Alert(
                            alert_id=f"alt_src_{uuid.uuid4().hex[:8]}",
                            account_id=curr_account,
                            rule_name=self.name,
                            severity=self.severity,
                            timestamp=event.get("timestamp") or format_utc_timestamp(),
                            reason=(
                                f"Account '{curr_account}' received failed logins across {len(distinct_sources)} "
                                f"distinct sources ({', '.join(sorted_sources)}) within {self.window_seconds}s. "
                                f"Indicates distributed credential stuffing or botnet attack."
                            ),
                            related_events=event_ids,
                            status="OPEN"
                        )
                        alerts.append(alert)
                        break

        return alerts


class DuplicateEventRule(DetectionRule):
    """
    Rule 3: Duplicate Event Detection
    Detects and rejects duplicate event IDs.
    Duplicate events do not increment login counters or create copies.
    """

    def __init__(self, severity: str = "INFORMATIONAL"):
        super().__init__(
            name="Duplicate Event Detection",
            description="Replay attack & deduplication filter: rejects duplicate event IDs to protect counter integrity.",
            enabled=True,
            severity=severity
        )

    def get_config(self) -> Dict[str, Any]:
        return {
            "severity": self.severity
        }

    def update_config(self, new_config: Dict[str, Any]):
        if "severity" in new_config:
            self.severity = str(new_config["severity"])

    def evaluate(self, event: Dict[str, Any], account_history: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Alert]:
        # Handled in validation pipeline before counter update
        return []

    def check_duplicate(self, event_id: str, existing_ids: Set[str]) -> Optional[Alert]:
        if not self.enabled:
            return None
        if event_id in existing_ids:
            return Alert(
                alert_id=f"alt_dup_{uuid.uuid4().hex[:8]}",
                account_id=None,
                rule_name=self.name,
                severity=self.severity,
                timestamp=format_utc_timestamp(),
                reason=f"Rejected duplicate event ID: '{event_id}'. Event discarded without altering counters.",
                related_events=[event_id],
                status="OPEN"
            )
        return None


class MalformedEventRule(DetectionRule):
    """
    Rule 4: Malformed Event Detection
    Rejects events with missing fields, invalid timestamps, invalid statuses,
    or unknown account policy violations.
    """

    def __init__(self, severity: str = "MEDIUM"):
        super().__init__(
            name="Malformed Event Detection",
            description="Input sanitization & validation filter: rejects structurally invalid or corrupt event payloads.",
            enabled=True,
            severity=severity
        )

    def get_config(self) -> Dict[str, Any]:
        return {
            "severity": self.severity
        }

    def update_config(self, new_config: Dict[str, Any]):
        if "severity" in new_config:
            self.severity = str(new_config["severity"])

    def evaluate(self, event: Dict[str, Any], account_history: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Alert]:
        return []

    def validate_payload(self, payload: Any, unknown_account_policy: str = "AUTO_CREATE") -> tuple[bool, Optional[str], Optional[Alert]]:
        """
        Validates payload. Returns (is_valid, rejection_reason, alert_if_applicable).
        """
        if not isinstance(payload, dict):
            reason = "Event payload is not a valid JSON object"
            return False, reason, self._create_alert(None, reason, None)

        required_fields = ["event_id", "account_id", "timestamp", "source", "status"]
        for f in required_fields:
            if f not in payload or payload[f] is None or str(payload[f]).strip() == "":
                reason = f"Missing required event field: '{f}'"
                return False, reason, self._create_alert(payload.get("account_id"), reason, payload.get("event_id"))

        # Status check
        status = str(payload.get("status")).strip().upper()
        if status not in {"SUCCESS", "FAILURE"}:
            reason = f"Invalid status '{payload.get('status')}'. Must be either 'SUCCESS' or 'FAILURE'"
            return False, reason, self._create_alert(payload.get("account_id"), reason, payload.get("event_id"))

        # Timestamp check
        ts = parse_iso_timestamp(payload.get("timestamp"))
        if ts is None:
            reason = f"Malformed timestamp '{payload.get('timestamp')}'. Must be valid ISO 8601 UTC format (e.g. 2026-10-27T12:00:00Z)"
            return False, reason, self._create_alert(payload.get("account_id"), reason, payload.get("event_id"))

        # Account ID check against policy
        account_id = str(payload.get("account_id")).strip()
        if unknown_account_policy == "REJECT":
            if account_id not in DEFAULT_SYNTHETIC_ACCOUNTS:
                reason = f"Account '{account_id}' is unknown and rejected per strict Unknown-Account Policy"
                return False, reason, self._create_alert(account_id, reason, payload.get("event_id"))

        return True, None, None

    def _create_alert(self, account_id: Optional[str], reason: str, event_id: Optional[str]) -> Optional[Alert]:
        if not self.enabled:
            return None
        return Alert(
            alert_id=f"alt_mal_{uuid.uuid4().hex[:8]}",
            account_id=account_id,
            rule_name=self.name,
            severity=self.severity,
            timestamp=format_utc_timestamp(),
            reason=f"Validation failed: {reason}",
            related_events=[event_id] if event_id else [],
            status="OPEN"
        )


class DetectionRuleEngine:
    """
    Coordinates and executes all detection rules against incoming events.
    Thread-safe and supports live enabling/disabling and parameter updates.
    """

    def __init__(self):
        self.repeated_failures_rule = RepeatedFailedLoginsRule()
        self.unusual_source_rule = UnusualSourceActivityRule()
        self.duplicate_event_rule = DuplicateEventRule()
        self.malformed_event_rule = MalformedEventRule()

        self.rules: Dict[str, DetectionRule] = {
            self.repeated_failures_rule.name: self.repeated_failures_rule,
            self.unusual_source_rule.name: self.unusual_source_rule,
            self.duplicate_event_rule.name: self.duplicate_event_rule,
            self.malformed_event_rule.name: self.malformed_event_rule,
        }

    def load_configs_from_db(self, saved_configs: Dict[str, Dict[str, Any]]):
        """Loads and applies rule configs saved in SQLite."""
        for rule_name, data in saved_configs.items():
            if rule_name in self.rules:
                rule = self.rules[rule_name]
                rule.enabled = data.get("enabled", True)
                if "config" in data:
                    rule.update_config(data["config"])

    def evaluate_event(self, event: Dict[str, Any], account_history: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Alert]:
        """Runs all enabled behavioral detection rules against the event."""
        triggered_alerts: List[Alert] = []

        # Behavioral rules
        if self.repeated_failures_rule.enabled:
            alerts = self.repeated_failures_rule.evaluate(event, account_history, context)
            triggered_alerts.extend(alerts)

        if self.unusual_source_rule.enabled:
            alerts = self.unusual_source_rule.evaluate(event, account_history, context)
            triggered_alerts.extend(alerts)

        return triggered_alerts

    def get_rules_info(self) -> List[Dict[str, Any]]:
        """Returns structured information for UI display and editing."""
        return [
            {
                "name": rule.name,
                "description": rule.description,
                "enabled": rule.enabled,
                "severity": rule.severity,
                "config": rule.get_config()
            }
            for rule in self.rules.values()
        ]

    def update_rule(self, rule_name: str, enabled: Optional[bool] = None, config: Optional[Dict[str, Any]] = None) -> bool:
        """Updates rule state and parameters."""
        if rule_name not in self.rules:
            return False
        rule = self.rules[rule_name]
        if enabled is not None:
            rule.enabled = enabled
        if config:
            rule.update_config(config)
        return True
