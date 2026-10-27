"""
Thread-safe Event Processing Pipeline for CyberShield: Login Event Monitor.
Orchestrates queue consumption, validation, locking, rule evaluation, and persistence.
"""

import queue
import threading
import time
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone

from models import (
    Event, Alert, AccountStats, parse_iso_timestamp, format_utc_timestamp,
    DEFAULT_SYNTHETIC_ACCOUNTS
)
import database
from detection_rules import DetectionRuleEngine


class EventProcessor:
    """
    Central event-processing engine.
    Uses Python's queue.Queue for decoupled ingestion and an RLock for thread-safe
    account statistics updates under high concurrency.
    """

    def __init__(self):
        self.queue: queue.Queue = queue.Queue(maxsize=10000)
        self.rule_engine = DetectionRuleEngine()

        # Thread synchronization
        self._stats_lock = threading.RLock()
        self._worker_thread: Optional[threading.Thread] = None
        self._running = False

        # In-memory deduplication and fast cache
        self._seen_event_ids: set[str] = set()
        self._existing_alert_signatures: set[str] = set()
        self._accounts_cache: Dict[str, AccountStats] = {}
        self._account_events_cache: Dict[str, List[Dict[str, Any]]] = {}

        # Performance and throughput counters
        self._total_processed = 0
        self._start_time = time.time()

        # Initialize from database
        self._load_initial_state()

    def _load_initial_state(self):
        """Loads persistent data from SQLite on startup."""
        database.init_db()

        # Load saved rule configurations
        saved_rules = database.get_rule_configs()
        self.rule_engine.load_configs_from_db(saved_rules)

        # Prepopulate seen event IDs
        with self._stats_lock:
            existing_events = database.get_all_events(limit=5000)
            for evt in existing_events:
                self._seen_event_ids.add(evt["event_id"])
                acc_id = evt["account_id"]
                if acc_id not in self._account_events_cache:
                    self._account_events_cache[acc_id] = []
                self._account_events_cache[acc_id].append(evt)

            # Sort cached events chronologically for each account
            for acc_id in self._account_events_cache:
                self._sort_account_events_cache(acc_id)

            # Prepopulate account stats
            stats_list = database.get_account_stats_list()
            for s in stats_list:
                acc = AccountStats(
                    account_id=s["account_id"],
                    total_attempts=s["total_attempts"],
                    successful_logins=s["successful_logins"],
                    failed_logins=s["failed_logins"],
                    first_event_time=s["first_event_time"],
                    latest_event_time=s["latest_event_time"],
                    distinct_sources=s.get("distinct_sources", []),
                    risk_level=s["risk_level"],
                    alert_count=s["alert_count"]
                )
                self._accounts_cache[s["account_id"]] = acc

            # Load existing alerts to prevent replay alert duplication
            existing_alerts = database.get_alerts(limit=500)
            for a in existing_alerts:
                # Approximate signature
                sig = f"{a['rule_name']}:{a.get('account_id')}:{','.join(sorted(a.get('related_events', [])))}"
                self._existing_alert_signatures.add(sig)

    def _sort_account_events_cache(self, account_id: str):
        """Sorts the in-memory event list for an account chronologically by parsed timestamp."""
        def get_ts(item):
            parsed = parse_iso_timestamp(item.get("timestamp"))
            return parsed.timestamp() if parsed else 0.0

        if account_id in self._account_events_cache:
            self._account_events_cache[account_id].sort(key=get_ts)

    def start_worker(self):
        """Safely starts the background worker thread. Idempotent."""
        if self._running and self._worker_thread and self._worker_thread.is_alive():
            return

        self._running = True
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="EventProcessorWorker",
            daemon=True
        )
        self._worker_thread.start()

    def stop_worker(self, timeout: float = 2.0):
        """Gracefully stops the worker thread."""
        self._running = False
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)

    def _worker_loop(self):
        """Worker thread loop reading from thread-safe queue."""
        while self._running:
            try:
                # Non-blocking wait with small timeout to allow checking self._running
                payload = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                self.process_single_event(payload)
            except Exception as e:
                # Protect worker from crashing on unexpected exceptions
                print(f"[EventProcessor Error] Processing event failed: {e}")
            finally:
                self.queue.task_done()

    def enqueue_event(self, payload: Dict[str, Any]) -> bool:
        """Puts an event into the processing queue."""
        try:
            self.queue.put(payload, timeout=1.0)
            return True
        except queue.Full:
            return False

    def process_single_event(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the full pipeline for a single event:
        Validation -> Duplicate Check -> Persistence -> Counter Lock Update -> Rule Engine -> Alerts
        """
        policy = database.get_system_setting("unknown_account_policy", "AUTO_CREATE")

        # 1. Validation (Rule 4: Malformed Event Detection)
        is_valid, reject_reason, malformed_alert = self.rule_engine.malformed_event_rule.validate_payload(
            payload, unknown_account_policy=policy
        )

        if not is_valid:
            # Record rejected event
            database.save_rejected_event(
                event_id=payload.get("event_id") if isinstance(payload, dict) else None,
                payload=payload if isinstance(payload, dict) else {"raw": str(payload)},
                reason=reject_reason or "Malformed event",
                rule_name=self.rule_engine.malformed_event_rule.name
            )
            if malformed_alert:
                database.save_alert(malformed_alert.to_dict())

            return {
                "success": False,
                "status": "REJECTED",
                "reason": reject_reason,
                "rule": self.rule_engine.malformed_event_rule.name,
                "alert_generated": malformed_alert is not None
            }

        event_id = str(payload["event_id"]).strip()
        account_id = str(payload["account_id"]).strip()
        timestamp = str(payload["timestamp"]).strip()
        source = str(payload["source"]).strip()
        status = str(payload["status"]).strip().upper()

        # 2. Duplicate Detection (Rule 3)
        with self._stats_lock:
            if event_id in self._seen_event_ids or database.check_event_exists(event_id):
                dup_alert = self.rule_engine.duplicate_event_rule.check_duplicate(
                    event_id, {event_id}
                )
                reason = f"Duplicate event ID '{event_id}' rejected. Counters not updated."
                database.save_rejected_event(
                    event_id=event_id,
                    payload=payload,
                    reason=reason,
                    rule_name=self.rule_engine.duplicate_event_rule.name
                )
                if dup_alert:
                    database.save_alert(dup_alert.to_dict())

                return {
                    "success": False,
                    "status": "REJECTED_DUPLICATE",
                    "reason": reason,
                    "rule": self.rule_engine.duplicate_event_rule.name,
                    "alert_generated": dup_alert is not None
                }

            # Register as seen
            self._seen_event_ids.add(event_id)

        # 3. Store valid event in database
        event_record = {
            "event_id": event_id,
            "account_id": account_id,
            "timestamp": timestamp,
            "source": source,
            "status": status,
            "created_at": format_utc_timestamp()
        }
        database.save_event(event_record)

        # 4. Atomic Account Statistics & History Update
        with self._stats_lock:
            if account_id not in self._accounts_cache:
                self._accounts_cache[account_id] = AccountStats(account_id=account_id)
            stats = self._accounts_cache[account_id]

            # Update counters
            stats.total_attempts += 1
            if status == "SUCCESS":
                stats.successful_logins += 1
            elif status == "FAILURE":
                stats.failed_logins += 1

            if source not in stats.distinct_sources:
                stats.distinct_sources.append(source)

            # Update first and latest event times by comparing actual timestamps
            event_dt = parse_iso_timestamp(timestamp)
            if event_dt:
                if stats.first_event_time is None:
                    stats.first_event_time = timestamp
                else:
                    curr_first = parse_iso_timestamp(stats.first_event_time)
                    if curr_first and event_dt < curr_first:
                        stats.first_event_time = timestamp

                if stats.latest_event_time is None:
                    stats.latest_event_time = timestamp
                else:
                    curr_latest = parse_iso_timestamp(stats.latest_event_time)
                    if curr_latest and event_dt > curr_latest:
                        stats.latest_event_time = timestamp

            # Re-evaluate dynamic risk level
            stats.risk_level = stats.calculate_risk()

            # Append to in-memory account history and sort chronologically
            if account_id not in self._account_events_cache:
                self._account_events_cache[account_id] = []
            self._account_events_cache[account_id].append(event_record)
            self._sort_account_events_cache(account_id)

            # Write stats to database
            database.update_account_stats(stats.to_dict(), new_source=source)

            account_history_copy = list(self._account_events_cache[account_id])
            self._total_processed += 1

        # 5. Detection Rule Engine (Rule 1 & Rule 2)
        eval_context = {
            "existing_alert_signatures": self._existing_alert_signatures
        }
        triggered_alerts = self.rule_engine.evaluate_event(
            event=event_record,
            account_history=account_history_copy,
            context=eval_context
        )

        # 6. Persist Alerts and update account alert count
        created_alerts = []
        for alert in triggered_alerts:
            saved = database.save_alert(alert.to_dict())
            if saved:
                created_alerts.append(alert.to_dict())
                with self._stats_lock:
                    if account_id in self._accounts_cache:
                        self._accounts_cache[account_id].alert_count += 1
                        self._accounts_cache[account_id].risk_level = self._accounts_cache[account_id].calculate_risk()
                        database.update_account_stats(self._accounts_cache[account_id].to_dict())

        return {
            "success": True,
            "status": "PROCESSED",
            "event_id": event_id,
            "account_id": account_id,
            "alerts_created": created_alerts
        }

    def reset_all(self):
        """Clears all in-memory caches and database data."""
        with self._stats_lock:
            # Drain queue
            while not self.queue.empty():
                try:
                    self.queue.get_nowait()
                    self.queue.task_done()
                except Exception:
                    break

            self._seen_event_ids.clear()
            self._existing_alert_signatures.clear()
            self._accounts_cache.clear()
            self._account_events_cache.clear()
            self._total_processed = 0
            self._start_time = time.time()

            database.reset_database()

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Provides fast, accurate dashboard summary metrics."""
        summary = database.get_dashboard_aggregates()
        summary["queue_depth"] = self.queue.qsize()
        elapsed = max(time.time() - self._start_time, 1.0)
        summary["throughput_per_sec"] = round(self._total_processed / elapsed, 2)
        return summary
