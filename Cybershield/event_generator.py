"""
Synthetic Login Event Generator for CyberShield: Login Event Monitor.
Runs in a background worker thread with full lifecycle controls (start, pause, stop).
"""

import threading
import time
import random
import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from models import DEFAULT_SYNTHETIC_ACCOUNTS, KNOWN_SOURCES, format_utc_timestamp
from event_processor import EventProcessor


class SyntheticEventGenerator:
    """
    Simulates real-world enterprise login activity or adversarial attacks.
    Runs asynchronously on a dedicated worker thread, feeding events directly
    into the EventProcessor queue.
    """

    STATE_STOPPED = "STOPPED"
    STATE_RUNNING = "RUNNING"
    STATE_PAUSED = "PAUSED"

    def __init__(self, processor: EventProcessor):
        self.processor = processor
        self.state = self.STATE_STOPPED

        # Generator settings
        self.speed_ms = 500  # Interval between events in ms
        self.target_count: Optional[int] = None  # None means continuous until stopped
        self.generated_count = 0
        self.mode = "mixed"  # "normal", "suspicious", "mixed"
        self.sources = list(KNOWN_SOURCES)
        self.target_account: Optional[str] = None

        # Thread synchronization
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._pause_event = threading.Event()
        self._pause_event.set()  # set means not paused
        self._stop_event = threading.Event()

    def start(
        self,
        count: Optional[int] = None,
        speed_ms: int = 500,
        mode: str = "mixed",
        target_account: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Starts synthetic event generation.
        If already running, updates parameters without creating duplicate threads.
        """
        with self._lock:
            self.speed_ms = max(50, min(10000, speed_ms))
            self.target_count = count if (count and count > 0) else None
            self.mode = mode if mode in {"normal", "suspicious", "mixed"} else "mixed"
            self.target_account = target_account

            if self.state == self.STATE_PAUSED:
                # Resume from pause
                self.state = self.STATE_RUNNING
                self._pause_event.set()
                return self.get_status()

            if self.state == self.STATE_RUNNING:
                # Already running, parameters updated
                return self.get_status()

            # Start new run
            self.generated_count = 0
            self.state = self.STATE_RUNNING
            self._stop_event.clear()
            self._pause_event.set()

            self._thread = threading.Thread(
                target=self._generation_loop,
                name="SyntheticEventGeneratorThread",
                daemon=True
            )
            self._thread.start()

            return self.get_status()

    def pause(self) -> Dict[str, Any]:
        """Pauses generation without terminating the thread."""
        with self._lock:
            if self.state == self.STATE_RUNNING:
                self.state = self.STATE_PAUSED
                self._pause_event.clear()
            return self.get_status()

    def resume(self) -> Dict[str, Any]:
        """Resumes paused generation."""
        with self._lock:
            if self.state == self.STATE_PAUSED:
                self.state = self.STATE_RUNNING
                self._pause_event.set()
            return self.get_status()

    def stop(self) -> Dict[str, Any]:
        """Safely stops event generation."""
        with self._lock:
            if self.state != self.STATE_STOPPED:
                self.state = self.STATE_STOPPED
                self._stop_event.set()
                self._pause_event.set()  # Unblock if waiting in pause

        # Wait outside lock
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

        return self.get_status()

    def get_status(self) -> Dict[str, Any]:
        """Returns the current generator state and progress."""
        return {
            "state": self.state,
            "generated_count": self.generated_count,
            "target_count": self.target_count,
            "speed_ms": self.speed_ms,
            "mode": self.mode,
            "target_account": self.target_account
        }

    def _generation_loop(self):
        """Worker loop that generates events at the configured speed."""
        while not self._stop_event.is_set():
            # Check pause state
            self._pause_event.wait()
            if self._stop_event.is_set():
                break

            # Check if target limit reached
            if self.target_count is not None and self.generated_count >= self.target_count:
                self.state = self.STATE_STOPPED
                break

            # Synthesize single event
            event = self.generate_synthetic_event()
            # Push into event processing pipeline
            self.processor.enqueue_event(event)

            self.generated_count += 1

            # Sleep for speed_ms
            time.sleep(self.speed_ms / 1000.0)

        self.state = self.STATE_STOPPED

    def generate_synthetic_event(self) -> Dict[str, Any]:
        """Creates a single realistic synthetic event based on current mode."""
        evt_uuid = uuid.uuid4().hex[:8]
        timestamp = format_utc_timestamp()
        source = random.choice(self.sources)

        if self.mode == "suspicious":
            # 90% failures targeting a specific account or high-risk victim
            account = self.target_account or random.choice(["user102", "user103", "user107"])
            status = "FAILURE" if random.random() < 0.90 else "SUCCESS"
        elif self.mode == "normal":
            # 88% success, 12% sporadic failure across general accounts
            account = random.choice(list(DEFAULT_SYNTHETIC_ACCOUNTS))
            status = "SUCCESS" if random.random() < 0.88 else "FAILURE"
        else:  # "mixed"
            # 70% normal traffic, 30% targeted bursts
            if random.random() < 0.35:
                account = self.target_account or random.choice(["user102", "user105", "user108"])
                status = "FAILURE" if random.random() < 0.80 else "SUCCESS"
            else:
                account = random.choice(list(DEFAULT_SYNTHETIC_ACCOUNTS))
                status = "SUCCESS" if random.random() < 0.90 else "FAILURE"

        return {
            "event_id": f"evt_{evt_uuid}",
            "account_id": account,
            "timestamp": timestamp,
            "source": source,
            "status": status
        }
