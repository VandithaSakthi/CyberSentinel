# CyberShield: Login Event Monitor 🛡️
> **College Hackathon Project** — A Real-Time Defensive Security Operations Center (SOC) & Brute-Force Monitoring Dashboard.

CyberShield is a complete, full-stack cybersecurity application designed to ingest, validate, analyze, and visualize synthetic login activity. It detects brute-force attacks, distributed credential stuffing, replay attempts, and malformed telemetry in real time.

---

## 🚀 Key Highlights & Architecture

```
[Synthetic Event Generator] (Worker Thread)
           │
           ▼
[Thread-Safe Queue: queue.Queue]
           │
           ▼
[Event Processing Pipeline] (Worker Thread)
   ├─► 1. Structural Sanitization (Rule 4: Malformed Check)
   ├─► 2. Replay Filter & Cache (Rule 3: Duplicate Check)
   ├─► 3. Atomic Account Stats Lock (threading.RLock)
   ├─► 4. Chronological Out-of-Order Sliding Window Sort
   ├─► 5. Behavioral Detection Engine (Rule 1 & Rule 2)
   └─► 6. Persistent Storage (SQLite WAL Mode)
           │
           ▼
[REST APIs (Flask)] ◄── Real-Time Polling ──► [SOC Dark Dashboard (Chart.js)]
```

### 1. Robust Multi-Threaded Ingestion Pipeline
- **Decoupled Architecture:** Event generation and event analysis run in separate background worker threads communicating via Python's standard `queue.Queue`.
- **Atomic Concurrency Protection:** State mutations on account counters utilize an internal `threading.RLock()`, guaranteeing zero lost writes even under simultaneous burst attacks against the same user.
- **Out-of-Order Resiliency:** Detection rules evaluate events based on parsed UTC event timestamps rather than arrival sequence. Scrambled packet arrivals (e.g., `10:04`, `10:01`, `10:03`, `10:02`, `10:00`) are chronologically ordered to catch attacks within sliding windows.

### 2. Extensible Detection Rule Engine
Built with an abstract base class (`DetectionRule` in [detection_rules.py](file:///c:/Users/vansa/Downloads/Cybershield/detection_rules.py)):
- **Rule 1: Repeated Failed Logins:** Generates a `HIGH` severity alert when an account accumulates at least 5 failures within a sliding 5-minute (300s) window.
- **Rule 2: Unusual Source Activity:** Generates a `CRITICAL` severity alert when failed logins for an account originate across 3 or more distinct simulated sources (e.g. `web-portal-us`, `mobile-app-ios`, `vpn-internal`, `api-gateway`) within the time window.
- **Rule 3: Duplicate Event Detection:** Detects and immediately rejects replayed `event_id`s, preventing double-counting or counter inflation.
- **Rule 4: Malformed Event Detection:** Rejects invalid payloads (missing required fields, unparseable timestamps, invalid status codes, or unknown accounts per policy).

### 3. Interactive Attack & Test Lab
Dedicated 1-click test suite to demonstrate edge cases to hackathon judges:
- 🟢 **Normal Activity Batch:** Generates clean background traffic.
- 🔴 **Repeated Failed Logins:** Fires 5 successive failures for `user102` to trigger Rule 1.
- 🔀 **Out-of-Order Test:** Submits events in scrambled order `[10:04, 10:01, 10:03, 10:02, 10:00]` and verifies chronological detection.
- ⚡ **Concurrent Failures Test:** Spawns 10 concurrent worker threads simultaneously targeting `user105` to verify atomic locking.
- 📑 **Duplicate Event Test:** Submits the same event twice; verifies second event is rejected without altering counters.
- ⚠️ **Malformed Event Test:** Submits corrupt payloads and verifies Rule 4 rejection.
- ❓ **Unknown Account Test:** Evaluates handling under configured `AUTO_CREATE` or `REJECT` policies.
- 🌐 **Unusual Source Activity:** Simulates a distributed botnet attack across 4 sources to trigger Rule 2.

### 4. Enterprise SOC Dashboard
- **Dark Theme Aesthetics:** Navy/charcoal palette (`#070B14`, `#0F182C`) with electric cyan (`#00F2FE`), emerald (`#10B981`), amber (`#F59E0B`), and crimson (`#EF4444`) accents.
- **Live Charts:** Chart.js timeline of successes vs failures, doughnut status distribution, and horizontal bar chart of targeted accounts.
- **Alert Investigation:** Modal review workflow allowing analysts to transition alerts between `OPEN`, `INVESTIGATING`, `RESOLVED`, and `FALSE_POSITIVE` with notes.
- **Audit Export:** 1-click downloadable CSV security report (`/api/reports/export`).

---

## 📂 Project Structure

```
cybershield/
├── app.py                  # Flask application & REST API routes
├── event_generator.py      # Background worker for synthetic login traffic
├── event_processor.py      # Queue-based pipeline & thread-safe state engine
├── detection_rules.py      # DetectionRule ABC & concrete rules (Rules 1-4)
├── models.py               # Data models, validation utilities & constants
├── database.py             # SQLite WAL-mode persistence layer
├── requirements.txt        # Minimal external dependencies (Flask)
├── README.md               # Documentation & setup guide
├── templates/
│   └── index.html          # Single Page Application (8 operational views)
└── static/
    ├── css/
    │   └── style.css       # SOC design system, glassmorphism & typography
    ├── js/
    │   └── app.js          # Pure JS frontend, polling, charts & modals
    └── assets/
        └── logo.svg        # Custom glowing shield-and-lock SVG logo
```

---

## 🛠️ Installation & Execution

### Prerequisites
- Python 3.10+ (Tested on Python 3.12)
- Windows PowerShell

### Quick Start Commands

1. **Open PowerShell and navigate to the project directory:**
   ```powershell
   cd c:\Users\vansa\Downloads\Cybershield
   ```

2. **(Optional) Create and activate a virtual environment:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

4. **Launch the application:**
   ```powershell
   python app.py
   ```
   *Alternative command using the Windows Python launcher:*
   ```powershell
   py app.py
   ```

5. **Access the application in your browser:**
   Open: **[http://127.0.0.1:5000/](http://127.0.0.1:5000/)**

---

## 📡 REST API Reference

| Endpoint | Method | Description |
|---|---|---|
| `GET /api/dashboard` | `GET` | Aggregated statistics, chart timelines, queue depth, throughput |
| `GET /api/events` | `GET` | Paginated and filtered processed login events |
| `POST /api/events` | `POST` | Manually ingest a login event |
| `POST /api/simulator/start` | `POST` | Start synthetic event generator (`count`, `speed_ms`, `mode`) |
| `POST /api/simulator/pause` | `POST` | Pause event generation |
| `POST /api/simulator/resume` | `POST` | Resume paused generator |
| `POST /api/simulator/stop` | `POST` | Safely stop event generator |
| `GET /api/simulator/status` | `GET` | Current generator status & progress |
| `GET /api/accounts` | `GET` | Account statistics, risk profiles & failure rates |
| `GET /api/alerts` | `GET` | Security alert history with severity/status filters |
| `PATCH /api/alerts/<id>` | `PATCH` | Update alert status (`OPEN`, `INVESTIGATING`, `RESOLVED`) & notes |
| `GET /api/rules` | `GET` | Retrieve configured detection rules & thresholds |
| `PUT /api/rules/<name>` | `PUT` | Update rule parameters or enable/disable |
| `GET /api/reports` | `GET` | Aggregated compliance & breakdown summary |
| `GET /api/reports/export` | `GET` | Download security audit report as CSV |
| `POST /api/demo/trigger/<scenario>` | `POST` | Execute interactive attack scenario for demo |
| `POST /api/demo/reset` | `POST` | Clear database and reset state to pristine baseline |
| `GET /api/settings` | `GET` | Retrieve system settings (unknown account policy, polling) |
| `POST /api/settings` | `POST` | Update system settings |

---

## 🔒 Defensive Simulation & Ethics Notice
*CyberShield is developed strictly for defensive educational simulations and security research. It operates entirely on synthetic user accounts (`user101`, `user102`, etc.) and does not collect, prompt for, or store real user credentials or plaintext passwords.*
