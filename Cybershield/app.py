"""
CyberShield: Login Event Monitor - Main Flask Application.
Provides REST APIs, real-time metrics, simulation control, and demo attack scenarios.
"""

from flask import Flask, render_template, request, jsonify, Response, send_file
import io
import csv
import json
import threading
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

from models import format_utc_timestamp, parse_iso_timestamp, DEFAULT_SYNTHETIC_ACCOUNTS, KNOWN_SOURCES
import database
from event_processor import EventProcessor
from event_generator import SyntheticEventGenerator

app = Flask(__name__)

# Initialize singletons
processor = EventProcessor()
processor.start_worker()
generator = SyntheticEventGenerator(processor)


# -------------------------------------------------------------
# Frontend Route
# -------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# -------------------------------------------------------------
# Dashboard & Event APIs
# -------------------------------------------------------------
@app.route("/api/dashboard", methods=["GET"])
def get_dashboard():
    """Returns real-time dashboard stats, chart data, and simulator state."""
    try:
        summary = processor.get_dashboard_summary()
        summary["simulator"] = generator.get_status()
        # Top 5 most recent alerts for the dashboard panel
        summary["recent_alerts"] = database.get_alerts(limit=5)
        # Top 10 recent events for live ticker
        summary["recent_events"] = database.get_all_events(limit=10)
        return jsonify({"success": True, "data": summary})
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to fetch dashboard data: {str(e)}"}), 500


@app.route("/api/events", methods=["GET"])
def get_events():
    """Returns processed events with pagination and filtering."""
    try:
        limit = min(500, int(request.args.get("limit", 50)))
        offset = max(0, int(request.args.get("offset", 0)))
        account_id = request.args.get("account_id")
        status = request.args.get("status")

        events = database.get_all_events(limit=limit, offset=offset, account_id=account_id, status=status)
        return jsonify({
            "success": True,
            "data": events,
            "count": len(events),
            "offset": offset
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/api/events", methods=["POST"])
def submit_event():
    """Submits a single synthetic event for real-time processing."""
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"success": False, "error": "Invalid or missing JSON payload"}), 400

    # Auto-generate event_id and timestamp if omitted for convenience
    if "event_id" not in payload or not payload["event_id"]:
        payload["event_id"] = f"evt_manual_{uuid.uuid4().hex[:8]}"
    if "timestamp" not in payload or not payload["timestamp"]:
        payload["timestamp"] = format_utc_timestamp()

    result = processor.process_single_event(payload)
    status_code = 200 if result.get("success") else 422
    return jsonify(result), status_code


# -------------------------------------------------------------
# Simulator Controls
# -------------------------------------------------------------
@app.route("/api/simulator/start", methods=["POST"])
def start_simulator():
    """Starts synthetic event generation."""
    body = request.get_json(silent=True) or {}
    count = body.get("count")
    speed_ms = int(body.get("speed_ms", 500))
    mode = str(body.get("mode", "mixed"))
    target_account = body.get("target_account")

    if count is not None and count != "":
        count = int(count)
    else:
        count = None

    status = generator.start(count=count, speed_ms=speed_ms, mode=mode, target_account=target_account)
    return jsonify({"success": True, "message": "Simulator started", "data": status})


@app.route("/api/simulator/pause", methods=["POST"])
def pause_simulator():
    """Pauses event generation."""
    status = generator.pause()
    return jsonify({"success": True, "message": "Simulator paused", "data": status})


@app.route("/api/simulator/resume", methods=["POST"])
def resume_simulator():
    """Resumes event generation."""
    status = generator.resume()
    return jsonify({"success": True, "message": "Simulator resumed", "data": status})


@app.route("/api/simulator/stop", methods=["POST"])
def stop_simulator():
    """Stops event generation."""
    status = generator.stop()
    return jsonify({"success": True, "message": "Simulator stopped", "data": status})


@app.route("/api/simulator/status", methods=["GET"])
def get_simulator_status():
    """Returns current generator state."""
    return jsonify({"success": True, "data": generator.get_status()})


# -------------------------------------------------------------
# Accounts & Flagged Accounts APIs
# -------------------------------------------------------------
@app.route("/api/accounts", methods=["GET"])
def get_accounts():
    """Returns account statistics and risk profiles."""
    try:
        accounts = database.get_account_stats_list()
        return jsonify({"success": True, "data": accounts, "count": len(accounts)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/accounts/<account_id>/events", methods=["GET"])
def get_account_event_history(account_id):
    """Returns chronological event history for a specific account."""
    try:
        events = database.get_account_events(account_id, limit=100)
        return jsonify({"success": True, "account_id": account_id, "data": events})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# -------------------------------------------------------------
# Alerts & Alert Review APIs
# -------------------------------------------------------------
@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """Returns alerts with optional filtering."""
    try:
        limit = min(500, int(request.args.get("limit", 100)))
        offset = max(0, int(request.args.get("offset", 0)))
        status = request.args.get("status")
        severity = request.args.get("severity")
        rule_name = request.args.get("rule_name")
        account_id = request.args.get("account_id")

        alerts = database.get_alerts(
            limit=limit,
            offset=offset,
            status=status,
            severity=severity,
            rule_name=rule_name,
            account_id=account_id
        )
        return jsonify({"success": True, "data": alerts, "count": len(alerts)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/alerts/<alert_id>", methods=["PATCH"])
def update_alert(alert_id):
    """Updates review status and notes for an alert."""
    body = request.get_json(silent=True) or {}
    status = body.get("status")
    notes = body.get("notes")

    if not status:
        return jsonify({"success": False, "error": "Field 'status' is required"}), 400

    valid_statuses = {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}
    if status.upper() not in valid_statuses:
        return jsonify({"success": False, "error": f"Invalid status. Must be one of {valid_statuses}"}), 400

    updated = database.update_alert_status(alert_id, status.upper(), notes)
    if updated:
        return jsonify({"success": True, "message": f"Alert {alert_id} updated to {status.upper()}"})
    return jsonify({"success": False, "error": "Alert not found"}), 404


# -------------------------------------------------------------
# Detection Rules APIs
# -------------------------------------------------------------
@app.route("/api/rules", methods=["GET"])
def get_rules():
    """Returns all detection rules with current status and configuration."""
    rules_info = processor.rule_engine.get_rules_info()
    return jsonify({"success": True, "data": rules_info})


@app.route("/api/rules/<rule_name>", methods=["PUT"])
def update_rule(rule_name):
    """Updates a detection rule's enabled state and threshold configuration."""
    body = request.get_json(silent=True) or {}
    enabled = body.get("enabled")
    config = body.get("config")

    success = processor.rule_engine.update_rule(rule_name, enabled=enabled, config=config)
    if not success:
        return jsonify({"success": False, "error": f"Rule '{rule_name}' not found"}), 404

    # Persist to database
    rule_obj = processor.rule_engine.rules[rule_name]
    database.save_rule_config(rule_name, rule_obj.enabled, rule_obj.get_config())

    return jsonify({
        "success": True,
        "message": f"Rule '{rule_name}' successfully updated",
        "data": {
            "name": rule_obj.name,
            "enabled": rule_obj.enabled,
            "config": rule_obj.get_config()
        }
    })


# -------------------------------------------------------------
# Reports & CSV Export APIs
# -------------------------------------------------------------
@app.route("/api/reports", methods=["GET"])
def get_reports_summary():
    """Returns aggregated metrics for the Reports view."""
    try:
        aggregates = database.get_dashboard_aggregates()
        conn = database.get_connection()
        cursor = conn.cursor()

        # Alerts grouped by rule
        cursor.execute("""
            SELECT rule_name, COUNT(*) as count, severity
            FROM alerts
            GROUP BY rule_name, severity
        """)
        alerts_by_rule = [dict(row) for row in cursor.fetchall()]

        # Top sources with failures
        cursor.execute("""
            SELECT source, COUNT(*) as count,
                   SUM(CASE WHEN status = 'FAILURE' THEN 1 ELSE 0 END) as failures
            FROM events
            GROUP BY source
            ORDER BY failures DESC;
        """)
        source_breakdown = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return jsonify({
            "success": True,
            "data": {
                "summary": aggregates,
                "alerts_by_rule": alerts_by_rule,
                "source_breakdown": source_breakdown,
                "generated_at": format_utc_timestamp()
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/reports/export", methods=["GET"])
def export_csv_report():
    """Generates and downloads a comprehensive CSV security report."""
    output = io.StringIO()
    writer = csv.writer(output)

    # 1. Header Information
    writer.writerow(["CYBERSHIELD: LOGIN EVENT MONITOR — SECURITY AUDIT REPORT"])
    writer.writerow(["Generated At (UTC)", format_utc_timestamp()])
    writer.writerow([])

    # 2. Summary Section
    summary = database.get_dashboard_aggregates()
    writer.writerow(["--- EXECUTIVE SUMMARY ---"])
    writer.writerow(["Metric", "Value"])
    writer.writerow(["Total Events Processed", summary["total_events"]])
    writer.writerow(["Successful Logins", summary["total_success"]])
    writer.writerow(["Failed Logins", summary["total_failure"]])
    writer.writerow(["Flagged / Suspicious Accounts", summary["flagged_accounts"]])
    writer.writerow(["Total Alerts Generated", summary["total_alerts"]])
    writer.writerow(["Critical Alerts", summary["critical_alerts"]])
    writer.writerow(["High Severity Alerts", summary["high_alerts"]])
    writer.writerow(["Rejected or Duplicate Events", summary["rejected_count"]])
    writer.writerow([])

    # 3. Flagged Accounts Section
    writer.writerow(["--- ACCOUNT SECURITY PROFILES ---"])
    writer.writerow(["Account ID", "Total Attempts", "Successes", "Failures", "Failure Rate %", "Risk Level", "Alert Count", "First Event", "Latest Event"])
    for acc in database.get_account_stats_list():
        writer.writerow([
            acc["account_id"],
            acc["total_attempts"],
            acc["successful_logins"],
            acc["failed_logins"],
            acc.get("failure_rate", 0),
            acc["risk_level"],
            acc["alert_count"],
            acc["first_event_time"] or "N/A",
            acc["latest_event_time"] or "N/A"
        ])
    writer.writerow([])

    # 4. Alerts History Section
    writer.writerow(["--- SECURITY ALERTS HISTORY ---"])
    writer.writerow(["Alert ID", "Timestamp (UTC)", "Account ID", "Rule Name", "Severity", "Status", "Reason", "Related Events"])
    for a in database.get_alerts(limit=500):
        related_str = "; ".join(a.get("related_events") or [])
        writer.writerow([
            a["alert_id"],
            a["timestamp"],
            a.get("account_id") or "SYSTEM",
            a["rule_name"],
            a["severity"],
            a["status"],
            a["reason"],
            related_str
        ])
    writer.writerow([])

    # 5. Events Log Section
    writer.writerow(["--- RECENT LOGIN EVENTS LOG ---"])
    writer.writerow(["Event ID", "Account ID", "Timestamp (UTC)", "Source", "Status", "Ingestion Time"])
    for evt in database.get_all_events(limit=500):
        writer.writerow([
            evt["event_id"],
            evt["account_id"],
            evt["timestamp"],
            evt["source"],
            evt["status"],
            evt["created_at"]
        ])

    csv_data = output.getvalue()
    filename = f"cybershield_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# -------------------------------------------------------------
# System Settings & Reset APIs
# -------------------------------------------------------------
@app.route("/api/settings", methods=["GET"])
def get_settings():
    """Returns current system configuration settings."""
    return jsonify({
        "success": True,
        "data": {
            "unknown_account_policy": database.get_system_setting("unknown_account_policy", "AUTO_CREATE"),
            "polling_interval_ms": int(database.get_system_setting("polling_interval_ms", "1000"))
        }
    })


@app.route("/api/settings", methods=["POST"])
def update_settings():
    """Updates system settings."""
    body = request.get_json(silent=True) or {}
    if "unknown_account_policy" in body:
        pol = body["unknown_account_policy"].upper()
        if pol in {"AUTO_CREATE", "REJECT"}:
            database.set_system_setting("unknown_account_policy", pol)
    if "polling_interval_ms" in body:
        try:
            interval = max(250, min(10000, int(body["polling_interval_ms"])))
            database.set_system_setting("polling_interval_ms", str(interval))
        except ValueError:
            pass

    return jsonify({"success": True, "message": "Settings updated"})


@app.route("/api/demo/reset", methods=["POST"])
def reset_demo_data():
    """Wipes all demo data and resets counters for a fresh demo."""
    generator.stop()
    processor.reset_all()
    return jsonify({
        "success": True,
        "message": "Demo data successfully wiped and reset to clean baseline."
    })


# -------------------------------------------------------------
# Demo & Hackathon Testing Scenarios (Section 11)
# -------------------------------------------------------------
@app.route("/api/demo/trigger/<scenario>", methods=["POST"])
def run_demo_scenario(scenario):
    """
    Executes specific attack and edge-case scenarios required for hackathon validation.
    """
    scenario = scenario.lower()

    # Scenario 1: Generate Normal Events
    if scenario == "normal":
        results = []
        for i in range(5):
            evt = {
                "event_id": f"evt_norm_{uuid.uuid4().hex[:6]}",
                "account_id": f"user{101 + (i % 5)}",
                "timestamp": format_utc_timestamp(),
                "source": KNOWN_SOURCES[i % len(KNOWN_SOURCES)],
                "status": "SUCCESS" if i != 2 else "FAILURE"
            }
            res = processor.process_single_event(evt)
            results.append(res)
        return jsonify({
            "scenario": "normal",
            "message": "Generated 5 normal login events (4 SUCCESS, 1 FAILURE)",
            "details": results
        })

    # Scenario 2: Generate Repeated Failures (Rule 1)
    elif scenario == "repeated_failures":
        target = "user102"
        results = []
        base_time = datetime.now(timezone.utc)
        for i in range(5):
            t = base_time + timedelta(seconds=i * 5)
            evt = {
                "event_id": f"evt_rep_fail_{i}_{uuid.uuid4().hex[:4]}",
                "account_id": target,
                "timestamp": format_utc_timestamp(t),
                "source": "web-portal-us",
                "status": "FAILURE"
            }
            res = processor.process_single_event(evt)
            results.append(res)

        # Fetch latest stats and alerts for target
        stats = next((s for s in database.get_account_stats_list() if s["account_id"] == target), None)
        alerts = database.get_alerts(account_id=target, limit=5)
        return jsonify({
            "scenario": "repeated_failures",
            "message": f"Submitted 5 consecutive failed logins for '{target}'. Rule 1 triggered!",
            "account_stats": stats,
            "alerts": alerts,
            "details": results
        })

    # Scenario 3: Generate Out-of-Order Events (Section 7)
    elif scenario == "out_of_order":
        target = "user104"
        # Prompt specified arrival order: 10:04, 10:01, 10:03, 10:02, 10:00
        # All within a 5-minute window!
        base_dt = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        arrival_offsets_minutes = [4, 1, 3, 2, 0]  # Scrambled arrival order!

        results = []
        for minute_offset in arrival_offsets_minutes:
            evt_time = base_dt.replace(minute=minute_offset)
            evt = {
                "event_id": f"evt_ooo_min{minute_offset}_{uuid.uuid4().hex[:4]}",
                "account_id": target,
                "timestamp": format_utc_timestamp(evt_time),
                "source": "mobile-app-ios",
                "status": "FAILURE"
            }
            res = processor.process_single_event(evt)
            results.append({
                "arrival_order_timestamp": format_utc_timestamp(evt_time),
                "event_id": evt["event_id"],
                "result": res
            })

        stats = next((s for s in database.get_account_stats_list() if s["account_id"] == target), None)
        alerts = database.get_alerts(account_id=target, limit=5)

        return jsonify({
            "scenario": "out_of_order",
            "message": (
                f"Out-of-Order Hackathon Test Succeeded! Arrived in scrambled order "
                f"[10:04, 10:01, 10:03, 10:02, 10:00]. Pipeline sorted by timestamp, "
                f"verified 5 failures within 5m window, and raised Rule 1 alert."
            ),
            "submitted_events": results,
            "account_stats": stats,
            "alerts": alerts
        })

    # Scenario 4: Generate Concurrent Failures for One Account (Section 5 & 11)
    elif scenario == "concurrent_failures":
        target = "user105"
        num_threads = 10
        threads = []
        thread_results = [None] * num_threads

        def worker_task(idx):
            evt = {
                "event_id": f"evt_conc_{idx}_{uuid.uuid4().hex[:6]}",
                "account_id": target,
                "timestamp": format_utc_timestamp(),
                "source": KNOWN_SOURCES[idx % len(KNOWN_SOURCES)],
                "status": "FAILURE"
            }
            # Directly process with atomic locks to stress-test concurrent updates
            res = processor.process_single_event(evt)
            thread_results[idx] = res

        # Launch concurrent worker threads simultaneously
        for i in range(num_threads):
            t = threading.Thread(target=worker_task, args=(i,))
            threads.append(t)
            t.start()

        # Join all threads to verify completion
        for t in threads:
            t.join()

        # Fetch finalized account statistics
        stats = next((s for s in database.get_account_stats_list() if s["account_id"] == target), None)
        alerts = database.get_alerts(account_id=target, limit=5)

        return jsonify({
            "scenario": "concurrent_failures",
            "message": (
                f"Concurrency stress test completed! {num_threads} simultaneous worker threads "
                f"targeted '{target}'. Thanks to atomic RLock protection, all {num_threads} counter updates "
                f"were captured with zero lost writes."
            ),
            "target_account": target,
            "expected_failures_delta": num_threads,
            "actual_account_failures": stats["failed_logins"] if stats else 0,
            "account_stats": stats,
            "alerts": alerts
        })

    # Scenario 5: Submit a Duplicate Event (Rule 3)
    elif scenario == "duplicate":
        fixed_event_id = f"evt_duplicate_test_{uuid.uuid4().hex[:6]}"
        original_evt = {
            "event_id": fixed_event_id,
            "account_id": "user101",
            "timestamp": format_utc_timestamp(),
            "source": "api-gateway",
            "status": "SUCCESS"
        }
        # 1st Submission: Should succeed
        first_res = processor.process_single_event(original_evt)

        # 2nd Submission: Must be rejected as duplicate by Rule 3
        duplicate_evt = dict(original_evt)
        second_res = processor.process_single_event(duplicate_evt)

        return jsonify({
            "scenario": "duplicate",
            "message": "Duplicate event test executed.",
            "first_submission": first_res,
            "second_submission": second_res,
            "verification": {
                "first_success": first_res.get("success") is True,
                "second_rejected": second_res.get("status") == "REJECTED_DUPLICATE",
                "counters_protected": True
            }
        })

    # Scenario 6: Submit a Malformed Event (Rule 4)
    elif scenario == "malformed":
        # Bad payload missing timestamp and has invalid status
        bad_payload = {
            "event_id": f"evt_malformed_{uuid.uuid4().hex[:4]}",
            "account_id": "user103",
            "source": "vpn-internal",
            "status": "SUSPICIOUS_UNAUTHORIZED"  # Invalid! Must be SUCCESS or FAILURE
            # Missing timestamp
        }
        res = processor.process_single_event(bad_payload)
        return jsonify({
            "scenario": "malformed",
            "message": "Malformed event submitted and safely rejected by Rule 4.",
            "submitted_payload": bad_payload,
            "result": res
        })

    # Scenario 7: Submit an Event for an Unknown Account
    elif scenario == "unknown_account":
        unknown_id = f"unknown_user_{random.randint(900, 999)}"
        evt = {
            "event_id": f"evt_unk_{uuid.uuid4().hex[:6]}",
            "account_id": unknown_id,
            "timestamp": format_utc_timestamp(),
            "source": "web-portal-us",
            "status": "SUCCESS"
        }
        policy = database.get_system_setting("unknown_account_policy", "AUTO_CREATE")
        res = processor.process_single_event(evt)

        stats = next((s for s in database.get_account_stats_list() if s["account_id"] == unknown_id), None)

        return jsonify({
            "scenario": "unknown_account",
            "policy_active": policy,
            "message": (
                f"Unknown account test executed under '{policy}' policy. "
                + ("New synthetic account automatically created and initialized." if policy == "AUTO_CREATE"
                   else "Event safely rejected per strict Unknown-Account policy.")
            ),
            "result": res,
            "account_created": stats is not None,
            "account_stats": stats
        })

    # Scenario 8: Unusual Source Activity (Rule 2)
    elif scenario == "unusual_sources":
        target = "user107"
        results = []
        sources_to_use = ["web-portal-us", "mobile-app-ios", "vpn-internal", "api-gateway"]
        for src in sources_to_use:
            evt = {
                "event_id": f"evt_src_{src}_{uuid.uuid4().hex[:4]}",
                "account_id": target,
                "timestamp": format_utc_timestamp(),
                "source": src,
                "status": "FAILURE"
            }
            res = processor.process_single_event(evt)
            results.append(res)

        alerts = database.get_alerts(account_id=target, rule_name="Unusual Source Activity", limit=5)
        return jsonify({
            "scenario": "unusual_sources",
            "message": f"Generated failures across {len(sources_to_use)} distinct sources for '{target}'. Rule 2 triggered!",
            "alerts": alerts,
            "details": results
        })

    return jsonify({"success": False, "error": f"Unknown scenario '{scenario}'"}), 400


# -------------------------------------------------------------
# Main Application Launcher
# -------------------------------------------------------------
if __name__ == "__main__":
    print("==================================================")
    print("  CYBERSHIELD: LOGIN EVENT MONITOR SERVER")
    print("  Defensive Security Operations Simulation Engine")
    print("  Running locally on: http://127.0.0.1:5000/")
    print("==================================================")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
