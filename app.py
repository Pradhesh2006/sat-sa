"""
SAT-SA — Supervisory Analytics Tool for SOC Assessment
Full prototype: performance dashboard, filters, MITRE ATT&CK tagging,
SLA compliance, shift comparison, trend charts, workload heatmap,
week-over-week comparison, role-based access, audit log, CSV upload/export,
and PDF report generation.
"""
import sqlite3
import os
import io
import csv
import secrets
from collections import defaultdict
from functools import wraps
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, g, abort, request, redirect,
    url_for, session, flash, Response, send_file
)
from werkzeug.security import check_password_hash, generate_password_hash

from constants import MITRE_MAP, mitre_for, SLA_TARGETS

DB_PATH = "satsa.db"

app = Flask(__name__)
app.secret_key = os.environ.get("SAT_SA_SECRET_KEY", secrets.token_hex(32))


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def log_action(action, detail=""):
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (username, action, detail, created_at) VALUES (?, ?, ?, ?)",
        (session.get("username", "anonymous"), action, detail, datetime.now().isoformat())
    )
    db.commit()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def supervisor_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        if session.get("role") != "Supervisor":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["analyst_id"] = user["analyst_id"]
            log_action("login", f"role={user['role']}")
            next_url = request.args.get("next") or url_for("home")
            return redirect(next_url)

        flash("Invalid username or password.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    if "username" in session:
        log_action("logout")
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def home():
    """Route users to the right landing page based on role."""
    if session.get("role") == "Supervisor":
        return redirect(url_for("dashboard"))
    elif session.get("analyst_id"):
        return redirect(url_for("analyst_detail", analyst_id=session["analyst_id"]))
    abort(403)


# ---------------------------------------------------------------------------
# Filtering helpers
# ---------------------------------------------------------------------------

def get_filters():
    return {
        "start": request.args.get("start", "").strip(),
        "end": request.args.get("end", "").strip(),
        "severity": request.args.get("severity", "").strip(),
        "alert_type": request.args.get("alert_type", "").strip(),
        "shift": request.args.get("shift", "").strip(),
        "q": request.args.get("q", "").strip(),
    }


def filters_active(filters):
    return any(filters.values())


def build_where(filters, analyst_id=None):
    where = ["1=1"]
    params = []
    if filters.get("start"):
        where.append("date(a.opened_at) >= date(?)")
        params.append(filters["start"])
    if filters.get("end"):
        where.append("date(a.opened_at) <= date(?)")
        params.append(filters["end"])
    if filters.get("severity"):
        where.append("a.severity = ?")
        params.append(filters["severity"])
    if filters.get("alert_type"):
        where.append("a.alert_type = ?")
        params.append(filters["alert_type"])
    if filters.get("shift"):
        where.append("an.shift = ?")
        params.append(filters["shift"])
    if filters.get("q"):
        like = f"%{filters['q']}%"
        where.append("(an.name LIKE ? OR a.alert_type LIKE ?)")
        params.extend([like, like])
    if analyst_id is not None:
        where.append("a.analyst_id = ?")
        params.append(analyst_id)
    return " AND ".join(where), params


def fetch_alerts(db, filters, analyst_id=None, order_desc=True):
    where_sql, params = build_where(filters, analyst_id)
    order = "DESC" if order_desc else "ASC"
    query = f"""
        SELECT a.*, an.name AS analyst_name, an.shift AS analyst_shift, an.id AS a_analyst_id
        FROM alerts a JOIN analysts an ON a.analyst_id = an.id
        WHERE {where_sql}
        ORDER BY a.opened_at {order}
    """
    return db.execute(query, params).fetchall()


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------

def sla_minutes_for(severity):
    return SLA_TARGETS.get(severity, 60)


def compute_analyst_stats(db, filters):
    """Aggregate per-analyst metrics, filtered."""
    analysts = db.execute("SELECT * FROM analysts").fetchall()
    alerts = fetch_alerts(db, filters)

    by_analyst = defaultdict(list)
    for al in alerts:
        by_analyst[al["analyst_id"]].append(al)

    stats = []
    for a in analysts:
        rows = by_analyst.get(a["id"], [])
        total = len(rows)
        if total == 0:
            stats.append({
                "id": a["id"], "name": a["name"], "shift": a["shift"],
                "total_alerts": 0, "avg_response": 0, "avg_resolution": 0,
                "accuracy": 0, "fp_rate": 0, "escalated": 0,
                "sla_compliance": 0, "flags": [],
            })
            continue

        avg_response = sum(x["response_minutes"] for x in rows) / total
        avg_resolution = sum(x["resolution_minutes"] for x in rows) / total
        true_pos = sum(1 for x in rows if x["classification"] == "True Positive")
        false_pos = total - true_pos
        accuracy = round((true_pos / total) * 100, 1)
        fp_rate = round((false_pos / total) * 100, 1)
        escalated = sum(1 for x in rows if x["status"] == "Escalated")

        within_sla = sum(1 for x in rows if x["response_minutes"] <= sla_minutes_for(x["severity"]))
        sla_compliance = round((within_sla / total) * 100, 1)

        flags = []
        if avg_response > 45:
            flags.append("Slow response time")
        if fp_rate > 30:
            flags.append("High false-positive rate")
        if sla_compliance < 70:
            flags.append("SLA compliance below 70%")
        if total > 100:
            flags.append("Overloaded — high alert volume")
        if total < 30:
            flags.append("Underutilized — low alert volume")

        stats.append({
            "id": a["id"], "name": a["name"], "shift": a["shift"],
            "total_alerts": total,
            "avg_response": round(avg_response, 1),
            "avg_resolution": round(avg_resolution, 1),
            "accuracy": accuracy, "fp_rate": fp_rate,
            "escalated": escalated, "sla_compliance": sla_compliance,
            "flags": flags,
        })

    return stats


def compute_shift_stats(db, filters):
    """Aggregate metrics grouped by shift instead of by analyst."""
    alerts = fetch_alerts(db, filters)
    by_shift = defaultdict(list)
    for al in alerts:
        by_shift[al["analyst_shift"]].append(al)

    result = []
    for shift, rows in by_shift.items():
        total = len(rows)
        if total == 0:
            continue
        avg_response = round(sum(x["response_minutes"] for x in rows) / total, 1)
        true_pos = sum(1 for x in rows if x["classification"] == "True Positive")
        accuracy = round((true_pos / total) * 100, 1)
        within_sla = sum(1 for x in rows if x["response_minutes"] <= sla_minutes_for(x["severity"]))
        sla_compliance = round((within_sla / total) * 100, 1)
        result.append({
            "shift": shift, "total_alerts": total,
            "avg_response": avg_response, "accuracy": accuracy,
            "sla_compliance": sla_compliance,
        })
    result.sort(key=lambda x: x["shift"])
    return result


def compute_trend(db, filters, analyst_id=None, weeks=8):
    """Weekly buckets: avg response time + alert count, most recent `weeks` weeks."""
    alerts = fetch_alerts(db, filters, analyst_id=analyst_id, order_desc=False)
    if not alerts:
        return []

    buckets = defaultdict(list)
    for al in alerts:
        dt = datetime.fromisoformat(al["opened_at"])
        # ISO week label e.g. "2026-W23"
        week_label = f"{dt.isocalendar()[0]}-W{dt.isocalendar()[1]:02d}"
        buckets[week_label].append(al)

    ordered_weeks = sorted(buckets.keys())[-weeks:]
    trend = []
    for wk in ordered_weeks:
        rows = buckets[wk]
        total = len(rows)
        avg_response = round(sum(x["response_minutes"] for x in rows) / total, 1)
        true_pos = sum(1 for x in rows if x["classification"] == "True Positive")
        accuracy = round((true_pos / total) * 100, 1)
        trend.append({"week": wk, "count": total, "avg_response": avg_response, "accuracy": accuracy})
    return trend


def compute_heatmap(db, filters, analyst_id=None):
    """7 (weekday) x 24 (hour) grid of alert counts."""
    alerts = fetch_alerts(db, filters, analyst_id=analyst_id)
    grid = [[0] * 24 for _ in range(7)]  # grid[weekday][hour], Mon=0
    for al in alerts:
        dt = datetime.fromisoformat(al["opened_at"])
        grid[dt.weekday()][dt.hour] += 1
    return grid


def compute_comparison(db, analyst_id=None):
    """This week vs previous week — team-wide or for one analyst."""
    now = datetime.now()
    this_week_start = now - timedelta(days=7)
    last_week_start = now - timedelta(days=14)

    def period_stats(start, end):
        where = ["date(a.opened_at) >= date(?)", "date(a.opened_at) < date(?)"]
        params = [start.date().isoformat(), end.date().isoformat()]
        if analyst_id is not None:
            where.append("a.analyst_id = ?")
            params.append(analyst_id)
        query = f"""
            SELECT a.* FROM alerts a WHERE {' AND '.join(where)}
        """
        rows = db.execute(query, params).fetchall()
        total = len(rows)
        if total == 0:
            return {"count": 0, "avg_response": 0, "accuracy": 0}
        avg_response = round(sum(x["response_minutes"] for x in rows) / total, 1)
        true_pos = sum(1 for x in rows if x["classification"] == "True Positive")
        accuracy = round((true_pos / total) * 100, 1)
        return {"count": total, "avg_response": avg_response, "accuracy": accuracy}

    this_week = period_stats(this_week_start, now)
    last_week = period_stats(last_week_start, this_week_start)

    def delta(a, b):
        if b == 0:
            return 0
        return round(((a - b) / b) * 100, 1)

    return {
        "this_week": this_week,
        "last_week": last_week,
        "count_delta": delta(this_week["count"], last_week["count"]),
        "response_delta": delta(this_week["avg_response"], last_week["avg_response"]),
        "accuracy_delta": delta(this_week["accuracy"], last_week["accuracy"]),
    }


def refresh_flag_notifications(db, stats):
    """Compare current flags to stored flag_state; return newly-flagged names
    and persist the new state."""
    newly_flagged = []
    for s in stats:
        row = db.execute("SELECT was_flagged FROM flag_state WHERE analyst_id = ?", (s["id"],)).fetchone()
        currently_flagged = 1 if s["flags"] else 0
        was_flagged = row["was_flagged"] if row else 0

        if currently_flagged and not was_flagged:
            newly_flagged.append(s["name"])

        if row:
            db.execute("UPDATE flag_state SET was_flagged = ? WHERE analyst_id = ?",
                       (currently_flagged, s["id"]))
        else:
            db.execute("INSERT INTO flag_state (analyst_id, was_flagged) VALUES (?, ?)",
                       (s["id"], currently_flagged))
    db.commit()
    return newly_flagged


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@supervisor_required
def dashboard():
    db = get_db()
    filters = get_filters()
    stats = compute_analyst_stats(db, filters)

    total_alerts = sum(s["total_alerts"] for s in stats)
    team_avg_response = round(
        sum(s["avg_response"] * s["total_alerts"] for s in stats) / total_alerts, 1
    ) if total_alerts else 0
    team_avg_accuracy = round(
        sum(s["accuracy"] * s["total_alerts"] for s in stats) / total_alerts, 1
    ) if total_alerts else 0
    team_sla = round(
        sum(s["sla_compliance"] * s["total_alerts"] for s in stats) / total_alerts, 1
    ) if total_alerts else 0
    flagged_count = sum(1 for s in stats if s["flags"])

    by_speed = sorted([s for s in stats if s["total_alerts"] > 0], key=lambda x: x["avg_response"])
    by_accuracy = sorted([s for s in stats if s["total_alerts"] > 0], key=lambda x: -x["accuracy"])
    by_volume = sorted(stats, key=lambda x: -x["total_alerts"])

    shift_stats = compute_shift_stats(db, filters)
    trend = compute_trend(db, filters)
    heatmap = compute_heatmap(db, filters)
    comparison = compute_comparison(db)

    newly_flagged = refresh_flag_notifications(db, stats)

    recent_alerts = fetch_alerts(db, filters)[:18]
    live_feed = []
    for a in recent_alerts:
        mitre = mitre_for(a["alert_type"])
        live_feed.append({
            "time": a["opened_at"][11:16],
            "date": a["opened_at"][:10],
            "analyst": a["analyst_name"],
            "type": a["alert_type"],
            "mitre": mitre["id"],
            "severity": a["severity"],
            "classification": a["classification"],
        })

    all_alert_types = sorted(MITRE_MAP.keys())
    all_shifts = sorted({a["shift"] for a in db.execute("SELECT DISTINCT shift FROM analysts").fetchall()})

    return render_template(
        "dashboard.html",
        stats=stats,
        total_alerts=total_alerts,
        team_avg_response=team_avg_response,
        team_avg_accuracy=team_avg_accuracy,
        team_sla=team_sla,
        flagged_count=flagged_count,
        by_speed=by_speed,
        by_accuracy=by_accuracy,
        by_volume=by_volume,
        shift_stats=shift_stats,
        trend=trend,
        heatmap=heatmap,
        heatmap_days=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        comparison=comparison,
        newly_flagged=newly_flagged,
        live_feed=live_feed,
        filters=filters,
        filters_active=filters_active(filters),
        all_alert_types=all_alert_types,
        all_shifts=all_shifts,
        all_severities=list(SLA_TARGETS.keys()),
        generated_at=datetime.now().strftime("%d %b %Y, %I:%M %p"),
    )


@app.route("/analyst/<int:analyst_id>")
@login_required
def analyst_detail(analyst_id):
    # Analyst-role users may only view their own page.
    if session.get("role") == "Analyst" and session.get("analyst_id") != analyst_id:
        abort(403)

    db = get_db()
    analyst = db.execute("SELECT * FROM analysts WHERE id = ?", (analyst_id,)).fetchone()
    if analyst is None:
        abort(404)

    filters = get_filters()
    alerts = fetch_alerts(db, filters, analyst_id=analyst_id)

    all_stats = compute_analyst_stats(db, filters)
    my_stats = next((s for s in all_stats if s["id"] == analyst_id), None)

    type_breakdown = {}
    for al in alerts:
        t = al["alert_type"]
        type_breakdown.setdefault(t, {"count": 0, "true_pos": 0})
        type_breakdown[t]["count"] += 1
        if al["classification"] == "True Positive":
            type_breakdown[t]["true_pos"] += 1

    trend = compute_trend(db, filters, analyst_id=analyst_id)
    heatmap = compute_heatmap(db, filters, analyst_id=analyst_id)
    comparison = compute_comparison(db, analyst_id=analyst_id)

    recent = alerts[:25]
    recent_tagged = []
    for a in recent:
        d = dict(a)
        d["mitre"] = mitre_for(a["alert_type"])
        d["sla_target"] = sla_minutes_for(a["severity"])
        d["within_sla"] = a["response_minutes"] <= d["sla_target"]
        recent_tagged.append(d)

    return render_template(
        "analyst.html",
        analyst=analyst,
        alerts=recent_tagged,
        stats=my_stats,
        type_breakdown=type_breakdown,
        trend=trend,
        heatmap=heatmap,
        heatmap_days=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        comparison=comparison,
        filters=filters,
        is_supervisor=(session.get("role") == "Supervisor"),
        mitre_map=MITRE_MAP,
    )


# ---------------------------------------------------------------------------
# CSV upload (real data ingestion)
# ---------------------------------------------------------------------------

REQUIRED_CSV_COLUMNS = [
    "analyst_name", "alert_type", "severity", "opened_at",
    "response_minutes", "resolution_minutes", "classification", "status"
]


@app.route("/upload", methods=["GET", "POST"])
@supervisor_required
def upload():
    db = get_db()
    result = None

    if request.method == "POST":
        file = request.files.get("csv_file")
        if not file or file.filename == "":
            flash("Please choose a CSV file.")
            return redirect(url_for("upload"))

        try:
            stream = io.StringIO(file.stream.read().decode("utf-8-sig"))
            reader = csv.DictReader(stream)
            missing = [c for c in REQUIRED_CSV_COLUMNS if c not in (reader.fieldnames or [])]
            if missing:
                flash(f"CSV is missing required columns: {', '.join(missing)}")
                return redirect(url_for("upload"))

            inserted, skipped = 0, 0
            analyst_cache = {row["name"]: row["id"] for row in db.execute("SELECT id, name FROM analysts")}

            for row in reader:
                name = (row.get("analyst_name") or "").strip()
                if not name:
                    skipped += 1
                    continue

                if name not in analyst_cache:
                    cur = db.execute(
                        "INSERT INTO analysts (name, shift) VALUES (?, ?)",
                        (name, row.get("shift", "Unassigned").strip() or "Unassigned")
                    )
                    analyst_cache[name] = cur.lastrowid

                try:
                    db.execute("""
                        INSERT INTO alerts
                        (analyst_id, alert_type, severity, opened_at, response_minutes,
                         resolution_minutes, classification, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        analyst_cache[name],
                        row["alert_type"].strip(),
                        row["severity"].strip(),
                        row["opened_at"].strip(),
                        int(row["response_minutes"]),
                        int(row["resolution_minutes"]),
                        row["classification"].strip(),
                        row["status"].strip(),
                    ))
                    inserted += 1
                except (ValueError, KeyError):
                    skipped += 1

            db.commit()
            log_action("csv_upload", f"inserted={inserted} skipped={skipped} file={file.filename}")
            result = {"inserted": inserted, "skipped": skipped}
            flash(f"Import complete: {inserted} alerts added, {skipped} rows skipped.")

        except Exception as e:
            flash(f"Import failed: {e}")

    return render_template("upload.html", result=result, required_columns=REQUIRED_CSV_COLUMNS)


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

@app.route("/export/alerts.csv")
@supervisor_required
def export_alerts_csv():
    db = get_db()
    filters = get_filters()
    alerts = fetch_alerts(db, filters)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Analyst", "Shift", "Alert Type", "MITRE ID", "Severity",
                      "Opened At", "Response (min)", "Resolution (min)",
                      "Classification", "Status"])
    for a in alerts:
        mitre = mitre_for(a["alert_type"])
        writer.writerow([a["analyst_name"], a["analyst_shift"], a["alert_type"],
                          mitre["id"], a["severity"], a["opened_at"],
                          a["response_minutes"], a["resolution_minutes"],
                          a["classification"], a["status"]])

    log_action("export_csv", f"alerts export, {len(alerts)} rows")
    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    return send_file(mem, mimetype="text/csv", as_attachment=True,
                      download_name=f"sat-sa-alerts-{datetime.now().strftime('%Y%m%d')}.csv")


@app.route("/export/summary.csv")
@supervisor_required
def export_summary_csv():
    db = get_db()
    filters = get_filters()
    stats = compute_analyst_stats(db, filters)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Analyst", "Shift", "Total Alerts", "Avg Response (min)",
                      "Avg Resolution (min)", "Accuracy %", "False Positive %",
                      "SLA Compliance %", "Escalated", "Flags"])
    for s in stats:
        writer.writerow([s["name"], s["shift"], s["total_alerts"], s["avg_response"],
                          s["avg_resolution"], s["accuracy"], s["fp_rate"],
                          s["sla_compliance"], s["escalated"], "; ".join(s["flags"])])

    log_action("export_csv", "summary export")
    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    return send_file(mem, mimetype="text/csv", as_attachment=True,
                      download_name=f"sat-sa-summary-{datetime.now().strftime('%Y%m%d')}.csv")


@app.route("/export/report.pdf")
@supervisor_required
def export_report_pdf():
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

    db = get_db()
    filters = get_filters()
    stats = compute_analyst_stats(db, filters)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("SAT-SA — Supervisory Analytics Report", styles["Title"]))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%d %b %Y, %I:%M %p')}", styles["Normal"]))
    elements.append(Spacer(1, 16))

    table_data = [["Analyst", "Shift", "Alerts", "Avg Resp (min)", "Accuracy %", "SLA %", "Flags"]]
    for s in stats:
        table_data.append([
            s["name"], s["shift"], str(s["total_alerts"]), str(s["avg_response"]),
            f"{s['accuracy']}%", f"{s['sla_compliance']}%",
            ", ".join(s["flags"]) if s["flags"] else "—"
        ])

    t = Table(table_data, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1622")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#2dd4bf")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(t)

    doc.build(elements)
    buf.seek(0)
    log_action("export_pdf", "supervisory report")
    return send_file(buf, mimetype="application/pdf", as_attachment=True,
                      download_name=f"sat-sa-report-{datetime.now().strftime('%Y%m%d')}.pdf")


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

@app.route("/audit")
@supervisor_required
def audit():
    db = get_db()
    logs = db.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200").fetchall()
    return render_template("audit.html", logs=logs)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
