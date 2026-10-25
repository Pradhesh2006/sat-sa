"""
SAT-SA — Supervisory Analytics Tool for SOC Assessment
Database initializer: creates schema and seeds realistic sample data
spanning 60 days (needed for week-over-week comparison and trend charts).
"""
import sqlite3
import random
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

DB_PATH = "satsa.db"

# Default accounts seeded on first run.
# CHANGE THESE PASSWORDS before using this anywhere beyond a local demo.
# analyst_username links an Analyst-role account to one analyst row so they
# only ever see their own performance page.
DEFAULT_USERS = [
    {"username": "admin", "password": "admin123", "role": "Supervisor", "analyst_name": None},
    {"username": "ananya", "password": "analyst123", "role": "Analyst", "analyst_name": "Ananya Rao"},
]

ALERT_TYPES = [
    "Phishing Email", "Malware Detection", "Brute Force Login",
    "Suspicious Outbound Traffic", "Port Scan", "Privilege Escalation",
    "Data Exfiltration Attempt", "Unauthorized Access", "DDoS Attempt",
    "Insider Threat Indicator"
]

SEVERITIES = ["Low", "Medium", "High", "Critical"]

ANALYSTS = [
    {"name": "Ananya Rao", "shift": "Morning (6AM-2PM)"},
    {"name": "Vikram Singh", "shift": "Morning (6AM-2PM)"},
    {"name": "Priya Nair", "shift": "Evening (2PM-10PM)"},
    {"name": "Karthik Subramaniam", "shift": "Evening (2PM-10PM)"},
    {"name": "Fatima Sheikh", "shift": "Night (10PM-6AM)"},
    {"name": "Rohan Mehta", "shift": "Night (10PM-6AM)"},
]

# Each analyst gets a "performance profile" so the data tells a believable story.
# trend: 'improving' / 'declining' / 'stable' lets the trend chart show movement
# over the 60-day window instead of a flat line.
PROFILES = {
    "Ananya Rao":         dict(speed=0.9,  accuracy=0.93, volume=1.2, trend="stable"),
    "Vikram Singh":       dict(speed=0.55, accuracy=0.80, volume=0.7, trend="improving"),
    "Priya Nair":         dict(speed=0.85, accuracy=0.95, volume=1.0, trend="stable"),
    "Karthik Subramaniam":dict(speed=0.75, accuracy=0.60, volume=1.4, trend="declining"),
    "Fatima Sheikh":      dict(speed=0.80, accuracy=0.90, volume=0.5, trend="stable"),
    "Rohan Mehta":        dict(speed=0.70, accuracy=0.88, volume=1.6, trend="declining"),
}

DAYS_OF_HISTORY = 60


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.executescript("""
    DROP TABLE IF EXISTS alerts;
    DROP TABLE IF EXISTS analysts;
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS audit_log;
    DROP TABLE IF EXISTS flag_state;

    CREATE TABLE analysts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        shift TEXT NOT NULL
    );

    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'Supervisor',
        analyst_id INTEGER,
        FOREIGN KEY (analyst_id) REFERENCES analysts (id)
    );

    CREATE TABLE alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analyst_id INTEGER NOT NULL,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        opened_at TEXT NOT NULL,
        response_minutes INTEGER NOT NULL,
        resolution_minutes INTEGER NOT NULL,
        classification TEXT NOT NULL,  -- 'True Positive' or 'False Positive'
        status TEXT NOT NULL,          -- 'Resolved' or 'Escalated'
        FOREIGN KEY (analyst_id) REFERENCES analysts (id)
    );

    CREATE TABLE audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        detail TEXT,
        created_at TEXT NOT NULL
    );

    CREATE TABLE flag_state (
        analyst_id INTEGER PRIMARY KEY,
        was_flagged INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (analyst_id) REFERENCES analysts (id)
    );
    """)

    analyst_ids = {}
    for a in ANALYSTS:
        cur.execute("INSERT INTO analysts (name, shift) VALUES (?, ?)", (a["name"], a["shift"]))
        analyst_ids[a["name"]] = cur.lastrowid
        cur.execute("INSERT INTO flag_state (analyst_id, was_flagged) VALUES (?, 0)",
                    (analyst_ids[a["name"]],))

    for u in DEFAULT_USERS:
        aid = analyst_ids.get(u["analyst_name"]) if u["analyst_name"] else None
        cur.execute(
            "INSERT INTO users (username, password_hash, role, analyst_id) VALUES (?, ?, ?, ?)",
            (u["username"], generate_password_hash(u["password"]), u["role"], aid)
        )

    base_date = datetime.now() - timedelta(days=DAYS_OF_HISTORY)
    random.seed(42)

    for name, aid in analyst_ids.items():
        profile = PROFILES[name]
        num_alerts = int(90 * profile["volume"])

        for i in range(num_alerts):
            day_offset = random.randint(0, DAYS_OF_HISTORY - 1)

            # Apply trend: performance drifts better/worse as days progress.
            progress = day_offset / DAYS_OF_HISTORY  # 0 (old) -> 1 (recent)
            if profile["trend"] == "improving":
                speed_mod = profile["speed"] * (0.75 + 0.5 * progress)
                acc_mod = min(0.97, profile["accuracy"] * (0.85 + 0.3 * progress))
            elif profile["trend"] == "declining":
                speed_mod = profile["speed"] * (1.25 - 0.5 * progress)
                acc_mod = max(0.45, profile["accuracy"] * (1.15 - 0.3 * progress))
            else:
                speed_mod = profile["speed"]
                acc_mod = profile["accuracy"]

            alert_type = random.choice(ALERT_TYPES)
            severity = random.choices(SEVERITIES, weights=[35, 35, 20, 10])[0]
            opened_at = base_date + timedelta(
                days=day_offset,
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )

            base_response = random.randint(5, 60)
            response_minutes = max(2, int(base_response / max(0.3, speed_mod)))

            base_resolution = random.randint(20, 180)
            resolution_minutes = max(response_minutes + 5, int(base_resolution / max(0.3, speed_mod)))

            is_true_positive = random.random() < acc_mod
            classification = "True Positive" if is_true_positive else "False Positive"
            status = "Resolved" if random.random() < 0.92 else "Escalated"

            cur.execute("""
                INSERT INTO alerts
                (analyst_id, alert_type, severity, opened_at, response_minutes,
                 resolution_minutes, classification, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (aid, alert_type, severity, opened_at.isoformat(),
                  response_minutes, resolution_minutes, classification, status))

    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")
    print(f"  {len(ANALYSTS)} analysts, {DAYS_OF_HISTORY} days of alert history")
    print(f"  Supervisor login -> username: 'admin'   password: 'admin123'")
    print(f"  Analyst login    -> username: 'ananya'  password: 'analyst123'")
    print(f"  (change these before real use)")


if __name__ == "__main__":
    init_db()
