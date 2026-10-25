# SAT-SA — Supervisory Analytics Tool for SOC Assessment

Prototype for SIH26157 (NTRO). A Flask dashboard that lets SOC supervisors
monitor and improve analyst performance, with role-based access for
analysts to view their own stats.------------------------------------------------------------------------------------------------------------------## Features
- **Performance metrics**: alerts handled, avg response/resolution time,
  accuracy, false-positive rate, escalations, SLA compliance %
- **Auto-flagging**: slow response, high false-positive rate, SLA breach,
  overload, underutilization
- **Filters**: date range, severity, alert type, shift, free-text search
- **MITRE ATT&CK tagging**: every alert type mapped to a technique + tactic
- **Shift comparison**: aggregate performance grouped by shift
- **Trend charts**: weekly response time / accuracy / volume (Chart.js)
- **Workload heatmap**: alerts by day-of-week x hour-of-day
- **Week-over-week comparison**: this week vs last week, with deltas
- **Role-based access**: Supervisor sees everything; Analyst accounts are
  locked to their own performance page only
- **Audit log**: logs, exports, uploads, all timestamped with the user
- **CSV upload**: ingest real alert data (SIEM/SOAR export format)
- **Exports**: alerts CSV, summary CSV, and a PDF supervisory report
- **In-app notifications**: banner when an analyst newly crosses a flag
  threshold since the last dashboard check
------------------------------------------------------------------------------------------------------------------
## Run it
```
pip install -r requirements.txt
python init_db.py      # creates satsa.db with 60 days of sample data
python app.py           # starts on http://localhost:5000
```
------------------------------------------------------------------------------------------------------------------
## Logins
- Supervisor: `admin` / `admin123`
- Analyst (locked to their own page): `ananya` / `analyst123`

Change these (edit `DEFAULT_USERS` in `init_db.py`) before real use.
Sessions use a random secret key each restart — set `SAT_SA_SECRET_KEY`
as an environment variable for a fixed key in real deployments.
------------------------------------------------------------------------------------------------------------------
## CSV upload format
Required columns: `analyst_name, alert_type, severity, opened_at,
response_minutes, resolution_minutes, classification, status`
(optional `shift` column when creating a new analyst).
`opened_at` must be ISO format (e.g. `2026-09-05T14:30:00`).
`classification` is `True Positive` or `False Positive`.
`status` is `Resolved` or `Escalated`.
------------------------------------------------------------------------------------------------------------------
## Still worth adding for a full production version
- Password reset / account management UI (currently edit `init_db.py`)
- Pagination on the alerts table (currently capped at 25/200 rows shown)
- Email notifications (current notifications are in-app only)
- Multi-supervisor org support / team hierarchies
