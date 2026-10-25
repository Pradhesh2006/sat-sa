"""
Shared reference data for SAT-SA.
"""

# Maps each alert type in the sample data to a MITRE ATT&CK technique.
# In a real deployment this would come from the SIEM/SOAR's own tagging —
# this is a reasonable static mapping for demo/prototype purposes.
MITRE_MAP = {
    "Phishing Email":               {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
    "Malware Detection":            {"id": "T1204", "name": "User Execution", "tactic": "Execution"},
    "Brute Force Login":            {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "Suspicious Outbound Traffic":  {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "Port Scan":                    {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "Privilege Escalation":         {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "Data Exfiltration Attempt":    {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "Unauthorized Access":          {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
    "DDoS Attempt":                 {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    "Insider Threat Indicator":     {"id": "T1078.002", "name": "Valid Accounts: Domain Accounts", "tactic": "Persistence"},
}

def mitre_for(alert_type):
    return MITRE_MAP.get(alert_type, {"id": "—", "name": "Unmapped", "tactic": "—"})


# Response-time SLA targets in minutes, by severity. Used to compute
# each analyst's SLA compliance percentage.
SLA_TARGETS = {
    "Critical": 15,
    "High": 30,
    "Medium": 60,
    "Low": 120,
}
