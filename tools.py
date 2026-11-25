import os, json, ipaddress, requests

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY")

def check_ip_reputation(ip: str) -> dict:
    try:
        if ipaddress.ip_address(ip).is_private:
            return {"ip": ip, "note": "Private lab address; public reputation databases have no data on it."}
    except ValueError:
        return {"ip": ip, "error": "not a valid IP address"}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10)
        data = resp.json().get("data", {})
        return {"ip": ip, "abuse_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"), "country": data.get("countryCode")}
    except Exception as e:
        return {"ip": ip, "error": str(e)}

def search_alert_logs(keyword: str, log_file: str = "alerts_export.json") -> dict:
    matches = []
    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if keyword in line:
                    try:
                        a = json.loads(line)
                        matches.append({"time": a.get("timestamp"),
                                        "rule": a.get("rule", {}).get("description"),
                                        "log": a.get("full_log", "")[:200]})
                    except json.JSONDecodeError:
                        continue
    except FileNotFoundError:
        return {"error": f"{log_file} not found"}
    return {"keyword": keyword, "match_count": len(matches), "matches": matches[:5]}

MITRE_LOOKUP = {
    "failed_login": "T1110 - Brute Force",
    "sudo_misuse": "T1548 - Abuse Elevation Control Mechanism",
    "file_creation_temp": "T1105 - Ingress Tool Transfer",
    "credential_access": "T1003 - OS Credential Dumping",
    "recon_scan": "T1595 - Active Scanning",
}

def map_to_mitre(activity_type: str) -> dict:
    return {"activity_type": activity_type,
            "mitre_technique": MITRE_LOOKUP.get(activity_type, "Unknown - manual review needed")}