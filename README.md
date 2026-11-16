# Threat Hunter Toolkit

A PowerShell tool that analyses SSH, web server and PowerShell logs for signs of attack, checks them against a list of known-bad indicators, and writes an investigation report with a risk level and recommended actions. It's aimed at a Security Operations Centre (SOC), where analysts need to get through a lot of log data quickly without checking it all by hand.

Built as the individual project for *Advanced Scripting for Cyber Security* (COMP H2705) at TU Dublin. The logs in `ProjectDataset/` are the dataset provided for the project.

---

## 📂 Repository Structure

```
ThreatHunterToolkit/
├── run.ps1                              # Runs the whole investigation
├── scripts/
│   ├── detect_auth_threats.ps1          # SSH brute force, successful brute force, username enumeration
│   ├── detect_powershell_threats.ps1    # Six checks for suspicious PowerShell activity
│   ├── detect_ioc.ps1                   # Matches web traffic against known-bad IPs and paths
│   ├── detect_web_scanning.ps1          # IPs producing lots of 404/403 errors
│   └── generate_report.ps1              # Builds the report, sets the risk level, archives the old report
├── ProjectDataset/
│   ├── auth.log                         # SSH authentication log
│   ├── access.log                       # Web server access log
│   ├── powershell_log.txt               # Host PowerShell execution log
│   └── ioc.txt                          # Known malicious IPs and web paths
├── investigation_report.txt             # Report from the latest run
├── archive/                             # Earlier reports, named with the time they were generated
└── documentation/
    └── Threat Hunter Toolkit Report.pdf # Project report
```

---

## ⚙️ How It Works

`run.ps1` sets all the file paths in one place (using `$PSScriptRoot`, so it works from any folder), checks that every log file and script exists, runs each detection script in turn, and passes their results to `generate_report.ps1`. Each detection is its own script, so one can be changed or added without touching the others.

| Detection | Script | Log | Flagged when |
|-----------|--------|-----|--------------|
| SSH brute force | `detect_auth_threats.ps1` | `auth.log` | 5 or more failed logins from one IP |
| Brute force success | `detect_auth_threats.ps1` | `auth.log` | A flagged IP also has a successful login |
| Username enumeration | `detect_auth_threats.ps1` | `auth.log` | 3 or more different usernames tried from one IP |
| Suspicious PowerShell | `detect_powershell_threats.ps1` | `powershell_log.txt` | Any of six rule-based checks matches |
| IOC matching | `detect_ioc.ps1` | `access.log` and `ioc.txt` | Any match against a known-bad IP or path |
| Web scanning | `detect_web_scanning.ps1` | `access.log` | 20 or more 404/403 errors from one IP |

The six PowerShell checks look for:

- `-EncodedCommand`, which attackers use to hide payloads in Base64
- `-ExecutionPolicy Bypass`
- `Invoke-WebRequest` to domains that aren't Microsoft's
- `DownloadString`
- `Compress-Archive` together with `Invoke-WebRequest -Upload`, which points to data exfiltration (both timestamps go in the alert)
- two or more reconnaissance commands from a set list (`whoami`, `ipconfig`, `net user`, `netstat`, `tasklist`, `systeminfo`)

Between them, the detections cover signature-based detection (matching known indicators) and anomaly-based detection (thresholds on unusual behaviour).

### Risk level

Some findings set the risk level on their own, whatever the alert count. The counts are a fallback for when none of those findings is present.

| Level | Trigger |
|-------|---------|
| CRITICAL | A brute force success, data exfiltration, or a known malicious IP in the web traffic |
| HIGH | Reconnaissance commands, username enumeration, or 20 or more alerts |
| MEDIUM | 5 to 19 alerts |
| LOW | 1 to 4 alerts |
| NONE | No alerts |

### Reports

`generate_report.ps1` puts the findings into a plain-text report, with recommended actions for whatever was detected. If `investigation_report.txt` already exists, the script reads the timestamp inside it, renames the old report with that timestamp and moves it to `archive/`, so earlier results are never overwritten.

---

## 📊 Results on the Project Dataset

Running the tool on the dataset raised **65 alerts** and a **CRITICAL** risk level:

| Detection | What it found |
|-----------|---------------|
| SSH brute force | 46 IPs, the worst with 157 failed attempts |
| Brute force success | 2 of those IPs then logged in successfully |
| Username enumeration | 2 IPs, one trying 24 different usernames |
| Suspicious PowerShell | 8 events: an encoded command, an execution policy bypass, two suspicious web requests, three reconnaissance commands, and a compress-then-upload exfiltration pattern |
| IOC matching | 5 indicators (2 malicious IPs and 3 malicious paths) found in 14 log entries |
| Web scanning | 2 IPs, with 899 and 451 `404` errors |

The risk level was CRITICAL because of the two successful brute force logins, the known malicious IPs in the web traffic and the exfiltration pattern.

The start of the report from that run:

```
================================================================
                 SECURITY INVESTIGATION REPORT
================================================================
Generated: 2026-05-03 17:27:52

EXECUTIVE SUMMARY
-----------------
Total Alerts Detected: 65
Overall Risk Level: CRITICAL
```

The full report is in [`investigation_report.txt`](investigation_report.txt), and earlier runs are in [`archive/`](archive).

---

## ▶️ Running It

In PowerShell, from the repository folder:

```powershell
.\run.ps1
```

Alerts are printed to the console as they're found, and the report is written to `investigation_report.txt`.

---

## ⚠️ Limitations

- The brute force and web scanning thresholds are fixed, so they don't adapt to different servers or traffic levels.
- Findings are grouped by detection type, not in time order, which makes it harder to follow an attack from start to finish.
- A slow attack that spreads its attempts out could stay under the thresholds.
- The IOC section lists every matching log entry separately instead of grouping them by indicator.
- The report is plain text, so it couldn't be fed straight into a SIEM.

---

## 📄 Report

The full [project report (PDF)](documentation/Threat%20Hunter%20Toolkit%20Report.pdf) can be viewed in-repo. It covers the design of each detection, example results with screenshots, and possible improvements.
