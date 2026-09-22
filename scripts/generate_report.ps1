# generate_report.ps1
# generates the final investigation_report.txt

param (
    [string]$ReportPath,
    [array]$AuthResults,
    [array]$PowerShellResults,
    [array]$IOCResults,
    [array]$WebScanningResults
)

$SuccessIPs = $AuthResults | Where-Object { $_ -match "^SUCCESS\|" } | ForEach-Object { ($_ -split "\|")[1] }

$BruteForceCount = ($AuthResults | Where-Object { $_ -notmatch "^SUCCESS\|" -and $_ -notmatch "^ENUM\|" -and $SuccessIPs -notcontains ($_ -split "\|")[0]}).Count
$SuccessCount = ($AuthResults | Where-Object { $_ -match "^SUCCESS\|" }).Count
$EnumerationCount = ($AuthResults | Where-Object { $_ -match "^ENUM\|" }).Count

$EncodedCount = ($PowerShellResults | Where-Object { $_ -match "^EncodedCommand\|" }).Count
$BypassCount = ($PowerShellResults | Where-Object { $_ -match "^ExecutionPolicyBypass\|" }).Count
$WebRequestCount = ($PowerShellResults | Where-Object { $_ -match "^SuspiciousWebRequest\|" }).Count
$DownloadCount = ($PowerShellResults | Where-Object { $_ -match "^DownloadString\|" }).Count
$ExfilCount = ($PowerShellResults | Where-Object { $_ -match "^DataExfiltration\|" }).Count
$ReconCount = ($PowerShellResults | Where-Object { $_ -match "^Reconnaissance\|" }).Count

$MaliciousIPCount = ($IOCResults | Where-Object { $_ -match "^MaliciousIP\|" } | ForEach-Object { ($_ -split "\|")[1] } | Sort-Object -Unique).Count
$MaliciousPathCount = ($IOCResults | Where-Object { $_ -match "^MaliciousPath\|" } | ForEach-Object { ($_ -split "\|")[1] } | Sort-Object -Unique).Count

$TotalAlerts = $BruteForceCount + $SuccessCount + $EnumerationCount + $PowerShellResults.Count + $MaliciousIPCount + $MaliciousPathCount + $WebScanningResults.Count

#risk level:
if ($SuccessCount -gt 0) {
    $RiskLevel = "CRITICAL"
} elseif ($ExfilCount -gt 0) {
    $RiskLevel = "CRITICAL"
} elseif ($MaliciousIPCount -gt 0) {
    $RiskLevel = "CRITICAL"
} elseif ($ReconCount -gt 0) {
    $RiskLevel = "HIGH"
} elseif ($EnumerationCount -gt 0) {
    $RiskLevel = "HIGH"
} elseif ($TotalAlerts -ge 20) {
    $RiskLevel = "HIGH"
} elseif ($TotalAlerts -ge 5) {
    $RiskLevel = "MEDIUM"
} elseif ($TotalAlerts -ge 1) {
    $RiskLevel = "LOW"
} else {
    $RiskLevel = "NONE"
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ArchiveFolder = "$PSScriptRoot\..\archive"
if (Test-Path $ReportPath) {
    if (-Not (Test-Path $ArchiveFolder)) {
        New-Item -ItemType Directory -Path $ArchiveFolder | Out-Null
    }
    $ExistingReport = Get-Content $ReportPath
    $TimestampLine = $ExistingReport | Select-String -Pattern "^Generated: "
    if ($TimestampLine) {
        $ExistingTimestamp = $TimestampLine.Line.Replace("Generated: ", "").Trim()
        $ExistingTimestamp = $ExistingTimestamp.Replace(":", "-").Replace(" ", "_")
    } else {
        $ExistingTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    }
    $ArchivePath = "$ArchiveFolder\investigation_report_$ExistingTimestamp.txt"
    Move-Item -Path $ReportPath -Destination $ArchivePath
    Write-Host "[*] Previous report archived to: $ArchivePath"
}


$report = @"
================================================================
                 SECURITY INVESTIGATION REPORT
================================================================
Generated: $timestamp

EXECUTIVE SUMMARY
-----------------
Total Alerts Detected: $TotalAlerts
Overall Risk Level: $RiskLevel

Detection modules run:
  [1] SSH Brute Force and Enumeration Detection (auth.log)
  [2] Suspicious PowerShell Activity (powershell_log.txt)
  [3] IOC Matching (access.log vs ioc.txt)
  [4] Web Scanning Detection (access.log)

================================================================
         SSH BRUTE FORCE AND ENUMERATION (Detection 1)
================================================================
Threshold: 5 or more failed SSH login attempts from one IP
           3 or more distinct usernames tried from one IP

Brute force attempts detected: $BruteForceCount IP(s)
Brute force successes: $SuccessCount IP(s)
Username enumeration: $EnumerationCount IP(s)
"@

if ($AuthResults.Count -eq 0) {
    $report += "`r`nNo authentication threats detected.`r`n"
} else {
    $report += "`r`nALERTS:`r`n"
    foreach ($f in $AuthResults) {
        $parts = $f -split "\|"
        if ($parts[0] -eq "SUCCESS") {
            $ip = $parts[1]
            $count = $parts[2]
            $report += "  - [BRUTE FORCE SUCCESS] $ip - $count failed attempts followed by successful login`r`n"
        } elseif ($parts[0] -eq "ENUM") {
            $ip = $parts[1]
            $EnumerationCount = $parts[2]
            $usernames = $parts[3]
            $report += "  - [ENUMERATION] $ip - $EnumerationCount distinct usernames tried: $usernames`r`n"
        } else {
            $ip = $parts[0]
            $count = $parts[1]
            $report += "  - [BRUTE FORCE] $ip - $count attempts`r`n"
        }
    }
}

$report += @"

================================================================
          SUSPICIOUS POWERSHELL ACTIVITY (Detection 2)
================================================================
Result: $($PowerShellResults.Count) suspicious event(s) detected

Encoded commands: $EncodedCount
Execution policy bypass: $BypassCount
Suspicious web requests: $WebRequestCount
DownloadString usage: $DownloadCount
Data exfiltration patterns: $ExfilCount
Reconnaissance commands detected: $ReconCount
"@

if ($PowerShellResults.Count -eq 0) {
    $report += "`r`nNo suspicious PowerShell activity detected.`r`n"
} else {
    $report += "`r`nALERTS:`r`n"
    foreach ($f in $PowerShellResults) {
        $parts = $f -split "\|"
        $type = $parts[0]
        $detail = $parts[1]

        switch ($type) {
            "EncodedCommand" { $label = "ENCODED COMMAND" }
            "ExecutionPolicyBypass"{ $label = "EXECUTION POLICY BYPASS" }
            "SuspiciousWebRequest" { $label = "SUSPICIOUS WEB REQUEST" }
            "DownloadString" { $label = "DOWNLOAD STRING" }
            "DataExfiltration" { $label = "DATA EXFILTRATION" }
            "Reconnaissance" { $label = "RECONNAISSANCE" }
            default { $label = $type.ToUpper() }
        }

        $report += "  - [$label] $detail`r`n"
    }
}

$report += @"

================================================================
                   IOC MATCHING (Detection 3)
================================================================
Result: $($MaliciousIPCount + $MaliciousPathCount) unique IOC match(es) detected

Malicious IP matches: $MaliciousIPCount
Malicious path matches: $MaliciousPathCount
"@

if ($IOCResults.Count -eq 0) {
    $report += "`r`nResult: No IOC matches found.`r`n"
} else {
    $report += "`r`nALERTS:`r`n"
    foreach ($f in $IOCResults) {
        $parts = $f -split "\|"
        $type = $parts[0]
        $indicator = $parts[1]
        $entry = $parts[2]
        
        if ($type -eq "MaliciousIP") {
            $label = "MALICIOUS IP"
        } else {
            $label = "MALICIOUS PATH"
        }

        $report += "  - [$label] $indicator`r`n    $entry`r`n"
    }
}

$report += @"

================================================================
                   WEB SCANNING (Detection 4)
================================================================
Threshold: 20 or more HTTP 404/403 errors from a single IP
Result: $($WebScanningResults.Count) scanning IP(s) detected
"@

if ($WebScanningResults.Count -eq 0) {
    $report += "`r`nNo web scanning activity detected.`r`n"
} else {
    $report += "`r`nALERTS:`r`n"
    foreach ($f in $WebScanningResults) {
        $parts = $f -split "\|"
        $ip = $parts[0]
        $count404 = $parts[1]
        $count403 = $parts[2]
        $total = $parts[3]
            $report += "  - [WEB SCANNING] $ip - 404 Errors: $count404 | 403 Errors: $count403 | Total Client Errors: $total`r`n"
    }
}

$report += @"

================================================================
                         FINAL SUMMARY
================================================================
Total Alerts: $TotalAlerts
Risk Level: $RiskLevel

Recommended Actions:

"@

if ($AuthResults.Count -gt 0) {
    $report += "  - Block IPs with repeated SSH failures using firewall rules.`r`n"
    $report += "  - Enable SSH key-based authentication and disable password login.`r`n"
}
if ($SuccessCount -gt 0) {
    $report += "  - URGENT: Confirmed compromise - immediately revoke access for affected IPs.`r`n"
    $report += "  - Investigate all activity from successful login IPs.`r`n"
}
if ($EnumerationCount -gt 0) {
    $report += "  - Block IPs performing username enumeration at the firewall.`r`n"
    $report += "  - Consider implementing account lockout policies.`r`n"
}
if ($PowerShellResults.Count -gt 0) {
    $report += "  - Investigate PowerShell execution on the host immediately.`r`n"
    $report += "  - Review PowerShell logging and consider Constrained Language Mode.`r`n"
}
if ($IOCResults.Count -gt 0) {
    $report += "  - Block all IOC IPs and paths at the firewall/WAF level.`r`n"
    $report += "  - Escalate to Tier 2 for deeper forensic investigation.`r`n"
}
if ($WebScanningResults.Count -gt 0) {
    $report += "  - Rate-limit or block scanning IPs at the web server.`r`n"
    $report += "  - Review WAF rules to detect and block scanner signatures.`r`n"
}
if ($TotalAlerts -eq 0) {
    $report += "  - No immediate action required. Continue monitoring.`r`n"
}

$report += @"

================================================================
                         END OF REPORT
================================================================
"@

#write report to file
$report | Out-File -FilePath $ReportPath -Encoding UTF8

Write-Host ""
Write-Host "================================================================"
Write-Host "Report saved to: $ReportPath"
Write-Host "Total Alerts: $TotalAlerts"
Write-Host "Risk Level: $RiskLevel"
Write-Host "================================================================"
Write-Host ""

