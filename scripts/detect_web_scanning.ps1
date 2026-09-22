# detect_web_scanning.ps1
# Detects IPs making an unusually high number of 404/403 requests in access.log

param (
    [string]$AccessLog,
    [int]$threshold = 20
)

Write-Host "[*] Checking for web scanning activity..."

$LogLines = Get-Content $AccessLog

$results404 = $LogLines | Where-Object { $_ -match '" 404 ' } |
    ForEach-Object {
        if ($_ -match "^(\d+\.\d+\.\d+\.\d+)") { $Matches[1] }
    } |
    Group-Object |
    Sort-Object Count -Descending

$results403 = $LogLines | Where-Object { $_ -match '" 403 ' } |
    ForEach-Object {
        if ($_ -match "^(\d+\.\d+\.\d+\.\d+)") { $Matches[1] }
    } |
    Group-Object |
    Sort-Object Count -Descending

$AllIPs = ($results404 + $results403) |
    ForEach-Object { $_.Name } |
    Sort-Object -Unique

$ReportedIPs = @()

foreach ($ip in $AllIPs) {
    $match404 = $results404 | Where-Object { $_.Name -eq $ip }
    $match403 = $results403 | Where-Object { $_.Name -eq $ip }

    if ($match404) { $count404 = $match404.Count } else { $count404 = 0 }
    if ($match403) { $count403 = $match403.Count } else { $count403 = 0 }

    $TotalErrors = $count404 + $count403

    if ($TotalErrors -ge $threshold) {
        Write-Host "[ALERT] Web scanning detected from $ip (404 errors: $count404 | 403 errors: $count403 | Total: $TotalErrors)"
        Write-Output "$ip|$count404|$count403|$TotalErrors"
        $ReportedIPs += $ip
    }
}

Write-Host "[*] Web scanning check complete"