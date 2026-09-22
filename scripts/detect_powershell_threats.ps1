# detect_powershell_threats.ps1
# Detects suspicious PowerShell execution patterns from powershell_log.txt

param (
    [string]$LogFile
)

Write-Host "[*] Checking PowerShell threats..."

$LogLines = Get-Content $LogFile

$EncodedMatches = $LogLines | Select-String -Pattern "-EncodedCommand"
foreach ($line in $EncodedMatches) {
    Write-Host "[ALERT] Encoded command detected: $($line.Line.Trim())"
    Write-Output "EncodedCommand|$($line.Line.Trim())"
}

$BypassMatches = $LogLines | Select-String -Pattern "-ExecutionPolicy Bypass"
foreach ($line in $BypassMatches) {
    Write-Host "[ALERT] Execution policy bypass detected: $($line.Line.Trim())"
    Write-Output "ExecutionPolicyBypass|$($line.Line.Trim())"
}

$WebMatches = $LogLines | Select-String -Pattern "Invoke-WebRequest"
foreach ($line in $WebMatches) {
    if ($line.Line -notmatch "microsoft\.com|windowsupdate\.com|office\.com") {
        Write-Host "[ALERT] Suspicious web request detected: $($line.Line.Trim())"
        Write-Output "SuspiciousWebRequest|$($line.Line.Trim())"
    } else {
        Write-Host "[INFO] Benign web request: $($line.Line.Trim())"
    }
}

$DownloadMatches = $LogLines | Select-String -Pattern "DownloadString"
foreach ($line in $DownloadMatches) {
    Write-Host "[ALERT] DownloadString detected: $($line.Line.Trim())"
    Write-Output "DownloadString|$($line.Line.Trim())"
}

#data exfilitration
$CompressFound = $LogLines | Select-String -Pattern "Compress-Archive"
$UploadFound = $LogLines | Select-String -Pattern "Invoke-WebRequest.*-Upload"

if ($CompressFound -and $UploadFound) {
    $CompressTime = $CompressFound.Line.Trim().Substring(0, 19)
    $UploadTime   = $UploadFound.Line.Trim().Substring(0, 19)
    Write-Host "[ALERT] Potential data exfiltration detected: Compress-Archive at $CompressTime followed by suspicious web request at $UploadTime"
    Write-Output "DataExfiltration|Compress-Archive at $CompressTime followed by Invoke-WebRequest -Upload at $UploadTime"
}

$ReconCommands = @("whoami", "ipconfig", "net user", "netstat", "tasklist", "systeminfo")
$ReconFound = @()

foreach ($cmd in $ReconCommands) {
    $match = $LogLines | Select-String -Pattern "^\d{4}-\d{2}-\d{2}.*\b$cmd\b"
    if ($match) {
        $ReconFound += $match.Line.Trim()
    }
}

if ($ReconFound.Count -ge 2) {
    Write-Host "[ALERT] Reconnaissance command sequence detected:"
    foreach ($line in $ReconFound) {
        Write-Host "  $line"
        Write-Output "Reconnaissance|$line"
    }
}
