# detect_ioc.ps1
# Checks access.log against known malicious indicators in ioc.txt

param (
    [string]$AccessLog,
    [string]$IOCFile
)

Write-Host "[*] Checking IOC matches..."

$IOCLines = Get-Content $IOCFile | Where-Object { $_ -notmatch "^#" -and $_.Trim() -ne "" }

$MaliciousIPs   = $IOCLines | Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" }
$MaliciousPaths = $IOCLines | Where-Object { $_ -match "^/" }

Write-Host "[*] Loaded $($MaliciousIPs.Count) malicious IPs and $($MaliciousPaths.Count) malicious paths"

$AccessLogLines = Get-Content $AccessLog

foreach ($ip in $MaliciousIPs) {
    $matches = $AccessLogLines | Select-String -Pattern "^$ip "
    foreach ($match in $matches) {
        Write-Host "[ALERT] Malicious IP $ip found: $($match.Line.Trim())"
        Write-Output "MaliciousIP|$ip|$($match.Line.Trim())"
    }
}

foreach ($path in $MaliciousPaths) {
    $matches = $AccessLogLines | Select-String -Pattern $path -SimpleMatch
    foreach ($match in $matches) {
        Write-Host "[ALERT] Malicious path $path found: $($match.Line.Trim())"
        Write-Output "MaliciousPath|$path|$($match.Line.Trim())"
    }
}
