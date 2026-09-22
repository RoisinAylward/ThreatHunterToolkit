# run.ps1
# Main script to run all detection functions

# definied paths:
#log files:
$LogPath = "$PSScriptRoot\ProjectDataset"
$AccessLog = "$LogPath\access.log"
$AuthLog = "$LogPath\auth.log"
$PSLog = "$LogPath\powershell_log.txt"
$IOCFile = "$LogPath\ioc.txt"

$ScriptPath = "$PSScriptRoot\scripts"
$AuthThreats = "$ScriptPath\detect_auth_threats.ps1"
$PowerShellThreats = "$ScriptPath\detect_powershell_threats.ps1"
$IOCThreats = "$ScriptPath\detect_ioc.ps1"
$WebScanningThreats = "$ScriptPath\detect_web_scanning.ps1"

$ReportPath = "$PSScriptRoot\investigation_report.txt"

$FilesToCheck = @($AccessLog, $AuthLog, $PSLog, $IOCFile, $AuthThreats, $PowerShellThreats, $IOCThreats, $WebScanningThreats)

$MissingFiles = @()

foreach ($file in $FilesToCheck) {
    if (-Not (Test-Path $file)) {
        $MissingFiles += $file
    }
}

if ($MissingFiles.Count -gt 0) {
    Write-Host "[ERROR] The following required files were not found:"
    foreach ($file in $MissingFiles) {
        Write-Host "  - $file"
    }
    Write-Host "Please ensure all required log files and scripts are in the expected locations."
    exit 1
}

Write-Host "[*] All files validated successfully"
Write-Host ""

# run detections to return to terminal output:
$AuthResults = & $AuthThreats -LogFile $AuthLog
$PowerShellResults = & $PowerShellThreats -LogFile $PSLog
$IOCResults = & $IOCThreats -AccessLog $AccessLog -IOCFile $IOCFile
$WebScanningResults = & $WebScanningThreats -AccessLog $AccessLog

# generate report based on results:
& "$PSScriptRoot\scripts\generate_report.ps1" `
    -ReportPath $ReportPath `
    -AuthResults $AuthResults `
    -PowerShellResults $PowerShellResults `
    -IOCResults $IOCResults `
    -WebScanningResults $WebScanningResults
