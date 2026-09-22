# detect_auth_threats.ps1
# Detects repeated failed authentication attempts from auth.log

param (
    [string]$LogFile,
    [int]$BruteForceThreshold = 5,
    [int]$EnumerationThreshold = 3
)

Write-Host "[*] Checking SSH brute force..."

$InvalidUser = Select-String -Path $LogFile -Pattern "Invalid user.*from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" |
    ForEach-Object { $_.Matches.Groups[1].Value } 

$FailedPassword = Select-String -Path $LogFile -Pattern "Failed password.*from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" |
    ForEach-Object { $_.Matches.Groups[1].Value }

$results = ($FailedPassword + $InvalidUser) |
    Group-Object |
    Sort-Object Count -Descending

foreach ($group in $results) {
    $count = $group.Count
    $ip = $group.Name
    if ($count -ge $BruteForceThreshold) {
        Write-Host "[ALERT] Brute force suspected from $ip ($count attempts)"
        Write-Output "$ip|$count"
    }
}

#checks if flagged IP later sucessfully logged in:
$SuccessLines = Select-String -Path $LogFile -Pattern "Accepted.*from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" |
    ForEach-Object { $_.Matches.Groups[1].Value }

foreach ($group in $results) {
    $ip = $group.Name
    $count = $group.Count
    if ($count -ge $BruteForceThreshold -and $SuccessLines -contains $ip) {
        Write-Host "[ALERT] Brute force SUCCESS - $ip had $count failed attempts and a successful login"
        Write-Output "SUCCESS|$ip|$count"
    }
}

# check for username enumeration
Write-Host "[*] Checking username enumeration..."

$EnumResults = Select-String -Path $LogFile -Pattern "Invalid user\s+(\S+)\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" |
    ForEach-Object {
        "$($_.Matches.Groups[2].Value)|$($_.Matches.Groups[1].Value)"
    }

# group by IP and collect distinct usernames
$IPUsernames = $EnumResults | Group-Object { ($_ -split "\|")[0] }

foreach ($group in $IPUsernames) {
    $ip = $group.Name
    $usernames = $group.Group | ForEach-Object { ($_ -split "\|")[1] } | Sort-Object -Unique
    $UsernameCount = $usernames.Count
    if ($UsernameCount -ge $EnumerationThreshold) {
        $UsernameList = $usernames -join ", "
        Write-Host "[ALERT] Username enumeration from $ip ($UsernameCount distinct usernames: $UsernameList)"
        Write-Output "ENUM|$ip|$UsernameCount|$UsernameList"
    }
}

Write-Host "[*] Brute force check complete"
