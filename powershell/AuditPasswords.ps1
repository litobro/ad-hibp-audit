# (c) Thomas Dang, 2024
# This script downloads the latest HIBP hashes and checks all users in a target group
# It then adds the breached users to a group for Fine Grained Password Policies
#
# This work is licensed under GNU GPLv3.0
# View the repository here: https://github.com/litobro/ad-hibp-audit

# Get Parameters
param (
    [string]$group = "", # Target group to add users
    [string]$targetUserGroup = "", # Target user group dn to check passwords and reset
    [string]$server = "", # AD server to check/replicate
    [string]$download = "n",
    [string] $resetPasses = "y"
)

# Check for parameters
if ($group -eq "" -or $targetUserGroup -eq "" -or $server -eq "") {
    Write-Host "Usage: AuditPasswords.ps1 -group <GroupName> -targetUserGroup <GroupDN> -server <ADServer> [-download <y/n>] [-resetPasses <y/n>]"
    Write-Host "Example: Audit-Passwords.ps1 -group 'breached-users' -targetUserGroup 'OU=Users,DC=contoso,DC=com' -server 'contoso.com' -download 'y' -resetPasses 'y'"
    Write-Host "Defaults: -download 'y' -resetPasses 'y'"
    exit
}

# Write an output log of start time
Write-Output "$(Get-Date) - Starting script" >> "Audit-Passwords.log"

# Output the parameters
Write-Output "Group: $group" >> "Audit-Passwords.log"
Write-Output "Target User Group: $targetUserGroup" >> "Audit-Passwords.log"
Write-Output "Server: $server" >> "Audit-Passwords.log"
Write-Output "Download: $download" >> "Audit-Passwords.log"
Write-Output "Reset Passwords: $resetPasses" >> "Audit-Passwords.log"

if ($download -eq "y") {
    Write-Output "$(Get-Date) - Downloading latest HIBP hashes" >> "Audit-Passwords.log"

    # Use start-job to run the downloader in the background and output to log
    # Start-Job -Name "DownloadHashes" -ScriptBlock { "haveibeenpwned-downloader.exe -n -o" }
    # Get-Job -Name "DownloadHashes" | Wait-Job

    $proc = Start-Process "C:\scripts\haveibeenpwned-downloader.exe" -ArgumentList "-n -o" -Wait -PassThru -RedirectStandardOutput "hibp-downloader.log" -RedirectStandardError "hibp-downloader-err.log"
    # Wait for the process to finish
    $proc.WaitForExit()

    if ($proc.ExitCode -ne 0) {
        Write-Output "$(Get-Date) - Error downloading HIBP hashes" >> "Audit-Passwords.log"
        Write-Output $proc.ExitCode >> "Audit-Passwords.log"
        Write-Output $proc.StandardOutput.ReadToEnd() >> "Audit-Passwords.log"
        exit
    }

    Write-Output "$(Get-Date) - Finished downloading HIBP hashes" >> "Audit-Passwords.log"
}
Write-Output "$(Get-Date) - Checking passwords for weak hashes" >> "Audit-Passwords.log"

# We have to repl all passwords as we can't target by group
$results = Get-ADReplAccount -All -Server $server | 
Test-PasswordQuality -WeakPasswordHashesSortedFile .\pwnedpasswords_ntlm.txt

# Get current date
$date = Get-Date -Format "yyyy-MM-dd"

# Set export path
$weakPassPath = ".\$date-WeakPass.csv"

# Output weak accounts to CSV
$weakPasses = $results.WeakPassword | Select-Object @{Name='SamAccountName';Expression={$_}}
$weakPasses | Export-Csv -Path $weakPassPath -NoTypeInformation

# Log length of weak passwords found
Write-Output "$(Get-Date) - Found $($weakPasses.Count) weak passwords" >> "Audit-Passwords.log"

# Process the weak password results and enforce some password changes
if ($resetPasses) {
    Write-Host "Adding users to $group"
}
$processedUsers = @($weakPasses | ForEach-Object {
    $user = Get-ADUser -Identity $_.SamAccountName.Split('\')[1] -Properties CanonicalName,MemberOf
    $sam = $_.SamAccountName.Split('\')[1]
    $userOU = $user.CanonicalName

    # Check user in group
    if ($user.MemberOf -contains $targetUserGroup) {
        if ($resetPasses -eq "y") {
            # Add breached users to an AD Group for Fine Grained Password Policy (FGPP)
            Add-ADGroupMember -Identity $group -Members $sam
        }
        else {
            Write-Host "UPN: $sam OU: $userOU"
        }
        [PSCustomObject]@{
            SamAccountName = $sam
            OU = $userOU
        }
    }
})

# Log the number of users who will be processed
Write-Output "$(Get-Date) - Found $($processedUsers.Count) users to add to breached users" >> "Audit-Passwords.log"

# Export the processed users to a CSV
$processedUsers | Export-Csv -Path ".\$date-AddEnforcedGroup.csv" -NoTypeInformation

# Remove users who have already changed their password to something not breached
$members = Get-ADGroupMember -Identity $group

$removedUsers = @($members | ForEach-Object {
    $sam = $_.SamAccountName
    if ($_.SamAccountName -notin $processedUsers.SamAccountName) {
        Remove-ADGroupMember -Identity $group -Members $sam -Confirm:$false
        Write-Host "Removing $sam from $group as password not breached"
        [PSCustomObject]@{
            SamAccountName = $sam
        }
    } else {
        Write-Host "$sam is BREACHED and left in group"
    }
})

# Log the number of users who will be removed
Write-Output "$(Get-Date) - Found $($removedUsers.Count) users to remove from breached users" >> "Audit-Passwords.log"

# Export the removed users to a CSV
$removedUsers | Export-Csv -Path ".\$date-RemoveEnforcedGroup.csv" -NoTypeInformation
