# Thomas Dang, 2024
# Removes users from a group who are disabled
#
# This work is licensed under GNU GPLv3.0
# View the repository here: https://github.com/litobro/ad-hibp-audit

# Get Parameters
param (
    [string]$group
)

# Import the Active Directory module
Import-Module ActiveDirectory

# Check for parameters
if ($group -eq "") {
    Write-Host "Usage: UnshadowDisabledUsers.ps1 -group <Group>"
    Write-Host "Example: UnshadowDisabledUsers.ps1 -group 'all-users'"
    exit
}

# Check group exists
$groupExists = Get-ADGroup -Filter {Name -eq $group}
if ($null -eq $groupExists) {
    Write-Host "Group not found"
    exit
}

# Remove all disabled users from the group
Get-ADGroupMember -Identity $group | ForEach-Object {
    $user = $_
    $userObj = Get-ADUser -Identity $user
    if ($userObj.Enabled -eq $false) {
        # Remove user from group without confirmation
        Remove-ADGroupMember -Identity $group -Members $userObj -Confirm:$false
    }
}
