# (c) Thomas Dang, 2024
# This script shadows all the users in a given OU and adds them to a group
# Useful for GPO targeting groups or Fine Grained Password Policies
#
# This work is licensed under GNU GPLv3.0
# View the repository here: https://github.com/litobro/ad-hibp-audit

# Get Parameters
param (
    [string]$ou,
    [string]$group,
    [string]$filter = "*"
)

# Import the Active Directory module
Import-Module ActiveDirectory

# Check for parameters
if ($ou -eq "" -or $group -eq "") {
    Write-Host "Usage: ShadowUsers.ps1 -ou <OU> -group <Group> [-filter <Filter>]"
    Write-Host "Example: ShadowUsers.ps1 -ou 'OU=Example,DC=contoso,DC=com' -group 'all-users' -filter 'enabled -eq `$true'"
    exit
}

# Check OU exists
$ouExists = Get-ADOrganizationalUnit -Filter {DistinguishedName -eq $ou}
if ($null -eq $ouExists) {
    Write-Host "OU not found"
    exit
}

# Check group exists
$groupExists = Get-ADGroup -Filter {Name -eq $group}
if ($null -eq $groupExists) {
    Write-Host "Group not found"
    exit
}

# Add all users in the OU to the group
$users = Get-ADUser -Filter $filter -SearchBase $ou
Add-ADGroupMember -Identity $group -Members $users
