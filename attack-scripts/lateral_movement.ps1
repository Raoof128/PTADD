<#
.SYNOPSIS
    Lateral Movement via WMI/PSRemoting (MITRE ATT&CK: T1570)

.DESCRIPTION
    Demonstrates lateral movement techniques using WMI and PowerShell Remoting

.NOTES
    Author: Purple Team Lab
    MITRE ATT&CK: T1570 - Lateral Tool Transfer
    Date: 2024-01-14

.EXAMPLE
    .\lateral_movement.ps1 -Target WS02 -Credential (Get-Credential)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Target,

    [Parameter(Mandatory=$false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory=$false)]
    [string]$Command = "whoami"
)

Write-Host "===== LATERAL MOVEMENT ATTACK ====="
Write-Host "MITRE ATT&CK: T1570"
Write-Host "Target: $Target`n"

# Method 1: WMI
Write-Host "[*] Method 1: WMI Command Execution"
$WMICmd = "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'cmd.exe /c $Command' -ComputerName $Target"
Write-Host $WMICmd

# Method 2: PowerShell Remoting
Write-Host "`n[*] Method 2: PowerShell Remoting"
$PSRemoteCmd = "Invoke-Command -ComputerName $Target -ScriptBlock { $Command }"
Write-Host $PSRemoteCmd

# Method 3: PsExec
Write-Host "`n[*] Method 3: PsExec"
Write-Host "PsExec.exe \\$Target -u DOMAIN\user -p password cmd.exe"

Write-Host "`n[+] Detection: Monitor Event IDs 4688, 4689, 4624 (Type 3)"
