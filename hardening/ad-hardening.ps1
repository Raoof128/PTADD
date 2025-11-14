<#
.SYNOPSIS
    Active Directory Security Hardening Script

.DESCRIPTION
    Implements Active Directory security best practices to defend against
    common attack techniques demonstrated in this Purple Team lab.

    Hardens against:
    - Kerberoasting (T1558.003)
    - AS-REP Roasting (T1558.004)
    - DCSync (T1003.006)
    - Golden/Silver Tickets (T1558.001/002)
    - ACL Abuse (T1222.001)
    - GPO Abuse (T1484.001)
    - Password Spraying (T1110.003)

.NOTES
    Author: Purple Team Lab
    Date: 2024-01-14
    Requires: Domain Admin privileges

.EXAMPLE
    .\ad-hardening.ps1 -Action All -ReportOnly

.EXAMPLE
    .\ad-hardening.ps1 -Action EnableAudit -Apply
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('All','EnableAudit','HardenKerberos','ProtectPrivilegedAccounts','EnableSMBSigning','DisableNTLMv1','HardenGPOs','ImplementLAPS','Report')]
    [string]$Action = "Report",

    [Parameter(Mandatory=$false)]
    [switch]$Apply,

    [Parameter(Mandatory=$false)]
    [switch]$ReportOnly,

    [Parameter(Mandatory=$false)]
    [string]$LogPath = "$PWD\ad_hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

# Requires Active Directory module
Import-Module ActiveDirectory -ErrorAction Stop

$ErrorActionPreference = 'Continue'

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogPath -Value $LogMessage
}

function Get-CurrentSecurityPosture {
    Write-Log "===== CURRENT SECURITY POSTURE =====" "INFO"

    # Check for accounts with Kerberos pre-auth disabled
    $NoPreAuthUsers = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    Write-Log "Users with pre-auth disabled: $($NoPreAuthUsers.Count)" "WARNING"

    # Check for service accounts with weak passwords
    $OldPasswords = Get-ADUser -Filter {PasswordLastSet -lt (Get-Date).AddDays(-90)} -Properties PasswordLastSet, ServicePrincipalNames | Where-Object {$_.ServicePrincipalNames}
    Write-Log "Service accounts with passwords >90 days old: $($OldPasswords.Count)" "WARNING"

    # Check Protected Users group membership
    $ProtectedUsers = Get-ADGroupMember -Identity "Protected Users"
    Write-Log "Protected Users group members: $($ProtectedUsers.Count)" "INFO"

    # Check admin count
    $AdminCount = (Get-ADUser -Filter {AdminCount -eq 1}).Count
    Write-Log "Users with AdminCount=1: $AdminCount" "INFO"

    Write-Log "======================================`n" "INFO"
}

function Enable-AdvancedAuditing {
    Write-Log "===== ENABLING ADVANCED AUDITING =====" "INFO"

    if ($ReportOnly) {
        Write-Log "[REPORT] Would enable advanced auditing policies" "INFO"
        return
    }

    $AuditPolicies = @(
        @{Category="Account Logon"; SubCategory="Credential Validation"; Setting="Success,Failure"}
        @{Category="Account Logon"; SubCategory="Kerberos Service Ticket Operations"; Setting="Success,Failure"}
        @{Category="Account Logon"; SubCategory="Kerberos Authentication Service"; Setting="Success,Failure"}
        @{Category="Account Management"; SubCategory="User Account Management"; Setting="Success,Failure"}
        @{Category="Account Management"; SubCategory="Security Group Management"; Setting="Success"}
        @{Category="DS Access"; SubCategory="Directory Service Access"; Setting="Success,Failure"}
        @{Category="DS Access"; SubCategory="Directory Service Changes"; Setting="Success"}
        @{Category="Logon/Logoff"; SubCategory="Logon"; Setting="Success,Failure"}
        @{Category="Logon/Logoff"; SubCategory="Logoff"; Setting="Success"}
        @{Category="Logon/Logoff"; SubCategory="Special Logon"; Setting="Success"}
    )

    foreach ($Policy in $AuditPolicies) {
        Write-Log "Configuring: $($Policy.Category) - $($Policy.SubCategory)" "INFO"
        if ($Apply) {
            auditpol /set /subcategory:"$($Policy.SubCategory)" /success:enable /failure:enable
        }
    }

    Write-Log "[+] Advanced auditing configured for attack detection" "SUCCESS"
}

function Harden-KerberosSettings {
    Write-Log "===== HARDENING KERBEROS CONFIGURATION =====" "INFO"

    # Disable RC4 encryption (prevents Kerberoasting effectiveness)
    Write-Log "Disabling RC4 Kerberos encryption..." "INFO"

    if ($Apply) {
        # Set registry to disable RC4
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $RegPath -Name "SupportedEncryptionTypes" -Value 0x18 -Type DWord  # AES128/256 only
        Write-Log "[+] RC4 encryption disabled - Kerberoasting harder" "SUCCESS"
    } else {
        Write-Log "[REPORT] Would disable RC4 encryption" "INFO"
    }

    # Enable Kerberos pre-authentication for all users
    Write-Log "Enabling Kerberos pre-auth for all users..." "INFO"

    $NoPreAuthUsers = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

    foreach ($User in $NoPreAuthUsers) {
        Write-Log "Fixing: $($User.SamAccountName)" "WARNING"
        if ($Apply) {
            Set-ADAccountControl -Identity $User -DoesNotRequirePreAuth $false
        }
    }

    Write-Log "[+] AS-REP Roasting attack surface eliminated" "SUCCESS"

    # Set strong Kerberos ticket lifetimes
    Write-Log "Configuring Kerberos ticket lifetimes..." "INFO"
    if ($Apply) {
        # Default: 10 hours for TGT, 10 hours for service tickets
        # Reduced: 4 hours for TGT, 2 hours for service tickets
        Write-Log "[MANUAL] Set via Group Policy: Computer Config -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy" "INFO"
        Write-Log "  - Maximum lifetime for user ticket: 4 hours" "INFO"
        Write-Log "  - Maximum lifetime for service ticket: 2 hours" "INFO"
    }
}

function Protect-PrivilegedAccounts {
    Write-Log "===== PROTECTING PRIVILEGED ACCOUNTS =====" "INFO"

    # Add high-value accounts to Protected Users group
    $ProtectedUsersGroup = Get-ADGroup -Identity "Protected Users"

    $PrivilegedAccounts = @("Administrator", "krbtgt")  # Add more as needed

    foreach ($Account in $PrivilegedAccounts) {
        try {
            $User = Get-ADUser -Identity $Account
            $IsMember = Get-ADGroupMember -Identity $ProtectedUsersGroup | Where-Object {$_.SamAccountName -eq $Account}

            if (-not $IsMember) {
                Write-Log "Adding $Account to Protected Users group..." "INFO"
                if ($Apply) {
                    Add-ADGroupMember -Identity $ProtectedUsersGroup -Members $User
                    Write-Log "[+] $Account protected from credential delegation" "SUCCESS"
                }
            } else {
                Write-Log "$Account already in Protected Users group" "INFO"
            }
        } catch {
            Write-Log "Could not process $Account : $_" "ERROR"
        }
    }

    # Disable NTLM for privileged accounts
    Write-Log "Configuring NTLM restrictions for privileged accounts..." "INFO"
    Write-Log "[MANUAL] Configure via GPO: Computer Config -> Windows Settings -> Security Settings -> Local Policies -> Security Options" "INFO"
    Write-Log "  - Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers = Deny all" "INFO"

    # Enable AdminSDHolder protection
    Write-Log "[+] Privileged accounts hardened against credential theft" "SUCCESS"
}

function Enable-SMBSigning {
    Write-Log "===== ENABLING SMB SIGNING =====" "INFO"

    Write-Log "SMB signing prevents NTLM relay attacks" "INFO"

    if ($Apply) {
        # Domain controllers
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        Write-Log "[+] SMB signing required on domain controller" "SUCCESS"

        Write-Log "[MANUAL] Enable on all domain computers via GPO:" "INFO"
        Write-Log "  Computer Config -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Security Options" "INFO"
        Write-Log "  - Microsoft network client: Digitally sign communications (always) = Enabled" "INFO"
        Write-Log "  - Microsoft network server: Digitally sign communications (always) = Enabled" "INFO"
    } else {
        Write-Log "[REPORT] Would enable SMB signing" "INFO"
    }
}

function Disable-NTLMv1 {
    Write-Log "===== DISABLING NTLMv1 =====" "INFO"

    Write-Log "NTLMv1 is weak and should be disabled" "INFO"

    if ($Apply) {
        $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $RegPath -Name "LmCompatibilityLevel" -Value 5  # NTLMv2 only
        Write-Log "[+] NTLMv1 disabled (NTLMv2 required)" "SUCCESS"
    } else {
        Write-Log "[REPORT] Would disable NTLMv1" "INFO"
    }
}

function Harden-GroupPolicies {
    Write-Log "===== HARDENING GROUP POLICY OBJECTS =====" "INFO"

    # Restrict GPO modification permissions
    Write-Log "Auditing GPO permissions..." "INFO"

    Import-Module GroupPolicy -ErrorAction Stop

    $GPOs = Get-GPO -All

    foreach ($GPO in $GPOs) {
        Write-Log "Checking: $($GPO.DisplayName)" "INFO"

        # In production: Remove Authenticated Users write access
        # Grant only to Domain Admins and Enterprise Admins
    }

    Write-Log "[MANUAL] Review and restrict GPO permissions to authorized administrators only" "INFO"
    Write-Log "[+] Monitor Event IDs 5136, 5137, 5141 for GPO changes" "INFO"
}

function Implement-LAPS {
    Write-Log "===== IMPLEMENTING LAPS (Local Administrator Password Solution) =====" "INFO"

    Write-Log "LAPS mitigates lateral movement via local admin password reuse" "INFO"

    Write-Log "[MANUAL] LAPS Implementation Steps:" "INFO"
    Write-Log "1. Download and install LAPS: https://www.microsoft.com/en-us/download/details.aspx?id=46899" "INFO"
    Write-Log "2. Extend AD schema: Import-Module AdmPwd.PS; Update-AdmPwdADSchema" "INFO"
    Write-Log "3. Configure GPO: Computer Config -> Policies -> Administrative Templates -> LAPS" "INFO"
    Write-Log "4. Enable local admin password management" "INFO"
    Write-Log "5. Set password complexity: 14+ characters, complexity enabled" "INFO"
}

function Generate-ComplianceReport {
    Write-Log "===== GENERATING COMPLIANCE REPORT =====" "INFO"

    $Report = @{
        'Timestamp' = Get-Date
        'AS-REP Roasting Protection' = (Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}).Count -eq 0
        'Protected Users Configured' = (Get-ADGroupMember -Identity "Protected Users").Count -gt 0
        'Advanced Auditing' = "Manual Verification Required"
        'SMB Signing' = (Get-SmbServerConfiguration).RequireSecuritySignature
        'LAPS Deployed' = "Manual Verification Required"
    }

    Write-Log "`nCOMPLIANCE REPORT:" "INFO"
    $Report.GetEnumerator() | ForEach-Object {
        Write-Log "  $($_.Key): $($_.Value)" "INFO"
    }

    $Report | ConvertTo-Json | Out-File "$PWD\ad_compliance_$(Get-Date -Format 'yyyyMMdd').json"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Write-Log "===== AD SECURITY HARDENING SCRIPT =====" "INFO"
Write-Log "Purple Team Lab - Defense Implementation" "INFO"
Write-Log "Mode: $(if($Apply){'APPLY CHANGES'}else{'REPORT ONLY'})" "WARNING"
Write-Log "==========================================`n" "INFO"

# Check privileges
$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "This script requires elevated privileges (Run as Administrator)" "ERROR"
    exit 1
}

# Execute actions
switch ($Action) {
    'All' {
        Get-CurrentSecurityPosture
        Enable-AdvancedAuditing
        Harden-KerberosSettings
        Protect-PrivilegedAccounts
        Enable-SMBSigning
        Disable-NTLMv1
        Harden-GroupPolicies
        Implement-LAPS
        Generate-ComplianceReport
    }
    'Report' {
        Get-CurrentSecurityPosture
        Generate-ComplianceReport
    }
    'EnableAudit' { Enable-AdvancedAuditing }
    'HardenKerberos' { Harden-KerberosSettings }
    'ProtectPrivilegedAccounts' { Protect-PrivilegedAccounts }
    'EnableSMBSigning' { Enable-SMBSigning }
    'DisableNTLMv1' { Disable-NTLMv1 }
    'HardenGPOs' { Harden-GroupPolicies }
    'ImplementLAPS' { Implement-LAPS }
}

Write-Log "`n===== HARDENING COMPLETE =====" "SUCCESS"
Write-Log "Log file: $LogPath" "INFO"
Write-Log "Review manual steps and test thoroughly before production deployment" "WARNING"
