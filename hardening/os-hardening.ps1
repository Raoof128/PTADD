<#
.SYNOPSIS
    Windows OS Security Hardening Script

.DESCRIPTION
    Implements Windows OS security best practices to defend against
    credential theft and lateral movement attacks.

.NOTES
    Author: Purple Team Lab
    Date: 2024-01-14

.EXAMPLE
    .\os-hardening.ps1 -Apply
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Apply,

    [Parameter(Mandatory=$false)]
    [string]$LogPath = "$PWD\os_hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$Timestamp] $Message"
    Add-Content -Path $LogPath -Value "[$Timestamp] $Message"
}

Write-Log "===== WINDOWS OS HARDENING ====="

# 1. Enable Credential Guard
Write-Log "[*] Enabling Credential Guard..."
if ($Apply) {
    Enable-WindowsOptionalFeature -Online -FeatureName "VirtualMachinePlatform" -NoRestart
    Write-Log "[+] Credential Guard enabled (reboot required)"
}

# 2. Enable LSA Protection
Write-Log "[*] Enabling LSA Protection..."
if ($Apply) {
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -PropertyType DWORD -Force
    Write-Log "[+] LSASS running as Protected Process"
}

# 3. Disable WDigest
Write-Log "[*] Disabling WDigest (plaintext password caching)..."
if ($Apply) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0
    Write-Log "[+] WDigest disabled"
}

# 4. Enable PowerShell Logging
Write-Log "[*] Enabling PowerShell Logging..."
if ($Apply) {
    $PSPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
    New-Item -Path $PSPath -Force | Out-Null
    New-ItemProperty -Path "$PSPath\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWORD -Force
    New-ItemProperty -Path "$PSPath\Transcription" -Name "EnableTranscripting" -Value 1 -PropertyType DWORD -Force
    Write-Log "[+] PowerShell script block logging enabled"
}

# 5. Disable LLMNR
Write-Log "[*] Disabling LLMNR (prevents NTLM relay)..."
if ($Apply) {
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -PropertyType DWORD -Force
    Write-Log "[+] LLMNR disabled"
}

# 6. Configure Windows Firewall
Write-Log "[*] Hardening Windows Firewall..."
if ($Apply) {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Write-Log "[+] Firewall enabled on all profiles"
}

# 7. Disable unnecessary services
Write-Log "[*] Disabling unnecessary services..."
$ServicesToDisable = @('RemoteRegistry', 'WinRM')
foreach ($Service in $ServicesToDisable) {
    if ($Apply) {
        Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $Service -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Log "[+] Disabled service: $Service"
    }
}

Write-Log "`n===== OS HARDENING COMPLETE ====="
Write-Log "Log: $LogPath"
