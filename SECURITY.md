# Security Policy

## Purpose and Scope

This Purple Team Active Directory Attack & Defence Lab (PTADD) is an **educational cybersecurity research project** designed for controlled laboratory environments. This document outlines our security policy, vulnerability reporting procedures, and responsible use guidelines.

---

## ⚠️ Important Security Notice

### Educational Use Only

This repository contains:
- **Offensive security tools** designed to exploit Active Directory vulnerabilities
- **Attack simulation scripts** that can compromise systems if misused
- **Detection bypass techniques** for educational purposes

**All tools and techniques in this repository are intended exclusively for:**
- Authorized security testing in controlled lab environments
- Academic research and education
- Professional cybersecurity training
- Security awareness demonstrations

### Legal Compliance

Users must comply with:
- **Australian Cybercrime Act 2001** (Division 477 - Serious computer offences)
- **Computer Misuse Act** in their jurisdiction
- **Authorized testing agreements** and scope limitations
- **Organizational policies** for security research

**Unauthorized access to computer systems is illegal and may result in criminal prosecution.**

---

## 🔒 Supported Versions

We provide security updates for the following versions:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 1.0.x   | ✅ Supported       | Active development |
| < 1.0   | ❌ Not supported   | Legacy |

---

## 🐛 Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in this project, please report it responsibly.

### What to Report

Please report:
- **Security vulnerabilities** in the lab infrastructure
- **Detection bypass techniques** not intended for educational demonstration
- **Unintended exposure** of sensitive data or credentials
- **Dangerous misconfigurations** that could lead to system compromise outside the lab
- **Documentation issues** that could lead to unsafe deployments

### What NOT to Report

The following are **expected behaviors** and not vulnerabilities:
- Attack scripts successfully compromising the lab environment (this is intended)
- Detection rules having false positives (these are documented)
- Docker containers having intentionally weak credentials (lab environment only)
- Lack of security hardening in default deployment (pre-hardening state is intentional)

### Reporting Process

**Option 1: GitHub Security Advisory (Preferred)**
1. Go to the [Security tab](../../security) in this repository
2. Click "Report a vulnerability"
3. Fill out the security advisory form with:
   - Detailed description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested remediation (if available)

**Option 2: Email Report**
- Email: [your-email@domain.com] (replace with your contact)
- Subject: `[PTADD-SECURITY] Vulnerability Report`
- Include:
  - Component affected (infrastructure, attack scripts, detection, documentation)
  - Vulnerability description
  - Reproduction steps
  - Impact assessment (Critical/High/Medium/Low)
  - Your contact information for follow-up

### Response Timeline

| Stage | Timeline | Action |
|-------|----------|--------|
| **Acknowledgment** | Within 48 hours | Confirm receipt of your report |
| **Initial Assessment** | Within 7 days | Evaluate severity and impact |
| **Remediation Plan** | Within 14 days | Develop and test fix |
| **Disclosure** | Within 90 days | Public disclosure (coordinated) |

### Severity Classification

We use the following severity levels:

**Critical**
- Allows arbitrary code execution outside the lab environment
- Unintended exposure of real credentials or keys
- Enables persistent access to host systems

**High**
- Allows privilege escalation beyond intended lab scope
- Enables detection bypass not intended for educational demonstration
- Significant deviation from documented security posture

**Medium**
- Allows unauthorized access within lab environment beyond intended scenarios
- Documentation gaps that could lead to unsafe deployments
- Misconfigurations with moderate impact

**Low**
- Minor documentation errors
- Cosmetic issues with minimal security impact
- Theoretical vulnerabilities with no practical exploitation path

---

## 🛡️ Security Best Practices for Users

### Lab Deployment Security

**1. Network Isolation**
- ✅ Deploy lab in isolated network segment
- ✅ Use separate VLAN or air-gapped network
- ✅ Firewall rules to prevent lateral movement to production
- ❌ Never deploy on production networks
- ❌ Never expose lab directly to the Internet

**2. Credential Management**
- ✅ Change default passwords in `docker-compose.yml`
- ✅ Use password manager for generated credentials
- ✅ Rotate credentials after training exercises
- ❌ Never use real organizational credentials
- ❌ Never reuse lab passwords elsewhere

**3. Data Protection**
- ✅ Encrypt lab data at rest
- ✅ Securely delete attack artifacts after exercises
- ✅ Use `.gitignore` to prevent credential commits
- ❌ Never process real organizational data in the lab
- ❌ Never commit credential files to version control

**4. Tool Usage**
- ✅ Obtain written authorization before testing
- ✅ Define clear scope and boundaries
- ✅ Log all attack activities for auditing
- ❌ Never use tools against unauthorized targets
- ❌ Never modify tools to evade detection in production

**5. Decommissioning**
- ✅ Run `docker-compose down -v` to remove containers and volumes
- ✅ Securely wipe extracted credentials and hashes
- ✅ Remove Kali attacker tools if no longer needed
- ✅ Document lessons learned and detection improvements

### Docker Security

**Hardening the Lab Environment:**

```bash
# 1. Run Docker in rootless mode (recommended)
dockerd-rootless-setuptool.sh install

# 2. Limit container resources
# Add to docker-compose.yml:
deploy:
  resources:
    limits:
      cpus: '2.0'
      memory: 4G

# 3. Use read-only filesystems where possible
read_only: true

# 4. Drop unnecessary capabilities
cap_drop:
  - ALL
cap_add:
  - NET_BIND_SERVICE
```

---

## 🔐 Security Hardening Checklist

Before deploying the lab, review this checklist:

### Infrastructure Security
- [ ] Lab deployed on isolated network
- [ ] Firewall rules prevent external access
- [ ] Docker daemon secured with TLS
- [ ] Host OS patched and hardened
- [ ] Disk encryption enabled
- [ ] Audit logging configured

### Application Security
- [ ] Default credentials changed
- [ ] Attack scripts reviewed for unintended functionality
- [ ] Detection rules tested for false positives
- [ ] Hardening scripts reviewed before application
- [ ] Sensitive data excluded from git commits

### Operational Security
- [ ] Written authorization obtained
- [ ] Scope and boundaries documented
- [ ] Incident response plan defined
- [ ] Backup and recovery tested
- [ ] Decommissioning procedure documented

---

## 📜 Responsible Disclosure Policy

If you publicly disclose a vulnerability **before** we've had reasonable time to remediate:
- We may not acknowledge the disclosure
- We reserve the right to disagree with your assessment
- No bug bounty or rewards are offered for this educational project

**Coordinated Disclosure:**
- We appreciate responsible disclosure with reasonable timelines
- Security researchers will be credited (if desired) in CHANGELOG.md
- We commit to transparent communication throughout the process

---

## 🏆 Security Acknowledgments

We thank the following security researchers for their responsible disclosures:

| Researcher | Date | Severity | Issue |
|------------|------|----------|-------|
| *None yet* | - | - | - |

---

## 📞 Contact

- **Project Maintainer**: [Your Name/GitHub Handle]
- **Security Contact**: [security@yourdomain.com]
- **GitHub Issues**: [General bugs and features](../../issues)
- **GitHub Security**: [Security vulnerabilities](../../security/advisories/new)

---

## 📚 Additional Resources

- [Australian Cyber Security Centre (ACSC)](https://www.cyber.gov.au/)
- [OWASP Vulnerable Application Security](https://owasp.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Critical Security Controls](https://www.cisecurity.org/controls)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

**Document Version**: 1.0
**Last Updated**: 2024-01-14
**Next Review**: 2024-07-14
