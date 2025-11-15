# Contributing to Purple Team Active Directory Attack & Defence Lab

Thank you for your interest in contributing to PTADD! This document provides guidelines for contributing to this educational cybersecurity project.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Contribution Workflow](#contribution-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation Standards](#documentation-standards)
- [Security Considerations](#security-considerations)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Pull Request Process](#pull-request-process)

---

## 📜 Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

**Key Principles:**
- Be respectful and inclusive
- Focus on constructive feedback
- Prioritize educational value
- Maintain security and ethical standards

---

## 🤝 How Can I Contribute?

### Reporting Bugs

**Before submitting a bug report:**
- Check existing [Issues](../../issues) to avoid duplicates
- Determine if it's a bug or intended educational behavior
- Collect relevant logs and error messages

**Bug Report Template:**
```markdown
**Description:**
Brief description of the bug

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Docker Version: [e.g., 24.0.7]
- Component: [e.g., Wazuh, DC, Attacker]

**Steps to Reproduce:**
1. Deploy lab with...
2. Execute attack...
3. Observe error...

**Expected Behavior:**
What should happen

**Actual Behavior:**
What actually happens

**Logs:**
```
Paste relevant logs here
```

**Additional Context:**
Screenshots, configuration changes, etc.
```

### Suggesting Enhancements

We welcome suggestions for:
- **New attack techniques** (MITRE ATT&CK aligned)
- **Detection rules** (Sigma format preferred)
- **Hardening improvements** (PowerShell/Bash scripts)
- **Documentation enhancements**
- **Deployment options** (new platforms, cloud providers)
- **Performance optimizations**

**Enhancement Request Template:**
```markdown
**Feature Description:**
What feature would you like to see?

**Use Case:**
How would this benefit the project?

**MITRE ATT&CK Mapping:**
[If applicable] Technique ID and name

**Implementation Approach:**
Your proposed approach (optional)

**Alternatives Considered:**
Other options you've thought about
```

### Contributing Code

We accept contributions for:
- **Attack Scripts** (PowerShell, Python)
- **Detection Rules** (Sigma YAML)
- **Hardening Scripts** (PowerShell, Bash)
- **Infrastructure Improvements** (Docker, automation)
- **Documentation** (Markdown)
- **Testing** (Validation scripts, unit tests)

---

## 🔧 Development Setup

### Prerequisites

**Required:**
- Docker 24.0+ and Docker Compose 2.0+
- Python 3.9+
- PowerShell Core 7.0+ (for testing PS scripts)
- Git 2.30+

**Recommended:**
- Visual Studio Code with extensions:
  - Python (ms-python.python)
  - PowerShell (ms-vscode.powershell)
  - YAML (redhat.vscode-yaml)
  - Docker (ms-azuretools.vscode-docker)
  - Sigma (humpalum.sigma)

### Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/PTADD.git
cd PTADD

# Add upstream remote
git remote add upstream https://github.com/ORIGINAL_OWNER/PTADD.git

# Verify remotes
git remote -v
```

### Install Development Dependencies

```bash
# Python dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If available

# Pre-commit hooks (recommended)
pip install pre-commit
pre-commit install
```

### Validate Your Setup

```bash
# Run validation script
chmod +x lab-setup/validate-lab.sh
./lab-setup/validate-lab.sh

# Should show 0 errors for structure, syntax, and quality checks
```

---

## 🔄 Contribution Workflow

### 1. Create a Feature Branch

```bash
# Update your fork
git checkout main
git fetch upstream
git merge upstream/main

# Create feature branch (use descriptive names)
git checkout -b feature/kerberos-delegation-attack
git checkout -b fix/wazuh-indexer-config
git checkout -b docs/improve-testing-guide
```

**Branch Naming Convention:**
- `feature/` - New features or attack techniques
- `fix/` - Bug fixes
- `docs/` - Documentation improvements
- `refactor/` - Code refactoring without functional changes
- `test/` - Testing improvements

### 2. Make Your Changes

- Follow [Coding Standards](#coding-standards)
- Add/update documentation
- Add/update tests
- Validate changes locally

### 3. Test Your Changes

```bash
# Python syntax validation
python3 -m py_compile attack-scripts/your_script.py

# PowerShell syntax validation
pwsh -Command "Get-Content attack-scripts/your_script.ps1 | Out-Null"

# YAML validation (detection rules)
python3 -c "import yaml; yaml.safe_load(open('detection-rules/sigma-rules/your_rule.yml'))"

# Run full validation
./lab-setup/validate-lab.sh

# Deploy lab and test manually
docker-compose up -d
# Execute your attack/feature
# Verify detection works
docker-compose down -v
```

### 4. Commit Your Changes

Follow [Commit Message Guidelines](#commit-message-guidelines)

```bash
git add .
git commit -m "feat: Add Kerberos delegation attack (T1558.005)"
```

### 5. Push and Create Pull Request

```bash
git push origin feature/kerberos-delegation-attack
```

Then create a Pull Request on GitHub following the [PR template](#pull-request-process).

---

## 💻 Coding Standards

### General Principles

- **Clarity over cleverness** - Code should be readable and educational
- **Comments are mandatory** - Explain *why*, not just *what*
- **Error handling** - All scripts must handle errors gracefully
- **Logging** - Attack scripts should log activities with timestamps
- **Modularity** - Break complex logic into functions

### Python Standards

**Style Guide:** PEP 8

```python
# Good example
import logging
from typing import List, Dict, Optional
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP

class KerberoastingAttack:
    """
    Implements Kerberoasting attack (MITRE ATT&CK T1558.003).

    This attack requests TGS tickets for service accounts and extracts
    the encrypted portion for offline password cracking.

    Attributes:
        domain (str): Target Active Directory domain
        dc_ip (str): Domain Controller IP address
        username (str): Authenticated user for ticket requests
        password (str): User password for Kerberos authentication
    """

    def __init__(self, domain: str, dc_ip: str, username: str, password: str):
        """Initialize Kerberoasting attack with target parameters."""
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        self.logger = self._setup_logging()

    def _setup_logging(self) -> logging.Logger:
        """Configure logging with timestamp and severity levels."""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler(f'logs/kerberoast_{datetime.now():%Y%m%d_%H%M%S}.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def enumerate_spn_accounts(self) -> List[Dict[str, str]]:
        """
        Enumerate user accounts with Service Principal Names (SPNs).

        Returns:
            List of dictionaries containing account details (username, SPN, etc.)

        Raises:
            LDAPException: If LDAP query fails
            AuthenticationException: If credentials are invalid
        """
        try:
            # Implementation...
            self.logger.info(f"Found {len(spn_accounts)} SPN accounts")
            return spn_accounts
        except Exception as e:
            self.logger.error(f"SPN enumeration failed: {e}")
            raise
```

**Key Requirements:**
- Type hints for function parameters and returns
- Docstrings for all classes and functions (Google/NumPy style)
- Exception handling with specific error types
- Logging for attack activities
- Constants in UPPER_CASE
- Private methods prefixed with `_`

### PowerShell Standards

**Style Guide:** PowerShell Best Practices

```powershell
<#
.SYNOPSIS
    Implements Kerberoasting attack against Active Directory (T1558.003).

.DESCRIPTION
    This script requests Kerberos TGS tickets for service accounts with SPNs,
    exports them in Hashcat-compatible format, and optionally attempts offline cracking.

    Educational use only - demonstrates AD attack technique for detection development.

.PARAMETER Domain
    Target Active Directory domain (e.g., PURPLETEAM.LAB)

.PARAMETER OutputPath
    Directory to save exported tickets (default: ./loot)

.PARAMETER CrackPasswords
    Switch to attempt offline password cracking with hashcat

.EXAMPLE
    .\kerberoasting.ps1 -Domain PURPLETEAM.LAB -OutputPath C:\Temp\tickets

.NOTES
    Author: Your Name
    MITRE ATT&CK: T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
    Requires: PowerView or ActiveDirectory module
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\loot",

    [Parameter(Mandatory=$false)]
    [switch]$CrackPasswords
)

# Strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-AttackLog {
    <#
    .SYNOPSIS
        Writes timestamped log messages to file and console.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Color-coded console output
    switch ($Level) {
        'ERROR'   { Write-Host $logMessage -ForegroundColor Red }
        'WARNING' { Write-Host $logMessage -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $logMessage -ForegroundColor Green }
        default   { Write-Host $logMessage }
    }

    # Log to file
    Add-Content -Path "$OutputPath\kerberoast.log" -Value $logMessage
}

# Main execution with try-catch
try {
    Write-AttackLog "Starting Kerberoasting attack against $Domain" -Level INFO

    # Create output directory if not exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-AttackLog "Created output directory: $OutputPath" -Level INFO
    }

    # Implementation...

} catch {
    Write-AttackLog "Attack failed: $($_.Exception.Message)" -Level ERROR
    exit 1
}
```

**Key Requirements:**
- Comment-based help for all scripts and functions
- Parameter validation
- Strict mode enabled
- Try-catch error handling
- Approved verbs for function names (Get-, Set-, New-, etc.)
- Output logging with timestamps

### Sigma Detection Rule Standards

**Format:** Sigma YAML specification

```yaml
title: Kerberoasting Attack Detection - Service Ticket Request
id: a1b2c3d4-e5f6-4789-a012-3456789abcde  # Generate unique UUID
status: test  # test | stable | experimental | deprecated
description: |
  Detects potential Kerberoasting attacks by identifying service ticket (TGS) requests
  for service accounts using RC4 encryption, which is often targeted for offline cracking.

  Kerberoasting (T1558.003) allows attackers to request TGS tickets and crack service
  account passwords offline without triggering account lockouts.

references:
  - https://attack.mitre.org/techniques/T1558/003/
  - https://www.crowdstrike.com/blog/kerberoasting-attacks/

author: Your Name
date: 2024/01/14
modified: 2024/01/14
tags:
  - attack.credential_access
  - attack.t1558.003
  - attack.kerberos

logsource:
  product: windows
  service: security

detection:
  selection_base:
    EventID: 4769
    Status: '0x0'
    TicketEncryptionType: '0x17'  # RC4-HMAC

  filter_machine_accounts:
    TargetUserName|endswith: '$'

  filter_common_services:
    ServiceName|endswith:
      - 'krbtgt'
      - 'kadmin/changepw'

  condition: selection_base and not filter_machine_accounts and not filter_common_services

falsepositives:
  - Legacy applications requiring RC4 encryption
  - Service accounts accessed by legitimate administrators
  - Scheduled tasks using service account credentials

level: high  # informational | low | medium | high | critical

fields:
  - TargetUserName
  - ServiceName
  - IpAddress
  - TicketEncryptionType
```

**Key Requirements:**
- Unique UUID for each rule (use `uuidgen` or online generator)
- Comprehensive description with attack context
- MITRE ATT&CK tags
- False positive documentation
- Appropriate severity level
- Field extraction for investigation

---

## 🧪 Testing Guidelines

### Attack Script Testing

**Test Checklist:**
- [ ] Script executes without syntax errors
- [ ] Handles invalid credentials gracefully
- [ ] Handles network connectivity issues
- [ ] Logs activities to file
- [ ] Creates output in expected format
- [ ] Cleans up temporary files
- [ ] Detection rules trigger as expected
- [ ] Documented in ATTACK_PLAYBOOK.md

**Testing Procedure:**

```bash
# 1. Deploy clean lab
docker-compose up -d
sleep 60  # Allow services to initialize

# 2. Execute attack script
docker exec ptadd-kali python3 /opt/attack-scripts/your_attack.py \
  --domain PURPLETEAM.LAB \
  --dc-ip 172.28.0.10 \
  --username testuser \
  --password 'P@ssw0rd123!'

# 3. Verify detection
# Check Wazuh dashboard for alerts (http://localhost:5601)

# 4. Verify logging
docker exec ptadd-kali cat /opt/attack-scripts/logs/your_attack_*.log

# 5. Clean up
docker-compose down -v
```

### Detection Rule Testing

**Test Checklist:**
- [ ] YAML syntax is valid
- [ ] Rule triggers on attack execution
- [ ] False positive rate is acceptable (<1%)
- [ ] Detection time is acceptable (<30 seconds)
- [ ] Documented in DETECTION_MATRIX.md

**Testing Procedure:**

```bash
# 1. Validate Sigma syntax
sigma check detection-rules/sigma-rules/your_rule.yml

# 2. Convert to Wazuh format
sigma convert -t wazuh detection-rules/sigma-rules/your_rule.yml

# 3. Deploy and test
# - Add rule to Wazuh
# - Execute corresponding attack
# - Verify alert generation
# - Check for false positives over 24 hours

# 4. Document results in DETECTION_MATRIX.md
```

---

## 📚 Documentation Standards

### Code Documentation

- **Every file** must have a header comment explaining purpose and MITRE mapping
- **Every function** must have docstring/comment-based help
- **Complex logic** must have inline comments explaining the "why"
- **External references** for techniques (MITRE ATT&CK, blog posts)

### Markdown Documentation

**Standards:**
- Use descriptive headings (H2 ## for main sections)
- Include table of contents for documents >500 words
- Code blocks must specify language for syntax highlighting
- Screenshots/diagrams where appropriate
- Cross-reference other documentation files

**File Locations:**
- `README.md` - Project overview and quick start
- `ATTACK_PLAYBOOK.md` - Detailed attack execution guides
- `DETECTION_MATRIX.md` - Detection coverage and analysis
- `ARCHITECTURE.md` - Technical architecture details
- `DEPLOYMENT_OPTIONS.md` - Platform-specific deployment guides
- `TESTING_GUIDE.md` - Testing procedures and validation

---

## 🔒 Security Considerations

### Before Committing

**Critical Checks:**
- [ ] No real credentials committed (even in comments)
- [ ] No API keys or tokens
- [ ] No SSH private keys
- [ ] No production IP addresses
- [ ] `.gitignore` updated for new sensitive file types
- [ ] Attack output files excluded (*.kirbi, *.dmp, hashes.txt)

### Tool Safety

When adding new attack tools:
- [ ] Tool source is reputable (official GitHub, etc.)
- [ ] Tool has been reviewed for backdoors/malware
- [ ] Tool is widely used in security community
- [ ] Tool behavior is documented and understood
- [ ] Tool is isolated to lab environment

---

## 📝 Commit Message Guidelines

We follow **Conventional Commits** specification:

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Type

- `feat` - New feature (attack, detection, hardening)
- `fix` - Bug fix
- `docs` - Documentation changes
- `style` - Code formatting (no functional changes)
- `refactor` - Code refactoring
- `test` - Adding or updating tests
- `chore` - Maintenance tasks (dependencies, config)

### Scope (Optional)

- `attack` - Attack scripts
- `detection` - Detection rules
- `hardening` - Hardening scripts
- `infra` - Infrastructure (Docker, setup)
- `docs` - Documentation

### Examples

```bash
# Good examples
git commit -m "feat(attack): Add Kerberos delegation attack (T1558.005)"
git commit -m "fix(detection): Reduce false positives in DCSync rule"
git commit -m "docs: Update TESTING_GUIDE with Cloud deployment testing"
git commit -m "refactor(attack): Improve error handling in kerberoasting.py"

# Bad examples
git commit -m "fixed stuff"
git commit -m "updated files"
git commit -m "WIP"
```

### Body (Optional but Recommended)

Explain **why** the change was made, not **what** changed (the diff shows that).

```
feat(attack): Add Kerberos delegation attack (T1558.005)

Implements unconstrained and constrained Kerberos delegation attacks.
This technique is commonly used for lateral movement and privilege escalation
in Active Directory environments.

Includes both PowerShell and Python implementations, plus corresponding
Sigma detection rules for Event ID 4769 with delegation flags.
```

### Footer (Optional)

Reference issues or breaking changes:

```
Closes #42
Fixes #37

BREAKING CHANGE: Detection rule format changed to Sigma 2.0 specification.
Requires updating Wazuh converter script.
```

---

## 🔀 Pull Request Process

### Before Submitting

1. **Update documentation** - Ensure README.md, ATTACK_PLAYBOOK.md reflect your changes
2. **Run validation** - `./lab-setup/validate-lab.sh` must pass
3. **Test thoroughly** - Deploy lab and manually test your changes
4. **Update CHANGELOG.md** - Add entry for your changes
5. **Rebase on main** - Ensure clean commit history

```bash
git fetch upstream
git rebase upstream/main
```

### PR Title Format

Use conventional commit format:

```
feat(attack): Add Kerberos delegation attack (T1558.005)
fix(detection): Reduce DCSync false positives
docs: Improve attack playbook clarity
```

### PR Description Template

```markdown
## Description
Brief description of changes and motivation.

## Type of Change
- [ ] New attack technique
- [ ] Detection rule improvement
- [ ] Hardening enhancement
- [ ] Documentation update
- [ ] Bug fix
- [ ] Infrastructure improvement

## MITRE ATT&CK Mapping
**Technique ID**: T1558.005
**Technique Name**: Kerberos Delegation Attacks
**Tactic**: Credential Access, Lateral Movement

## Changes Made
- Added `kerberos_delegation.py` attack script (Python)
- Added `kerberos_delegation.ps1` attack script (PowerShell)
- Added 3 Sigma detection rules for delegation abuse
- Updated ATTACK_PLAYBOOK.md with delegation walkthrough
- Updated DETECTION_MATRIX.md with new coverage metrics

## Testing Performed
- [x] Python syntax validation passed
- [x] PowerShell syntax validation passed
- [x] Lab deployment successful
- [x] Attack execution successful (unconstrained delegation)
- [x] Attack execution successful (constrained delegation)
- [x] Detection rules triggered correctly
- [x] False positive testing (24-hour baseline)
- [x] Documentation reviewed for accuracy

## Detection Coverage
- **Primary Detection**: Event ID 4769 with delegation tickets
- **Secondary Detection**: Event ID 4624 from service accounts
- **Coverage Rate**: 94%
- **False Positive Rate**: 0.8%
- **Mean Time to Detection**: 6.2 seconds

## Checklist
- [ ] Code follows project coding standards
- [ ] Comments and documentation added/updated
- [ ] No sensitive data committed
- [ ] Validation script passes
- [ ] CHANGELOG.md updated
- [ ] Breaking changes documented (if applicable)

## Screenshots
(Optional) Include screenshots of detection alerts, attack output, etc.

## Additional Context
Any additional information reviewers should know.
```

### Review Process

**What Reviewers Check:**
- Code quality and adherence to standards
- Security implications
- Educational value
- Documentation completeness
- Testing thoroughness
- False positive analysis

**Timeline:**
- Initial review within 7 days
- Feedback and revision cycles as needed
- Merge when approved by maintainer(s)

### After Merge

- Your changes will be included in the next release
- You'll be credited in CHANGELOG.md
- Consider announcing new features in Discussions

---

## 🏆 Recognition

Contributors will be recognized in:
- **README.md** - Contributors section
- **CHANGELOG.md** - Version release notes
- **Git history** - Your commits and authorship

---

## 📞 Questions or Need Help?

- **GitHub Discussions**: For general questions and ideas
- **GitHub Issues**: For bug reports and feature requests
- **Security Issues**: See [SECURITY.md](SECURITY.md)

---

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to PTADD and advancing cybersecurity education!**
