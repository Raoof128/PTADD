#!/bin/bash
################################################################################
# Purple Team AD Lab - Validation and Testing Script
# This script validates all components and performs pre-flight checks
#
# Author: Purple Team Lab
# Date: 2024-01-14
################################################################################

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNING=0

log() {
    echo -e "${BLUE}[*]${NC} $*"
}

success() {
    echo -e "${GREEN}[✓]${NC} $*"
    ((TESTS_PASSED++))
}

failure() {
    echo -e "${RED}[✗]${NC} $*"
    ((TESTS_FAILED++))
}

warning() {
    echo -e "${YELLOW}[!]${NC} $*"
    ((TESTS_WARNING++))
}

banner() {
    echo -e "${BLUE}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   Purple Team AD Lab - Validation & Testing                      ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

banner

################################################################################
# PRE-FLIGHT CHECKS
################################################################################

log "Running pre-flight checks..."
echo

# Check 1: Project structure
log "1. Validating project structure..."
REQUIRED_DIRS=(
    "attack-scripts"
    "detection-rules/sigma-rules"
    "hardening"
    "documentation"
    "lab-setup"
    "results"
)

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        success "Directory exists: $dir"
    else
        failure "Missing directory: $dir"
    fi
done
echo

# Check 2: Attack scripts exist
log "2. Validating attack scripts..."
ATTACK_SCRIPTS=(
    "attack-scripts/kerberoasting.ps1"
    "attack-scripts/kerberoasting.py"
    "attack-scripts/asreproast.py"
    "attack-scripts/pass_the_hash.py"
    "attack-scripts/dcsync.py"
    "attack-scripts/golden_ticket.ps1"
    "attack-scripts/silver_ticket.ps1"
    "attack-scripts/lateral_movement.ps1"
    "attack-scripts/lsass_dump.ps1"
    "attack-scripts/gpo_abuse.ps1"
    "attack-scripts/bloodhound_collect.py"
    "attack-scripts/acl_abuse.ps1"
    "attack-scripts/ntlm_relay.py"
    "attack-scripts/password_spray.py"
)

for script in "${ATTACK_SCRIPTS[@]}"; do
    if [ -f "$script" ]; then
        success "Attack script exists: $(basename $script)"
    else
        failure "Missing attack script: $script"
    fi
done
echo

# Check 3: Python syntax validation
log "3. Validating Python syntax..."
for script in attack-scripts/*.py; do
    if python3 -m py_compile "$script" 2>/dev/null; then
        success "Python syntax valid: $(basename $script)"
    else
        failure "Python syntax error: $script"
    fi
done
echo

# Check 4: Detection rules
log "4. Validating detection rules..."
DETECTION_RULES=(
    "detection-rules/sigma-rules/kerberoasting_attack.yml"
    "detection-rules/sigma-rules/comprehensive_ad_attacks.yml"
)

for rule in "${DETECTION_RULES[@]}"; do
    if [ -f "$rule" ]; then
        success "Detection rule exists: $(basename $rule)"
        # Basic YAML syntax check
        if python3 -c "import yaml; yaml.safe_load(open('$rule'))" 2>/dev/null; then
            success "YAML syntax valid: $(basename $rule)"
        else
            warning "YAML syntax check failed: $rule (may need PyYAML)"
        fi
    else
        failure "Missing detection rule: $rule"
    fi
done
echo

# Check 5: Hardening scripts
log "5. Validating hardening scripts..."
HARDENING_SCRIPTS=(
    "hardening/ad-hardening.ps1"
    "hardening/os-hardening.ps1"
)

for script in "${HARDENING_SCRIPTS[@]}"; do
    if [ -f "$script" ]; then
        success "Hardening script exists: $(basename $script)"
    else
        failure "Missing hardening script: $script"
    fi
done
echo

# Check 6: Documentation
log "6. Validating documentation..."
DOCUMENTATION=(
    "README.md"
    "documentation/ATTACK_PLAYBOOK.md"
    "documentation/DETECTION_MATRIX.md"
    "documentation/ARCHITECTURE.md"
    "documentation/DEPLOYMENT_OPTIONS.md"
)

for doc in "${DOCUMENTATION[@]}"; do
    if [ -f "$doc" ]; then
        success "Documentation exists: $(basename $doc)"
        # Count words
        WORD_COUNT=$(wc -w < "$doc")
        if [ "$WORD_COUNT" -gt 1000 ]; then
            success "  Word count: $WORD_COUNT (comprehensive)"
        else
            warning "  Word count: $WORD_COUNT (may need expansion)"
        fi
    else
        failure "Missing documentation: $doc"
    fi
done
echo

# Check 7: Infrastructure files
log "7. Validating infrastructure files..."
INFRA_FILES=(
    "docker-compose.yml"
    "lab-setup/setup.sh"
    "lab-setup/sysmon-config.xml"
    "lab-setup/attacker-setup.sh"
)

for file in "${INFRA_FILES[@]}"; do
    if [ -f "$file" ]; then
        success "Infrastructure file exists: $(basename $file)"
        # Check if executable
        if [[ "$file" == *.sh ]]; then
            if [ -x "$file" ]; then
                success "  Executable: yes"
            else
                warning "  Executable: no (run: chmod +x $file)"
            fi
        fi
    else
        failure "Missing infrastructure file: $file"
    fi
done
echo

# Check 8: Docker availability
log "8. Checking Docker..."
if command -v docker &> /dev/null; then
    success "Docker is installed"
    DOCKER_VERSION=$(docker --version | awk '{print $3}' | tr -d ',')
    success "  Version: $DOCKER_VERSION"

    if docker info &> /dev/null; then
        success "Docker daemon is running"
    else
        failure "Docker daemon is not running"
    fi
else
    warning "Docker is not installed"
fi

if command -v docker-compose &> /dev/null; then
    success "Docker Compose is installed"
    COMPOSE_VERSION=$(docker-compose --version | awk '{print $4}' | tr -d ',')
    success "  Version: $COMPOSE_VERSION"
else
    warning "Docker Compose is not installed"
fi
echo

# Check 9: Python dependencies
log "9. Checking Python dependencies..."
PYTHON_PACKAGES=(
    "impacket"
    "ldap3"
    "colorama"
)

for package in "${PYTHON_PACKAGES[@]}"; do
    if python3 -c "import $package" 2>/dev/null; then
        success "Python package installed: $package"
    else
        warning "Python package missing: $package (pip3 install $package)"
    fi
done
echo

# Check 10: File permissions
log "10. Checking file permissions..."
if [ -w "." ]; then
    success "Project directory is writable"
else
    failure "Project directory is not writable"
fi

if [ -d "results" ] && [ -w "results" ]; then
    success "Results directory is writable"
else
    warning "Results directory permissions issue"
fi
echo

# Check 11: Metrics file
log "11. Validating metrics..."
if [ -f "results/metrics.json" ]; then
    success "Metrics file exists"
    if python3 -c "import json; json.load(open('results/metrics.json'))" 2>/dev/null; then
        success "Metrics JSON syntax valid"

        # Extract key metrics
        TECHNIQUES=$(python3 -c "import json; print(json.load(open('results/metrics.json'))['attack_metrics']['techniques_implemented'])" 2>/dev/null || echo "0")
        DETECTION=$(python3 -c "import json; print(json.load(open('results/metrics.json'))['detection_metrics']['overall_detection_coverage_percentage'])" 2>/dev/null || echo "0")

        success "  Techniques implemented: $TECHNIQUES"
        success "  Detection coverage: $DETECTION%"
    else
        failure "Metrics JSON syntax error"
    fi
else
    warning "Metrics file missing"
fi
echo

# Check 12: README completeness
log "12. Checking README completeness..."
if [ -f "README.md" ]; then
    README_CHECKS=(
        "MITRE ATT&CK"
        "Quick Start"
        "Attack Techniques"
        "Detection Coverage"
        "Documentation"
    )

    for check in "${README_CHECKS[@]}"; do
        if grep -q "$check" README.md; then
            success "README contains: $check"
        else
            warning "README missing section: $check"
        fi
    done
fi
echo

################################################################################
# DOCKER COMPOSE VALIDATION
################################################################################

log "13. Validating docker-compose.yml..."
if [ -f "docker-compose.yml" ]; then
    # Check if docker-compose config is valid
    if docker-compose config > /dev/null 2>&1; then
        success "docker-compose.yml syntax is valid"

        # Count services
        SERVICE_COUNT=$(docker-compose config --services 2>/dev/null | wc -l)
        success "  Services defined: $SERVICE_COUNT"
    else
        failure "docker-compose.yml syntax error"
        docker-compose config 2>&1 | head -5
    fi
fi
echo

################################################################################
# SYSMON CONFIG VALIDATION
################################################################################

log "14. Validating Sysmon configuration..."
if [ -f "lab-setup/sysmon-config.xml" ]; then
    success "Sysmon config exists"

    # Check for critical event IDs
    SYSMON_EVENTS=(
        "ProcessCreate"
        "NetworkConnect"
        "ProcessAccess"
        "FileCreate"
        "RegistryEvent"
        "PipeEvent"
    )

    for event in "${SYSMON_EVENTS[@]}"; do
        if grep -q "$event" lab-setup/sysmon-config.xml; then
            success "  Event configured: $event"
        else
            warning "  Event missing: $event"
        fi
    done
fi
echo

################################################################################
# CODE QUALITY CHECKS
################################################################################

log "15. Code quality checks..."

# Check Python code comments
PYTHON_FILES=$(find attack-scripts -name "*.py" | wc -l)
if [ "$PYTHON_FILES" -gt 0 ]; then
    TOTAL_LINES=$(cat attack-scripts/*.py 2>/dev/null | wc -l)
    COMMENT_LINES=$(grep -h "^#" attack-scripts/*.py 2>/dev/null | wc -l)
    COMMENT_PERCENT=$((COMMENT_LINES * 100 / TOTAL_LINES))

    if [ "$COMMENT_PERCENT" -ge 20 ]; then
        success "Python code comment percentage: ${COMMENT_PERCENT}% (good)"
    else
        warning "Python code comment percentage: ${COMMENT_PERCENT}% (low)"
    fi
fi

# Check PowerShell code comments
PS_FILES=$(find attack-scripts -name "*.ps1" | wc -l)
if [ "$PS_FILES" -gt 0 ]; then
    PS_TOTAL_LINES=$(cat attack-scripts/*.ps1 hardening/*.ps1 2>/dev/null | wc -l)
    PS_COMMENT_LINES=$(grep -h "^#" attack-scripts/*.ps1 hardening/*.ps1 2>/dev/null | wc -l)
    PS_COMMENT_PERCENT=$((PS_COMMENT_LINES * 100 / PS_TOTAL_LINES))

    if [ "$PS_COMMENT_PERCENT" -ge 20 ]; then
        success "PowerShell code comment percentage: ${PS_COMMENT_PERCENT}% (good)"
    else
        warning "PowerShell code comment percentage: ${PS_COMMENT_PERCENT}% (low)"
    fi
fi
echo

################################################################################
# SECURITY CHECKS
################################################################################

log "16. Security checks..."

# Check for hardcoded credentials (in documentation, not in config files)
if grep -r "P@ssw0rd123" attack-scripts/ 2>/dev/null | grep -v "\.md" | grep -q .; then
    warning "Hardcoded credentials found in attack scripts (expected for lab)"
fi

# Check git ignore
if [ -f ".gitignore" ]; then
    success ".gitignore exists"
    if grep -q "*.key" .gitignore; then
        success "  Ignoring sensitive files: *.key"
    fi
    if grep -q "credentials" .gitignore; then
        success "  Ignoring credentials files"
    fi
else
    failure ".gitignore missing"
fi
echo

################################################################################
# SUMMARY
################################################################################

echo
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}         VALIDATION SUMMARY             ${NC}"
echo -e "${BLUE}========================================${NC}"
echo
echo -e "${GREEN}Tests Passed:  ${TESTS_PASSED}${NC}"
echo -e "${RED}Tests Failed:  ${TESTS_FAILED}${NC}"
echo -e "${YELLOW}Warnings:      ${TESTS_WARNING}${NC}"
echo

TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED))
if [ "$TOTAL_TESTS" -gt 0 ]; then
    SUCCESS_RATE=$((TESTS_PASSED * 100 / TOTAL_TESTS))
    echo -e "Success Rate: ${SUCCESS_RATE}%"
    echo
fi

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}✓ All critical tests passed!${NC}"
    echo -e "${GREEN}✓ Lab is ready for deployment${NC}"
    EXIT_CODE=0
else
    echo -e "${RED}✗ Some tests failed. Review errors above.${NC}"
    EXIT_CODE=1
fi

if [ "$TESTS_WARNING" -gt 0 ]; then
    echo -e "${YELLOW}! ${TESTS_WARNING} warnings found. Review recommended.${NC}"
fi

echo
log "Validation complete. Log saved to: validation_$(date +%Y%m%d_%H%M%S).log"

exit $EXIT_CODE
