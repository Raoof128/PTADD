#!/bin/bash
################################################################################
# Purple Team Active Directory Lab - Automated Setup Script
# This script orchestrates the complete lab environment deployment
#
# Author: Purple Team Lab
# Last Updated: 2024-01-14
# Prerequisites:
#   - Docker and Docker Compose installed
#   - 16GB+ RAM available
#   - 50GB+ disk space
#   - Linux host (or WSL2 with Windows containers for full Windows AD)
################################################################################

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="$PROJECT_ROOT/results/setup.log"

################################################################################
# Helper Functions
################################################################################

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[✓]${NC} $*" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[✗]${NC} $*" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG_FILE"
}

banner() {
    echo -e "${BLUE}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   Purple Team Active Directory Attack & Defence Lab              ║
║   Automated Setup & Deployment                                   ║
║                                                                   ║
║   Author: Raouf's Cybersecurity Portfolio                        ║
║   Purpose: Educational Purple Team Training                      ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

check_prerequisites() {
    log "Checking prerequisites..."

    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    success "Docker found: $(docker --version)"

    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    success "Docker Compose found"

    # Check available disk space (at least 50GB)
    AVAILABLE_SPACE=$(df -BG "$PROJECT_ROOT" | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$AVAILABLE_SPACE" -lt 50 ]; then
        warning "Available disk space: ${AVAILABLE_SPACE}GB (Recommended: 50GB+)"
    else
        success "Sufficient disk space: ${AVAILABLE_SPACE}GB"
    fi

    # Check available RAM (at least 8GB)
    TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_RAM" -lt 8 ]; then
        warning "Total RAM: ${TOTAL_RAM}GB (Recommended: 16GB+)"
        warning "Lab may experience performance issues with limited RAM"
    else
        success "Sufficient RAM: ${TOTAL_RAM}GB"
    fi

    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        error "Docker daemon is not running. Please start Docker first."
        exit 1
    fi
    success "Docker daemon is running"
}

create_directories() {
    log "Creating directory structure..."

    mkdir -p "$PROJECT_ROOT/results/attack-evidence"
    mkdir -p "$PROJECT_ROOT/results/detection-screenshots"
    mkdir -p "$PROJECT_ROOT/results/logs"
    mkdir -p "$PROJECT_ROOT/detection-rules/wazuh-rules"
    mkdir -p "$PROJECT_ROOT/lab-setup/configs"

    success "Directory structure created"
}

build_custom_images() {
    log "Building custom Docker images..."

    # Note: Full Windows containers require Windows Server host
    # For Linux hosts, we'll use Samba AD DC as alternative

    warning "Windows Server containers require Windows host or hybrid setup"
    warning "Building Samba AD DC as Linux-based alternative..."

    # Create Samba AD DC Dockerfile
    cat > "$SCRIPT_DIR/Dockerfile.samba-dc" << 'DOCKERFILE'
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install Samba AD DC and dependencies
RUN apt-get update && apt-get install -y \
    samba \
    smbclient \
    winbind \
    krb5-user \
    krb5-config \
    libpam-winbind \
    libnss-winbind \
    ldap-utils \
    dnsutils \
    net-tools \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Configure Samba AD DC
COPY dc-setup.sh /scripts/dc-setup.sh
RUN chmod +x /scripts/dc-setup.sh

EXPOSE 88 135 139 389 445 464 636 3268 3269 53/tcp 53/udp

CMD ["/scripts/dc-setup.sh"]
DOCKERFILE

    # Create DC setup script
    cat > "$SCRIPT_DIR/dc-setup.sh" << 'DCSETUP'
#!/bin/bash
set -e

DOMAIN=${DOMAIN:-PURPLETEAM.LAB}
REALM=${REALM:-PURPLETEAM.LAB}
ADMINPASS=${ADMINPASS:-P@ssw0rd123!}
DNS_FORWARDER=${DNS_FORWARDER:-8.8.8.8}

# Provision Samba AD DC
if [ ! -f /var/lib/samba/.provisioned ]; then
    echo "Provisioning Samba AD DC for domain: $DOMAIN"

    samba-tool domain provision \
        --use-rfc2307 \
        --realm="$REALM" \
        --domain="$(echo $DOMAIN | cut -d. -f1)" \
        --adminpass="$ADMINPASS" \
        --server-role=dc \
        --dns-backend=SAMBA_INTERNAL \
        --option="dns forwarder = $DNS_FORWARDER"

    touch /var/lib/samba/.provisioned

    # Create vulnerable accounts for testing
    if [ -f /config/vulnerable-accounts.json ]; then
        echo "Creating vulnerable user accounts..."
        # Add vulnerable accounts here
    fi
fi

# Start Samba
exec samba -i
DCSETUP

    chmod +x "$SCRIPT_DIR/dc-setup.sh"

    # Build Samba DC image
    if [ -f "$SCRIPT_DIR/Dockerfile.samba-dc" ]; then
        log "Building Samba AD DC image..."
        docker build -f "$SCRIPT_DIR/Dockerfile.samba-dc" -t samba-ad-dc:latest "$SCRIPT_DIR" || {
            warning "Failed to build Samba DC image. Will use pre-built images if available."
        }
    fi

    success "Custom images prepared"
}

create_vulnerable_accounts_config() {
    log "Creating vulnerable accounts configuration..."

    cat > "$SCRIPT_DIR/vulnerable-accounts.json" << 'JSON'
{
  "users": [
    {
      "username": "svc_sqlserver",
      "password": "Winter2023!",
      "description": "SQL Server Service Account",
      "spn": "MSSQLSvc/sql01.purpleteam.lab:1433",
      "groups": ["Domain Users"],
      "kerberosPreauth": true,
      "vulnerability": "Kerberoasting - Weak Password"
    },
    {
      "username": "svc_iis",
      "password": "IIS@Admin123",
      "description": "IIS Service Account",
      "spn": "HTTP/web01.purpleteam.lab",
      "groups": ["Domain Users"],
      "kerberosPreauth": true,
      "vulnerability": "Kerberoasting - Weak Password"
    },
    {
      "username": "asreproast_user",
      "password": "Password123!",
      "description": "User with Kerberos Pre-Auth disabled",
      "spn": null,
      "groups": ["Domain Users"],
      "kerberosPreauth": false,
      "vulnerability": "AS-REP Roasting"
    },
    {
      "username": "admin_backup",
      "password": "BackupAdmin2023!",
      "description": "Backup Administrator",
      "spn": null,
      "groups": ["Domain Admins", "Backup Operators"],
      "kerberosPreauth": true,
      "vulnerability": "Over-privileged Account"
    },
    {
      "username": "helpdesk",
      "password": "HelpDesk!2023",
      "description": "Helpdesk Account with WriteDACL",
      "spn": null,
      "groups": ["Domain Users"],
      "permissions": ["WriteDACL on Domain Admins"],
      "kerberosPreauth": true,
      "vulnerability": "Excessive Permissions - ACL Abuse"
    }
  ],
  "computers": [
    {
      "name": "WS01",
      "description": "Workstation 1 - Vulnerable to lateral movement"
    },
    {
      "name": "WS02",
      "description": "Workstation 2 - Unpatched, local admin password reuse"
    }
  ]
}
JSON

    success "Vulnerable accounts configuration created"
}

deploy_lab() {
    log "Deploying lab environment with Docker Compose..."

    cd "$PROJECT_ROOT"

    # Pull required images
    log "Pulling Docker images..."
    docker-compose pull || warning "Some images may need to be built locally"

    # Start services
    log "Starting services..."
    docker-compose up -d

    # Wait for services to be healthy
    log "Waiting for services to become healthy..."
    sleep 10

    # Check service status
    docker-compose ps

    success "Lab environment deployed"
}

verify_deployment() {
    log "Verifying deployment..."

    # Check if containers are running
    RUNNING_CONTAINERS=$(docker-compose ps -q | wc -l)
    log "Running containers: $RUNNING_CONTAINERS"

    # Test Wazuh connectivity
    if curl -k -s https://localhost:443 > /dev/null; then
        success "Wazuh dashboard is accessible at https://localhost:443"
    else
        warning "Wazuh dashboard may still be initializing"
    fi

    success "Deployment verification complete"
}

display_summary() {
    echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    Deployment Complete!                          ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════╝${NC}\n"

    echo -e "${BLUE}Access Points:${NC}"
    echo -e "  ${YELLOW}Wazuh SIEM:${NC}      https://localhost:443 (admin:SecretPassword)"
    echo -e "  ${YELLOW}Elasticsearch:${NC}   http://localhost:9200"
    echo -e "  ${YELLOW}Domain:${NC}          PURPLETEAM.LAB"
    echo -e "  ${YELLOW}DC IP:${NC}           172.28.0.10"
    echo -e ""

    echo -e "${BLUE}Next Steps:${NC}"
    echo -e "  1. Access attacker workstation:"
    echo -e "     ${GREEN}docker-compose exec attacker bash${NC}"
    echo -e ""
    echo -e "  2. Run first attack (Kerberoasting):"
    echo -e "     ${GREEN}cd /opt/attack-scripts && ./kerberoasting.sh${NC}"
    echo -e ""
    echo -e "  3. Monitor logs in Wazuh dashboard"
    echo -e ""
    echo -e "  4. Review detection rules:"
    echo -e "     ${GREEN}cat detection-rules/sigma-rules/kerberoasting.yml${NC}"
    echo -e ""

    echo -e "${YELLOW}Important Notes:${NC}"
    echo -e "  - This lab contains INTENTIONALLY VULNERABLE configurations"
    echo -e "  - For EDUCATIONAL USE ONLY in isolated environment"
    echo -e "  - DO NOT connect to production networks"
    echo -e "  - All credentials are weak by design for training purposes"
    echo -e ""

    echo -e "${BLUE}Documentation:${NC}"
    echo -e "  - Full documentation: ${GREEN}documentation/ATTACK_PLAYBOOK.md${NC}"
    echo -e "  - Architecture: ${GREEN}documentation/ARCHITECTURE.md${NC}"
    echo -e "  - Detection matrix: ${GREEN}documentation/DETECTION_MATRIX.md${NC}"
    echo -e ""
}

################################################################################
# Main Execution
################################################################################

main() {
    banner

    log "Starting Purple Team AD Lab setup..."
    log "Log file: $LOG_FILE"

    check_prerequisites
    create_directories
    create_vulnerable_accounts_config
    build_custom_images
    deploy_lab
    verify_deployment
    display_summary

    success "Setup complete! Happy purple teaming! 🛡️"
}

# Run main function
main "$@"
