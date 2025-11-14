#!/bin/bash
################################################################################
# Kali Attacker Workstation Setup Script
# Installs and configures all offensive security tools for the Purple Team lab
#
# Author: Purple Team Lab
# Date: 2024-01-14
################################################################################

set -euo pipefail

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[*]${NC} $*"
}

success() {
    echo -e "${GREEN}[+]${NC} $*"
}

warning() {
    echo -e "${YELLOW}[!]${NC} $*"
}

log "===== ATTACKER WORKSTATION SETUP ====="
log "Installing offensive security tools..."

# Update package lists
log "Updating package lists..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# Install essential tools
log "Installing essential packages..."
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-dev \
    git \
    curl \
    wget \
    vim \
    smbclient \
    nmap \
    netcat-traditional \
    dnsutils \
    krb5-user \
    ldap-utils \
    bloodhound \
    responder \
    crackmapexec \
    evil-winrm \
    john \
    hashcat \
    hydra \
    metasploit-framework 2>/dev/null || warning "Some packages may not be available"

# Install Python packages
log "Installing Python packages..."
pip3 install --quiet --upgrade pip
pip3 install --quiet \
    impacket \
    ldap3 \
    dnspython \
    pyasn1 \
    pycryptodome \
    requests \
    colorama 2>/dev/null || warning "Some Python packages may have failed"

# Configure Impacket scripts
log "Configuring Impacket..."
if [ -d "/usr/share/doc/python3-impacket/examples" ]; then
    ln -sf /usr/share/doc/python3-impacket/examples/* /usr/local/bin/ 2>/dev/null || true
fi

# Download additional tools
log "Downloading additional tools..."

# BloodHound Ingestor
if [ ! -f "/opt/tools/SharpHound.ps1" ]; then
    mkdir -p /opt/tools
    wget -q https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1 \
        -O /opt/tools/SharpHound.ps1 2>/dev/null || warning "Failed to download SharpHound"
fi

# PowerView
if [ ! -f "/opt/tools/PowerView.ps1" ]; then
    wget -q https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 \
        -O /opt/tools/PowerView.ps1 2>/dev/null || warning "Failed to download PowerView"
fi

# Rubeus (compiled binary)
if [ ! -f "/opt/tools/Rubeus.exe" ]; then
    wget -q https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe \
        -O /opt/tools/Rubeus.exe 2>/dev/null || warning "Failed to download Rubeus"
fi

# Mimikatz
if [ ! -f "/opt/tools/mimikatz.exe" ]; then
    wget -q https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip \
        -O /tmp/mimikatz.zip 2>/dev/null || warning "Failed to download Mimikatz"
    if [ -f "/tmp/mimikatz.zip" ]; then
        unzip -q -o /tmp/mimikatz.zip -d /opt/tools/mimikatz/ 2>/dev/null || true
        rm /tmp/mimikatz.zip
    fi
fi

# Create wordlist directory
mkdir -p /opt/wordlists

# Download common wordlists
if [ ! -f "/opt/wordlists/rockyou.txt" ]; then
    log "Downloading rockyou wordlist..."
    if [ -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
        gunzip -c /usr/share/wordlists/rockyou.txt.gz > /opt/wordlists/rockyou.txt
    else
        wget -q https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt \
            -O /opt/wordlists/rockyou.txt 2>/dev/null || warning "Failed to download rockyou"
    fi
fi

# Create common usernames list
cat > /opt/wordlists/common_users.txt << 'EOF'
administrator
admin
user
test
guest
asreproast_user
svc_sqlserver
svc_iis
helpdesk
backup
service
sql
iis
web
EOF

# Create common passwords list for spraying
cat > /opt/wordlists/common_passwords.txt << 'EOF'
Password123!
Welcome123!
Winter2024!
Summer2024!
Spring2024!
P@ssw0rd
Password1
Admin123!
Company123!
EOF

# Configure Kerberos client
log "Configuring Kerberos client..."
cat > /etc/krb5.conf << 'EOF'
[libdefaults]
    default_realm = PURPLETEAM.LAB
    dns_lookup_realm = false
    dns_lookup_kdc = true

[realms]
    PURPLETEAM.LAB = {
        kdc = 172.28.0.10
        admin_server = 172.28.0.10
    }

[domain_realm]
    .purpleteam.lab = PURPLETEAM.LAB
    purpleteam.lab = PURPLETEAM.LAB
EOF

# Configure DNS resolution
log "Configuring DNS..."
cat >> /etc/hosts << 'EOF'

# Purple Team Lab Domain
172.28.0.10    dc01.purpleteam.lab dc01 purpleteam.lab
172.28.0.20    ws01.purpleteam.lab ws01
172.28.0.21    ws02.purpleteam.lab ws02
EOF

# Set permissions
chmod +x /opt/attack-scripts/*.py 2>/dev/null || true
chmod +x /opt/attack-scripts/*.sh 2>/dev/null || true

# Create attack shortcuts
log "Creating attack shortcuts..."
cat > /usr/local/bin/kerberoast << 'EOF'
#!/bin/bash
python3 /opt/attack-scripts/kerberoasting.py "$@"
EOF

cat > /usr/local/bin/asreproast << 'EOF'
#!/bin/bash
python3 /opt/attack-scripts/asreproast.py "$@"
EOF

cat > /usr/local/bin/dcsync << 'EOF'
#!/bin/bash
python3 /opt/attack-scripts/dcsync.py "$@"
EOF

chmod +x /usr/local/bin/kerberoast
chmod +x /usr/local/bin/asreproast
chmod +x /usr/local/bin/dcsync

# Display tool locations
success "Attacker workstation setup complete!"
echo
log "===== INSTALLED TOOLS ====="
log "Attack Scripts: /opt/attack-scripts/"
log "Additional Tools: /opt/tools/"
log "Wordlists: /opt/wordlists/"
log "Shortcuts: kerberoast, asreproast, dcsync"
echo
log "===== QUICK START ====="
log "1. Test connectivity: ping dc01.purpleteam.lab"
log "2. Run Kerberoasting: kerberoast -d PURPLETEAM.LAB -u lowpriv -p 'Password123!' -dc-ip 172.28.0.10"
log "3. View all scripts: ls -lh /opt/attack-scripts/"
echo
success "Ready for attacks!"
