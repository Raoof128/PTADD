# Deployment Options Guide

**Purple Team AD Lab - Multiple Deployment Methods**

This guide provides detailed instructions for deploying the Purple Team AD Lab in various environments.

---

## Table of Contents

1. [Docker Compose (Recommended for Linux)](#option-1-docker-compose)
2. [VirtualBox (Full Windows AD)](#option-2-virtualbox)
3. [Hyper-V (Windows Host)](#option-3-hyper-v)
4. [Cloud Deployment (AWS/Azure)](#option-4-cloud-deployment)
5. [Hybrid Approach](#option-5-hybrid-approach)
6. [Troubleshooting](#troubleshooting)

---

## Option 1: Docker Compose

**Best For**: Linux hosts, quick deployment, reproducibility

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y docker.io docker-compose git

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

### Deployment

```bash
# Clone repository
git clone https://github.com/yourusername/PTADD.git
cd PTADD

# Run setup
chmod +x lab-setup/setup.sh
./lab-setup/setup.sh

# Start lab
docker-compose up -d

# Verify
docker-compose ps
docker-compose logs -f wazuh-manager
```

### Accessing Components

| Component | Access Method |
|-----------|--------------|
| **Wazuh Dashboard** | https://localhost:443 (admin:SecretPassword) |
| **Attacker Shell** | `docker-compose exec attacker bash` |
| **DC Shell** | `docker-compose exec domain-controller bash` |
| **Workstation** | `docker-compose exec workstation1 cmd` (if Windows containers) |

### Resource Requirements

- **Minimum**: 8GB RAM, 4 CPU cores, 30GB storage
- **Recommended**: 16GB RAM, 8 CPU cores, 50GB storage

### Limitations

⚠️ **Windows Container Limitation**: Full Windows Server Active Directory requires Windows host or WSL2 with Windows containers enabled.

**Solution**: Use Samba AD DC (Linux-based AD alternative) included in docker-compose.yml

---

## Option 2: VirtualBox (Full Windows AD)

**Best For**: Full Windows Active Directory functionality, learning environments

### Prerequisites

- VirtualBox 6.1+ installed
- Windows Server 2019/2022 ISO
- Windows 10 Enterprise ISO
- Kali Linux ISO
- Ubuntu Server ISO (for SIEM)

### VM Configuration

#### Domain Controller (DC01)

```
Name: DC01
OS: Windows Server 2019
vCPU: 2 cores
RAM: 4 GB
Disk: 60 GB (dynamic)
Network: Internal Network (purpleteam_net)
```

**Installation Steps**:

1. Install Windows Server 2019
2. Set static IP: 172.28.0.10/16, Gateway: 172.28.0.1, DNS: 127.0.0.1
3. Install AD DS role:

```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to DC
Install-ADDSForest `
    -DomainName "purpleteam.lab" `
    -DomainNetbiosName "PURPLETEAM" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
    -Force
```

4. Install Sysmon:

```powershell
# Download Sysmon
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Sysmon.zip
Expand-Archive C:\Sysmon.zip -DestinationPath C:\Sysmon

# Copy config from lab-setup/sysmon-config.xml to C:\sysmon-config.xml

# Install Sysmon
C:\Sysmon\Sysmon64.exe -accepteula -i C:\sysmon-config.xml
```

5. Create vulnerable users:

```powershell
# Service accounts with SPNs
New-ADUser -Name "svc_sqlserver" -AccountPassword (ConvertTo-SecureString "Winter2023!" -AsPlainText -Force) -Enabled $true
Set-ADUser -Identity "svc_sqlserver" -ServicePrincipalNames @{Add="MSSQLSvc/sql01.purpleteam.lab:1433"}

New-ADUser -Name "svc_iis" -AccountPassword (ConvertTo-SecureString "IIS@Admin123" -AsPlainText -Force) -Enabled $true
Set-ADUser -Identity "svc_iis" -ServicePrincipalNames @{Add="HTTP/web01.purpleteam.lab"}

# AS-REP Roastable user
New-ADUser -Name "asreproast_user" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
Set-ADAccountControl -Identity "asreproast_user" -DoesNotRequirePreAuth $true

# Privileged user
New-ADUser -Name "admin_backup" -AccountPassword (ConvertTo-SecureString "BackupAdmin2023!" -AsPlainText -Force) -Enabled $true
Add-ADGroupMember -Identity "Domain Admins" -Members "admin_backup"
Add-ADGroupMember -Identity "Backup Operators" -Members "admin_backup"
```

#### Workstation 1 (WS01)

```
Name: WS01
OS: Windows 10 Enterprise
vCPU: 2 cores
RAM: 4 GB
Disk: 60 GB
Network: Internal Network (purpleteam_net)
```

**Installation**:

1. Install Windows 10
2. Set static IP: 172.28.0.20/16, Gateway: 172.28.0.1, DNS: 172.28.0.10
3. Join domain:

```powershell
Add-Computer -DomainName "purpleteam.lab" -Credential (Get-Credential) -Restart
```

4. Install Sysmon (same as DC)
5. Disable Windows Defender (for attack testing):

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force
```

#### Workstation 2 (WS02)

Same as WS01, but with IP 172.28.0.21

#### Attacker (Kali Linux)

```
Name: Kali-Attacker
OS: Kali Linux 2023.4
vCPU: 2 cores
RAM: 4 GB
Disk: 40 GB
Network: Internal Network (purpleteam_net)
```

**Installation**:

1. Install Kali Linux
2. Set static IP: 172.28.0.50/16, Gateway: 172.28.0.1, DNS: 172.28.0.10
3. Run attacker setup:

```bash
sudo bash /path/to/lab-setup/attacker-setup.sh
```

#### SIEM (Ubuntu + Wazuh)

```
Name: Wazuh-SIEM
OS: Ubuntu 22.04 Server
vCPU: 4 cores
RAM: 8 GB
Disk: 100 GB
Network: Internal Network (purpleteam_net) + NAT (for updates)
```

**Installation**:

1. Install Ubuntu 22.04 Server
2. Set static IP: 172.28.0.100/16
3. Install Wazuh:

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y curl apt-transport-https lsb-release gnupg

# Install Wazuh
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a

# Save credentials displayed after installation
```

4. Configure Wazuh agents on DC and Workstations

---

## Option 3: Hyper-V (Windows Host)

**Best For**: Windows 10/11 Pro users

### Enable Hyper-V

```powershell
# Run as Administrator
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```

### Create Virtual Switch

```powershell
New-VMSwitch -Name "PurpleTeam-Internal" -SwitchType Internal
```

### VM Creation

Use same specifications as VirtualBox option, but create VMs using Hyper-V Manager.

---

## Option 4: Cloud Deployment (AWS)

**Best For**: Remote access, team collaboration

### Architecture

```
VPC: 10.0.0.0/16
├── Subnet (Private): 10.0.1.0/24
│   ├── DC01: 10.0.1.10
│   ├── WS01: 10.0.1.20
│   ├── WS02: 10.0.1.21
│   └── Attacker: 10.0.1.50
└── Subnet (Public): 10.0.2.0/24
    └── SIEM: 10.0.2.100 (with Elastic IP)
```

### EC2 Instance Types

| Component | Instance Type | Cost (US East) |
|-----------|--------------|----------------|
| DC (Windows) | t3.medium | ~$0.0416/hr |
| Workstation | t3.medium | ~$0.0416/hr |
| Attacker (Linux) | t3.small | ~$0.0208/hr |
| SIEM | t3.large | ~$0.0832/hr |

**Total**: ~$0.25/hour (~$6/day if running 24/7)

### Terraform Deployment

```hcl
# Example terraform configuration
provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "purpleteam" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "PurpleTeam-VPC"
  }
}

# Additional resources...
```

---

## Option 5: Hybrid Approach

**Best For**: Maximum compatibility

### Configuration

- **Domain Controller**: VirtualBox/Hyper-V (Windows Server)
- **Workstations**: VirtualBox/Hyper-V (Windows 10)
- **Attacker + SIEM**: Docker containers

### Network Bridge

Create a network bridge between VMs and Docker:

```bash
# Create Docker network with host network driver
docker network create --driver=bridge --subnet=172.28.0.0/16 purpleteam_net

# Configure VMs to use same subnet
# DC: 172.28.0.10
# WS01: 172.28.0.20
# WS02: 172.28.0.21
```

---

## Troubleshooting

### Docker Issues

**Problem**: Containers fail to start
```bash
# Check logs
docker-compose logs

# Restart specific service
docker-compose restart domain-controller

# Rebuild containers
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

**Problem**: Out of memory
```bash
# Increase Docker memory limit
# Docker Desktop → Settings → Resources → Memory: 8GB+
```

### VirtualBox Issues

**Problem**: Network not working
- Verify all VMs are on same Internal Network
- Check static IP configuration
- Verify DNS points to DC (172.28.0.10)

**Problem**: Domain join fails
- Verify DC is domain controller: `Get-ADDomain`
- Check DNS resolution: `nslookup purpleteam.lab`
- Verify firewall rules allow AD traffic

### Wazuh Issues

**Problem**: Agents not connecting
```bash
# On agent, check status
service wazuh-agent status

# View agent logs
tail -f /var/ossec/logs/ossec.log

# Re-register agent
/var/ossec/bin/agent-auth -m 172.28.0.100
```

**Problem**: Dashboard not accessible
```bash
# Check service status
systemctl status wazuh-dashboard

# Restart services
systemctl restart wazuh-dashboard
```

### Performance Optimization

**Low Resources**:
- Deploy only DC + 1 Workstation + Attacker (minimal setup)
- Reduce RAM per VM to minimum (DC: 2GB, WS: 2GB)
- Use Samba AD instead of Windows Server
- Disable GUI on Ubuntu SIEM

**High Performance**:
- Allocate full recommended resources
- Use SSD storage
- Enable CPU virtualization extensions (VT-x/AMD-V)
- Increase network adapter speeds

---

## Deployment Comparison

| Method | Difficulty | Cost | Authenticity | Speed |
|--------|-----------|------|--------------|-------|
| Docker | Easy | Free | Medium (Samba AD) | Fast (15 min) |
| VirtualBox | Medium | Free | High (Real Windows AD) | Medium (2-3 hrs) |
| Hyper-V | Medium | Free (Win Pro req) | High | Medium (2-3 hrs) |
| Cloud | Medium | ~$6/day | High | Medium (1-2 hrs) |
| Hybrid | Hard | Free/Low | Highest | Slow (3-4 hrs) |

---

## Recommended Approach by Use Case

| Use Case | Recommendation |
|----------|---------------|
| **Quick Demo** | Docker Compose |
| **Learning AD Attacks** | VirtualBox (full Windows) |
| **Portfolio Development** | VirtualBox or Hybrid |
| **Team Training** | Cloud (AWS/Azure) |
| **Windows Host** | Hyper-V |
| **Resource Constrained** | Docker (minimal config) |

---

**Document Version**: 1.0
**Last Updated**: 2024-01-14
**Author**: Purple Team Lab
