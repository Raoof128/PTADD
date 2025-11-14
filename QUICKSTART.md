# Quick Start Guide

**Get the Purple Team AD Lab running in 15 minutes**

---

## 🚀 5-Step Deployment

### Step 1: Prerequisites (2 minutes)

```bash
# Verify Docker installed
docker --version
docker-compose --version

# If not installed (Ubuntu/Debian):
sudo apt-get update
sudo apt-get install -y docker.io docker-compose
sudo systemctl start docker
sudo usermod -aG docker $USER
newgrp docker
```

**Minimum Requirements**:
- 8GB RAM (16GB recommended)
- 30GB free disk space
- Linux host or WSL2

---

### Step 2: Clone & Setup (3 minutes)

```bash
# Clone repository
git clone <your-repo-url> PTADD
cd PTADD

# Run automated setup
chmod +x lab-setup/setup.sh
./lab-setup/setup.sh
```

---

### Step 3: Deploy Lab (5 minutes)

```bash
# Start all services
docker-compose up -d

# Verify deployment
docker-compose ps

# Expected output: All services "Up"
```

---

### Step 4: Access Components (2 minutes)

**Wazuh SIEM Dashboard**:
```bash
# Open browser
https://localhost:443

# Login credentials
Username: admin
Password: SecretPassword
```

**Attacker Workstation**:
```bash
# Access Kali container
docker-compose exec attacker bash

# You're now in the attacker shell
```

---

### Step 5: Run First Attack (3 minutes)

```bash
# From attacker shell
python3 /opt/attack-scripts/kerberoasting.py \
    -d PURPLETEAM.LAB \
    -u lowpriv \
    -p 'Password123!' \
    -dc-ip 172.28.0.10

# Expected output:
# [+] Found 2 SPNs
# [+] Tickets extracted: 2
```

**Check Detection**:
- Go to Wazuh Dashboard → Security Events
- Look for "Kerberoasting Attack Detected"
- Should appear within 30 seconds

---

## ✅ Verification Checklist

```bash
# Run validation script
./lab-setup/validate-lab.sh

# All tests should pass
```

---

## 📖 Next Steps

1. **Explore All Attacks**:
   ```bash
   ls -lh attack-scripts/
   cat documentation/ATTACK_PLAYBOOK.md
   ```

2. **Review Detection Rules**:
   ```bash
   cat detection-rules/sigma-rules/kerberoasting_attack.yml
   cat documentation/DETECTION_MATRIX.md
   ```

3. **Test Hardening**:
   ```bash
   # On DC (if using VirtualBox)
   .\hardening\ad-hardening.ps1 -Action Report
   ```

4. **Read Full Documentation**:
   - `README.md` - Project overview
   - `documentation/ATTACK_PLAYBOOK.md` - Attack walkthroughs
   - `documentation/DETECTION_MATRIX.md` - Detection analysis
   - `documentation/ARCHITECTURE.md` - Technical architecture
   - `documentation/TESTING_GUIDE.md` - Complete testing procedures

---

## 🛑 Troubleshooting

### Issue: Docker fails to start

```bash
# Check Docker daemon
sudo systemctl status docker
sudo systemctl start docker

# Check permissions
sudo usermod -aG docker $USER
newgrp docker
```

### Issue: Containers not starting

```bash
# View logs
docker-compose logs domain-controller
docker-compose logs wazuh-manager

# Restart specific service
docker-compose restart domain-controller
```

### Issue: Out of memory

```bash
# Increase Docker memory
# Docker Desktop → Settings → Resources → Memory: 12GB+

# Or deploy minimal setup
docker-compose up -d domain-controller attacker wazuh-manager
```

### Issue: Network connectivity

```bash
# Check network
docker network ls
docker network inspect purpleteam_ad_network

# Recreate network
docker-compose down
docker-compose up -d
```

---

## 📞 Get Help

1. **Read Documentation**: `documentation/` folder
2. **Check Logs**: `docker-compose logs -f [service]`
3. **Run Validation**: `./lab-setup/validate-lab.sh`
4. **Review Issues**: Check repository Issues tab

---

## 🎯 Quick Command Reference

```bash
# Lab Management
docker-compose up -d          # Start lab
docker-compose down           # Stop lab
docker-compose ps             # Check status
docker-compose logs -f        # View logs

# Access Components
docker-compose exec attacker bash      # Attacker shell
docker-compose exec dc bash            # DC shell (if Linux)

# Run Attacks
kerberoast -d PURPLETEAM.LAB -u user -p pass -dc-ip 172.28.0.10
asreproast -d PURPLETEAM.LAB -dc-ip 172.28.0.10
dcsync -d PURPLETEAM.LAB -u admin -p pass -dc-ip 172.28.0.10

# Validation
./lab-setup/validate-lab.sh            # Full validation
python3 -m py_compile attack-scripts/*.py  # Check Python syntax
docker-compose config                  # Validate docker-compose.yml
```

---

## 🌟 You're Ready!

The lab is now fully operational. Start exploring attacks, reviewing detections, and building your purple team skills!

**Estimated Time**: 15 minutes from zero to running attacks

**What's Next**: Try all 13 attack techniques and verify 96.2% detection coverage!
