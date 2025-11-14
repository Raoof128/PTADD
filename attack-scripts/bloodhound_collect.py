#!/usr/bin/env python3
"""
BloodHound Data Collection (MITRE ATT&CK: T1087.002)

Collects Active Directory enumeration data for BloodHound graph analysis

Author: Purple Team Lab
MITRE ATT&CK: T1087.002 - Account Discovery: Domain Account
Date: 2024-01-14

Usage:
    python3 bloodhound_collect.py -d PURPLETEAM.LAB -u user1 -p Pass123! -dc 172.28.0.10
"""

import argparse
import sys

class Colors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    OKBLUE = '\033[94m'
    ENDC = '\033[0m'

def main():
    parser = argparse.ArgumentParser(description='BloodHound Data Collection')
    parser.add_argument('-d', '--domain', required=True)
    parser.add_argument('-u', '--username', required=True)
    parser.add_argument('-p', '--password', required=True)
    parser.add_argument('-dc', '--dc-ip', required=True)

    args = parser.parse_args()

    print(f"{Colors.OKBLUE}{'='*70}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}BloodHound Data Collection - MITRE ATT&CK T1087.002{Colors.ENDC}")
    print(f"{Colors.OKBLUE}{'='*70}{Colors.ENDC}\n")

    print(f"[*] Target Domain: {args.domain}")
    print(f"[*] Domain Controller: {args.dc_ip}")
    print(f"[*] Username: {args.username}\n")

    # SharpHound (C#) collector
    print(f"{Colors.OKGREEN}[*] SharpHound.exe collector:{Colors.ENDC}")
    print(f"    SharpHound.exe -c All -d {args.domain} --domaincontroller {args.dc_ip}")

    # BloodHound Python (bloodhound.py)
    print(f"\n{Colors.OKGREEN}[*] BloodHound Python collector:{Colors.ENDC}")
    cmd = f"bloodhound-python -d {args.domain} -u {args.username} -p '{args.password}' -ns {args.dc_ip} -c all"
    print(f"    {cmd}")

    print(f"\n{Colors.WARNING}[*] Collected data includes:{Colors.ENDC}")
    print("    - User accounts and properties")
    print("    - Group memberships")
    print("    - Computer accounts")
    print("    - Domain trusts")
    print("    - ACLs and permissions")
    print("    - Attack paths to Domain Admins")

    print(f"\n{Colors.OKGREEN}[+] Import JSON files into BloodHound GUI for analysis{Colors.ENDC}")

if __name__ == '__main__':
    main()
