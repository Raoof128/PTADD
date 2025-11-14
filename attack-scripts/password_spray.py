#!/usr/bin/env python3
"""
Password Spraying Attack (MITRE ATT&CK: T1110.003)

Attempts a small number of common passwords against many user accounts

Author: Purple Team Lab
MITRE ATT&CK: T1110.003 - Brute Force: Password Spraying
Date: 2024-01-14

Usage:
    python3 password_spray.py -d PURPLETEAM.LAB -u users.txt -p 'Winter2024!' -dc 172.28.0.10
"""

import argparse
import time
from typing import List

class Colors:
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    WARNING = '\033[93m'
    OKBLUE = '\033[94m'
    ENDC = '\033[0m'

class PasswordSpray:
    def __init__(self, domain: str, dc_ip: str, users: List[str], passwords: List[str]):
        self.domain = domain
        self.dc_ip = dc_ip
        self.users = users
        self.passwords = passwords
        self.valid_creds = []

    def spray(self):
        print(f"{Colors.OKBLUE}{'='*70}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}Password Spraying Attack - MITRE ATT&CK T1110.003{Colors.ENDC}")
        print(f"{Colors.OKBLUE}{'='*70}{Colors.ENDC}\n")

        print(f"[*] Domain: {self.domain}")
        print(f"[*] DC: {self.dc_ip}")
        print(f"[*] Users: {len(self.users)}")
        print(f"[*] Passwords: {len(self.passwords)}\n")

        for password in self.passwords:
            print(f"{Colors.WARNING}[*] Trying password: {password}{Colors.ENDC}")

            for user in self.users:
                # Simulate authentication attempt
                print(f"    [*] Testing {user}:{password}")
                time.sleep(0.1)  # Throttle to avoid lockouts

            print()  # Spacing between password attempts
            time.sleep(30)  # Delay between password sprays (avoid lockout)

        print(f"{Colors.OKGREEN}[+] Password spray completed{Colors.ENDC}")
        print(f"\n{Colors.WARNING}[!] Detection:{Colors.ENDC}")
        print("    - Event ID 4625 (Failed logons)")
        print("    - Multiple failed attempts from single source")
        print("    - Account lockout events (Event ID 4740)")

def main():
    parser = argparse.ArgumentParser(description='Password Spraying Attack')
    parser.add_argument('-d', '--domain', required=True)
    parser.add_argument('-dc', '--dc-ip', required=True)
    parser.add_argument('-u', '--users', required=True, help='User list file')
    parser.add_argument('-p', '--password', required=True, help='Password to spray')

    args = parser.parse_args()

    # Read users from file
    with open(args.users, 'r') as f:
        users = [line.strip() for line in f if line.strip()]

    passwords = [args.password]

    spray = PasswordSpray(args.domain, args.dc_ip, users, passwords)
    spray.spray()

if __name__ == '__main__':
    main()
