#!/usr/bin/env python3
"""
Email Debounce Checker
Validates email addresses by checking syntax, DNS records, and SMTP verification
"""

import re
import dns.resolver
import smtplib
import socket
from typing import Dict, List, Tuple
from email.utils import parseaddr
import sys

class EmailDebounceChecker:
    """Check if email addresses are valid and deliverable"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = timeout
        self.dns_resolver.lifetime = timeout
    
    def check_syntax(self, email: str) -> Tuple[bool, str]:
        """Validate email syntax using regex"""
        if not email or '@' not in email:
            return False, "Invalid format: missing @ symbol"
        
        # Basic email regex pattern
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(pattern, email):
            return False, "Invalid email format"
        
        local, domain = email.rsplit('@', 1)
        
        # Check local part length
        if len(local) > 64:
            return False, "Local part too long (max 64 characters)"
        
        # Check domain length
        if len(domain) > 255:
            return False, "Domain too long (max 255 characters)"
        
        return True, "Valid syntax"
    
    def check_dns(self, domain: str) -> Tuple[bool, str, List[str]]:
        """Check if domain has valid MX records"""
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_hosts = [str(r.exchange).rstrip('.') for r in mx_records]
            return True, f"Found {len(mx_hosts)} MX record(s)", mx_hosts
        except dns.resolver.NXDOMAIN:
            return False, "Domain does not exist", []
        except dns.resolver.NoAnswer:
            return False, "No MX records found", []
        except dns.resolver.Timeout:
            return False, "DNS query timeout", []
        except Exception as e:
            return False, f"DNS error: {str(e)}", []
    
    def check_smtp(self, email: str, mx_host: str) -> Tuple[bool, str]:
        """Verify email via SMTP without sending"""
        try:
            # Connect to SMTP server
            server = smtplib.SMTP(timeout=self.timeout)
            server.set_debuglevel(0)
            
            # Connect to MX host
            server.connect(mx_host)
            server.helo(server.local_hostname)
            server.mail('verify@example.com')
            
            # Check if recipient exists
            code, message = server.rcpt(email)
            server.quit()
            
            if code == 250:
                return True, "SMTP verification passed"
            elif code == 550:
                return False, "Mailbox not found"
            else:
                return False, f"SMTP code {code}: {message.decode()}"
                
        except smtplib.SMTPServerDisconnected:
            return False, "SMTP server disconnected"
        except smtplib.SMTPConnectError:
            return False, "Cannot connect to SMTP server"
        except socket.timeout:
            return False, "SMTP connection timeout"
        except Exception as e:
            return False, f"SMTP error: {str(e)}"
    
    def check_email(self, email: str, verify_smtp: bool = False) -> Dict:
        """Perform complete email validation"""
        email = email.strip().lower()
        
        result = {
            'email': email,
            'valid': False,
            'syntax_valid': False,
            'dns_valid': False,
            'smtp_valid': None,
            'details': {},
            'errors': []
        }
        
        # Check syntax
        syntax_valid, syntax_msg = self.check_syntax(email)
        result['syntax_valid'] = syntax_valid
        result['details']['syntax'] = syntax_msg
        
        if not syntax_valid:
            result['errors'].append(syntax_msg)
            return result
        
        # Extract domain
        domain = email.split('@')[1]
        
        # Check DNS/MX records
        dns_valid, dns_msg, mx_hosts = self.check_dns(domain)
        result['dns_valid'] = dns_valid
        result['details']['dns'] = dns_msg
        result['details']['mx_records'] = mx_hosts
        
        if not dns_valid:
            result['errors'].append(dns_msg)
            return result
        
        # Optional SMTP verification
        if verify_smtp and mx_hosts:
            smtp_valid, smtp_msg = self.check_smtp(email, mx_hosts[0])
            result['smtp_valid'] = smtp_valid
            result['details']['smtp'] = smtp_msg
            
            if not smtp_valid:
                result['errors'].append(smtp_msg)
                return result
        
        # Email is valid if syntax and DNS checks pass
        result['valid'] = syntax_valid and dns_valid and (result['smtp_valid'] if verify_smtp else True)
        
        return result
    
    def check_bulk(self, emails: List[str], verify_smtp: bool = False) -> List[Dict]:
        """Check multiple emails"""
        results = []
        for email in emails:
            result = self.check_email(email, verify_smtp)
            results.append(result)
        return results


def print_result(result: Dict):
    """Pretty print validation result"""
    email = result['email']
    valid = result['valid']
    
    print(f"\n{'='*60}")
    print(f"Email: {email}")
    print(f"Status: {'✓ VALID' if valid else '✗ INVALID'}")
    print(f"{'='*60}")
    
    print(f"Syntax Check: {'✓' if result['syntax_valid'] else '✗'} {result['details'].get('syntax', '')}")
    print(f"DNS Check: {'✓' if result['dns_valid'] else '✗'} {result['details'].get('dns', '')}")
    
    if result['details'].get('mx_records'):
        print(f"MX Records:")
        for mx in result['details']['mx_records'][:3]:
            print(f"  - {mx}")
    
    if result['smtp_valid'] is not None:
        print(f"SMTP Check: {'✓' if result['smtp_valid'] else '✗'} {result['details'].get('smtp', '')}")
    
    if result['errors']:
        print(f"\nErrors:")
        for error in result['errors']:
            print(f"  - {error}")


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Email Debounce Checker - Validate email addresses',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 email_debounce_checker.py user@example.com
  python3 email_debounce_checker.py user@example.com --smtp
  python3 email_debounce_checker.py user1@example.com user2@example.com
  python3 email_debounce_checker.py --file emails.txt
        """
    )
    
    parser.add_argument('emails', nargs='*', help='Email address(es) to check')
    parser.add_argument('--file', '-f', help='File containing email addresses (one per line)')
    parser.add_argument('--smtp', action='store_true', help='Enable SMTP verification (slower)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds (default: 10)')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    
    args = parser.parse_args()
    
    # Collect emails
    emails = []
    
    if args.emails:
        emails.extend(args.emails)
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_emails = [line.strip() for line in f if line.strip()]
                emails.extend(file_emails)
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found")
            sys.exit(1)
    
    if not emails:
        parser.print_help()
        sys.exit(1)
    
    # Initialize checker
    checker = EmailDebounceChecker(timeout=args.timeout)
    
    # Check emails
    print(f"\nChecking {len(emails)} email(s)...")
    if args.smtp:
        print("⚠ SMTP verification enabled (this may take longer)")
    
    results = checker.check_bulk(emails, verify_smtp=args.smtp)
    
    # Output results
    if args.json:
        import json
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            print_result(result)
        
        # Summary
        valid_count = sum(1 for r in results if r['valid'])
        print(f"\n{'='*60}")
        print(f"Summary: {valid_count}/{len(results)} valid email(s)")
        print(f"{'='*60}\n")


if __name__ == '__main__':
    main()
