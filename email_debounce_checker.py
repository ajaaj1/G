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
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeoutError
from functools import partial

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

    def check_email_with_timeout(self, email: str, verify_smtp: bool = False) -> Dict:
        """Check email with timeout handling"""
        def timeout_handler(signum, frame):
            raise TimeoutError("Email check timed out")

        # Set up timeout signal
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(self.timeout * 2)  # Give extra time for cleanup

        try:
            result = self.check_email(email, verify_smtp)
            return result
        except TimeoutError:
            return {
                'email': email.strip().lower(),
                'valid': False,
                'syntax_valid': False,
                'dns_valid': False,
                'smtp_valid': None,
                'details': {'syntax': 'Check timed out'},
                'errors': ['Check timed out']
            }
        except Exception as e:
            return {
                'email': email.strip().lower(),
                'valid': False,
                'syntax_valid': False,
                'dns_valid': False,
                'smtp_valid': None,
                'details': {'syntax': f'Unexpected error: {str(e)}'},
                'errors': [f'Unexpected error: {str(e)}']
            }
        finally:
            # Restore original signal handler and cancel alarm
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

    def check_bulk(self, emails: List[str], verify_smtp: bool = False, concurrency: int = 10, batch_size: int = 100, delay: float = 0.0) -> List[Dict]:
        """Check multiple emails with progress tracking and parallel processing"""
        total_emails = len(emails)
        results = [None] * total_emails  # Pre-allocate results list
        start_time = time.time()

        print(f"\nChecking {total_emails} email(s) with {concurrency} concurrent threads...")
        if verify_smtp:
            print("⚠ SMTP verification enabled (this may take longer)")
        print(f"Progress updates every {batch_size} emails\n")

        # Process in batches for progress tracking
        for batch_start in range(0, total_emails, batch_size):
            batch_end = min(batch_start + batch_size, total_emails)
            batch_emails = emails[batch_start:batch_end]

            # Process batch with parallel threads
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                # Submit all tasks for this batch
                future_to_index = {
                    executor.submit(self.check_email_with_timeout, email, verify_smtp): batch_start + i
                    for i, email in enumerate(batch_emails)
                }

                # Collect results as they complete
                for future in as_completed(future_to_index):
                    index = future_to_index[future]
                    try:
                        results[index] = future.result()
                    except Exception as e:
                        # Handle any unexpected errors
                        email = emails[index]
                        results[index] = {
                            'email': email.strip().lower(),
                            'valid': False,
                            'syntax_valid': False,
                            'dns_valid': False,
                            'smtp_valid': None,
                            'details': {'syntax': f'Processing error: {str(e)}'},
                            'errors': [f'Processing error: {str(e)}']
                        }

            # Progress update
            processed = batch_end
            elapsed = time.time() - start_time
            rate = processed / elapsed if elapsed > 0 else 0
            eta = (total_emails - processed) / rate if rate > 0 else 0

            print(f"Progress: {processed}/{total_emails} emails processed "
                  f"({processed/total_emails*100:.1f}%) - "
                  f"Rate: {rate:.1f} emails/sec - "
                  f"ETA: {eta:.0f} seconds")

            # Optional delay between batches
            if delay > 0 and batch_end < total_emails:
                time.sleep(delay)

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
    parser.add_argument('--concurrency', type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('--batch-size', type=int, default=100, help='Batch size for progress updates (default: 100)')
    parser.add_argument('--delay', type=float, default=0.0, help='Delay between batches in seconds (default: 0.0)')
    
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
    results = checker.check_bulk(
        emails,
        verify_smtp=args.smtp,
        concurrency=args.concurrency,
        batch_size=args.batch_size,
        delay=args.delay
    )
    
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
