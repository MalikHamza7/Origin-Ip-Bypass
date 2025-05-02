#!/usr/bin/env python3
"""
Web Origin IP Bypass - Main Application
A tool to discover origin IPs by bypassing WAF protection
"""

import sys
import argparse
from colorama import init, Fore, Style
import time
import urllib3

# Local imports
from modules.banner import print_banner
from modules.subdomain_scanner import SubdomainScanner
from modules.waf_detector import WAFDetector
from modules.asn_extractor import ASNExtractor
from modules.ip_range_finder import IPRangeFinder
from modules.utils import clear_screen, print_colored, print_status, Spinner

# Initialize colorama
init(autoreset=True)

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    """Main function to run the application"""
    clear_screen()
    print_banner()
    
    # Create argument parser
    parser = argparse.ArgumentParser(
        description="Web Origin IP Bypass - A tool to find origin IPs by bypassing WAF protection",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Add arguments
    parser.add_argument('-d', '--domain', help='Target domain to scan')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('-s', '--subdomains-only', action='store_true', help='Only perform subdomain enumeration')
    parser.add_argument('-w', '--waf-only', action='store_true', help='Only perform WAF detection')
    parser.add_argument('-a', '--asn-only', action='store_true', help='Only perform ASN extraction')
    parser.add_argument('-i', '--ip-range-only', action='store_true', help='Only perform IP range finding')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--help-examples', action='store_true', help='Show usage examples')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Show help examples
    if args.help_examples:
        show_help_examples()
        return
    
    # Check if domain is provided
    if not args.domain:
        try:
            # Interactive mode if no domain provided
            print_colored("\n[+] No domain specified. Starting interactive mode...\n", Fore.YELLOW)
            args.domain = input(f"{Fore.CYAN}[>] Enter target domain (e.g., example.com): {Style.RESET_ALL}")
            
            if not args.domain:
                print_colored("\n[!] No domain provided. Exiting...", Fore.RED)
                sys.exit(1)
                
            print_colored(f"\n[+] Target domain set to: {args.domain}", Fore.GREEN)
            
            # Ask for output file
            output_choice = input(f"\n{Fore.CYAN}[>] Save results to file? (y/n): {Style.RESET_ALL}").lower()
            if output_choice == 'y':
                args.output = input(f"{Fore.CYAN}[>] Enter output filename: {Style.RESET_ALL}")
                print_colored(f"[+] Results will be saved to: {args.output}", Fore.GREEN)
            
            # Ask for verbosity
            verbose_choice = input(f"\n{Fore.CYAN}[>] Enable verbose output? (y/n): {Style.RESET_ALL}").lower()
            args.verbose = verbose_choice == 'y'
            
        except KeyboardInterrupt:
            print_colored("\n\n[!] Process interrupted by user. Exiting...", Fore.RED)
            sys.exit(1)
    
    print_colored("\n[+] Starting Web Origin IP Bypass workflow...", Fore.GREEN)
    print_colored(f"[+] Target domain: {args.domain}\n", Fore.GREEN)
    
    try:
        # Initialize modules
        subdomain_scanner = SubdomainScanner(args.domain, args.verbose)
        waf_detector = WAFDetector(args.verbose)
        asn_extractor = ASNExtractor(args.verbose)
        ip_range_finder = IPRangeFinder(args.verbose)
        
        # Workflow execution
        if args.subdomains_only:
            # Only run subdomain enumeration
            with Spinner("Enumerating subdomains..."):
                subdomains = subdomain_scanner.enumerate_subdomains()
            print_status(f"Found {len(subdomains)} subdomains", "success")
            for subdomain in subdomains:
                print(f"  - {subdomain}")
        elif args.waf_only and args.domain:
            # Only run WAF detection
            with Spinner(f"Detecting WAF on {args.domain}..."):
                waf_result = waf_detector.detect_waf(args.domain)
            if waf_result:
                print_status(f"WAF detected: {waf_result}", "warning")
            else:
                print_status("No WAF detected", "success")
        elif args.asn_only and args.domain:
            # Only run ASN extraction
            with Spinner(f"Extracting ASN information for {args.domain}..."):
                ip, asn_info = asn_extractor.extract_asn(args.domain)
            if asn_info:
                print_status(f"IP: {ip}", "info")
                print_status(f"ASN: {asn_info.get('asn')}", "info")
                print_status(f"Organization: {asn_info.get('org')}", "info")
                print_status(f"CIDR: {asn_info.get('cidr')}", "info")
        elif args.ip_range_only and args.domain:
            # Only run IP range finding
            with Spinner(f"Finding IP ranges for {args.domain}..."):
                ip, asn_info = asn_extractor.extract_asn(args.domain)
                ip_ranges = ip_range_finder.find_ip_ranges(asn_info.get('asn'))
            print_status(f"Found {len(ip_ranges)} IP ranges", "success")
            for ip_range in ip_ranges:
                print(f"  - {ip_range}")
        else:
            # Run full workflow
            print_colored("\n[STEP 1] Subdomain Enumeration", Fore.CYAN)
            with Spinner("Enumerating subdomains..."):
                subdomains = subdomain_scanner.enumerate_subdomains()
            print_status(f"Found {len(subdomains)} subdomains", "success")
            
            if len(subdomains) > 0:
                print_colored("\n[STEP 2] WAF Detection", Fore.CYAN)
                no_waf_subdomains = []
                
                for i, subdomain in enumerate(subdomains, 1):
                    print_status(f"Checking WAF [{i}/{len(subdomains)}]: {subdomain}", "info")
                    waf_result = waf_detector.detect_waf(subdomain)
                    
                    if waf_result:
                        print_status(f"  WAF detected: {waf_result}", "warning")
                    else:
                        print_status(f"  No WAF detected", "success")
                        no_waf_subdomains.append(subdomain)
                
                print_status(f"Found {len(no_waf_subdomains)} subdomains without WAF", "success")
                
                if len(no_waf_subdomains) > 0:
                    print_colored("\n[STEP 3] ASN Extraction", Fore.CYAN)
                    target_subdomain = no_waf_subdomains[0]
                    print_status(f"Using subdomain: {target_subdomain}", "info")
                    
                    with Spinner("Extracting ASN information..."):
                        ip, asn_info = asn_extractor.extract_asn(target_subdomain)
                    
                    if asn_info:
                        print_status(f"IP: {ip}", "info")
                        print_status(f"ASN: {asn_info.get('asn')}", "info")
                        print_status(f"Organization: {asn_info.get('org')}", "info")
                        print_status(f"CIDR: {asn_info.get('cidr')}", "info")
                        
                        print_colored("\n[STEP 4] IP Range Finding", Fore.CYAN)
                        with Spinner("Finding IP ranges..."):
                            ip_ranges = ip_range_finder.find_ip_ranges(asn_info.get('asn'))
                        
                        print_status(f"Found {len(ip_ranges)} IP ranges", "success")
                        for ip_range in ip_ranges:
                            print(f"  - {ip_range}")
                        
                        print_colored("\n[STEP 5] Live IP Verification", Fore.CYAN)
                        with Spinner("Verifying live IPs and scanning web ports..."):
                            live_ips = ip_range_finder.verify_live_ips(ip_ranges, 5)  # Verify 5 IPs
                        
                        if live_ips:
                            print_status(f"Found {len(live_ips)} live IPs with open web ports", "success")
                            print_colored("\n[FINAL RESULTS]", Fore.GREEN)
                            print_status(f"Original domain: {args.domain}", "info")
                            print_status(f"Subdomain without WAF: {target_subdomain}", "info")
                            print_status(f"ASN: {asn_info.get('asn')}", "info")
                            print_status(f"Organization: {asn_info.get('org')}", "info")
                            print_status(f"Potential origin IPs with open web ports:", "info")
                            
                            for ip_info in live_ips:
                                ip = ip_info['ip']
                                ports = ip_info['open_ports']
                                print(f"\n  IP: {ip}")
                                print("  Open web ports:")
                                for port_info in ports:
                                    status = f" (Status: {port_info['status_code']})" if port_info['status_code'] else ""
                                    print(f"    - {port_info['protocol']}://{ip}:{port_info['port']}{status}")
                        else:
                            print_status("No live IPs with open web ports found", "error")
                    else:
                        print_status("Failed to extract ASN information", "error")
                else:
                    print_status("No subdomains without WAF found", "error")
            else:
                print_status("No subdomains found", "error")
        
        # Save results to file if specified
        if args.output and ((subdomains and len(subdomains) > 0) or 
                           (locals().get('no_waf_subdomains') and len(no_waf_subdomains) > 0) or
                           (locals().get('live_ips') and len(live_ips) > 0)):
            save_results(args)
            
    except KeyboardInterrupt:
        print_colored("\n\n[!] Process interrupted by user. Exiting...", Fore.RED)
        sys.exit(1)
    except Exception as e:
        print_colored(f"\n[!] An error occurred: {str(e)}", Fore.RED)
        if args.verbose:
            import traceback
            print(traceback.format_exc())
        sys.exit(1)

def save_results(args):
    """Save results to a file"""
    try:
        with open(args.output, 'w') as f:
            f.write("Web Origin IP Bypass - Results\n")
            f.write(f"Target domain: {args.domain}\n\n")
            
            # Add more sections based on what was executed
            # This is a placeholder - in a real implementation, 
            # we'd pass the actual results to this function
            
        print_colored(f"\n[+] Results saved to {args.output}", Fore.GREEN)
    except Exception as e:
        print_colored(f"\n[!] Failed to save results: {str(e)}", Fore.RED)

def show_help_examples():
    """Display help examples"""
    examples = """
Web Origin IP Bypass - Usage Examples
====================================

Basic Usage:
-----------
python main.py -d example.com

Run specific steps:
-----------------
python main.py -d example.com -s        # Only enumerate subdomains
python main.py -d example.com -w        # Only detect WAF
python main.py -d example.com -a        # Only extract ASN
python main.py -d example.com -i        # Only find IP ranges

Output results to file:
---------------------
python main.py -d example.com -o results.txt

Enable verbose output:
-------------------
python main.py -d example.com -v

Interactive mode:
---------------
python main.py

For more help:
------------
python main.py -h              # Show all options
python main.py --help-examples # Show these examples
"""
    print(examples)

if __name__ == "__main__":
    main()