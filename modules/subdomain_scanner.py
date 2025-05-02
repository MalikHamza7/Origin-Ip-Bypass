#!/usr/bin/env python3
"""
Subdomain Scanner module for enumerating subdomains
"""

import requests
import socket
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from .utils import print_status, print_colored
from colorama import Fore

class SubdomainScanner:
    """Class for enumerating subdomains of a target domain"""
    
    def __init__(self, domain, verbose=False):
        """Initialize the SubdomainScanner class"""
        self.domain = domain
        self.verbose = verbose
        self.subdomains = set()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        
        # Default nameservers
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
    
    def enumerate_subdomains(self):
        """Main method to enumerate subdomains from multiple sources"""
        sources = [
            self._bruteforce_subdomains,
            self._find_subdomains_crtsh,
            self._find_subdomains_virustotal,
            self._find_subdomains_alienvault
        ]
        
        for source in sources:
            try:
                source()
            except Exception as e:
                if self.verbose:
                    print_colored(f"[!] Error in {source.__name__}: {str(e)}", Fore.RED)
        
        # Verify subdomains
        self._verify_subdomains()
        
        return sorted(list(self.subdomains))
    
    def _bruteforce_subdomains(self):
        """Bruteforce subdomains using a wordlist"""
        if self.verbose:
            print_colored("[+] Bruteforcing common subdomains...", Fore.YELLOW)
        
        common_subdomains = [
            "www", "mail", "ftp", "webmail", "login", "admin", "blog",
            "shop", "forum", "dev", "test", "stage", "api", "cdn", "app",
            "beta", "secure", "support", "remote", "portal", "vpn", "dns",
            "m", "mobile", "ns1", "ns2", "ns3", "ns4", "smtp", "webdisk"
        ]
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for subdomain in common_subdomains:
                full_domain = f"{subdomain}.{self.domain}"
                futures.append(executor.submit(self._resolve_domain, full_domain))
            
            for future in futures:
                result = future.result()
                if result:
                    self.subdomains.add(result)
    
    def _find_subdomains_crtsh(self):
        """Find subdomains using crt.sh certificate transparency logs"""
        if self.verbose:
            print_colored("[+] Looking up subdomains from crt.sh...", Fore.YELLOW)
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name = entry['name_value'].lower()
                        if name.endswith(f".{self.domain}") or name == self.domain:
                            self.subdomains.add(name)
                except:
                    if self.verbose:
                        print_colored("[!] Failed to parse crt.sh response", Fore.RED)
        except requests.exceptions.RequestException:
            if self.verbose:
                print_colored("[!] Failed to connect to crt.sh", Fore.RED)
    
    def _find_subdomains_virustotal(self):
        """Find subdomains using VirusTotal API (public, limited)"""
        if self.verbose:
            print_colored("[+] Looking up subdomains from VirusTotal...", Fore.YELLOW)
        
        try:
            url = f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains"
            headers = {"Accept": "application/json"}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                try:
                    data = response.json()
                    for item in data.get('data', []):
                        subdomain = item.get('id', '').lower()
                        if subdomain.endswith(f".{self.domain}") or subdomain == self.domain:
                            self.subdomains.add(subdomain)
                except:
                    if self.verbose:
                        print_colored("[!] Failed to parse VirusTotal response", Fore.RED)
        except requests.exceptions.RequestException:
            if self.verbose:
                print_colored("[!] Failed to connect to VirusTotal", Fore.RED)
    
    def _find_subdomains_alienvault(self):
        """Find subdomains using AlienVault OTX API"""
        if self.verbose:
            print_colored("[+] Looking up subdomains from AlienVault OTX...", Fore.YELLOW)
        
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data.get('passive_dns', []):
                        hostname = entry.get('hostname', '').lower()
                        if hostname.endswith(f".{self.domain}") or hostname == self.domain:
                            self.subdomains.add(hostname)
                except:
                    if self.verbose:
                        print_colored("[!] Failed to parse AlienVault response", Fore.RED)
        except requests.exceptions.RequestException:
            if self.verbose:
                print_colored("[!] Failed to connect to AlienVault", Fore.RED)
    
    def _resolve_domain(self, domain):
        """Resolve a domain to see if it exists"""
        try:
            self.resolver.resolve(domain, 'A')
            return domain
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            return None
    
    def _verify_subdomains(self):
        """Verify that subdomains are valid by resolving them"""
        if not self.subdomains:
            return
        
        if self.verbose:
            print_colored("[+] Verifying subdomains...", Fore.YELLOW)
        
        confirmed_subdomains = set()
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for subdomain in self.subdomains:
                futures.append(executor.submit(self._resolve_domain, subdomain))
            
            for future in tqdm(futures, desc="Verifying", disable=not self.verbose):
                result = future.result()
                if result:
                    confirmed_subdomains.add(result)
        
        self.subdomains = confirmed_subdomains