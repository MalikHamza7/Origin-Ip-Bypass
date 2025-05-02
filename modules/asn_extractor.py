#!/usr/bin/env python3
"""
ASN Extractor module for extracting AS information from IPs
"""

import socket
import requests
from ipwhois import IPWhois
from .utils import print_colored
from colorama import Fore

class ASNExtractor:
    """Class for extracting ASN information from IP addresses"""
    
    def __init__(self, verbose=False):
        """Initialize the ASNExtractor class"""
        self.verbose = verbose
    
    def extract_asn(self, domain):
        """
        Extract ASN information from a domain
        
        Args:
            domain (str): Domain to extract ASN information from
            
        Returns:
            tuple: (ip_address, asn_info)
        """
        try:
            # Make sure domain doesn't include protocol
            if domain.startswith(('http://', 'https://')):
                domain = domain.split('://', 1)[1]
            
            # Remove path if present
            domain = domain.split('/', 1)[0]
            
            # Resolve domain to IP
            ip = self._resolve_ip(domain)
            if not ip:
                if self.verbose:
                    print_colored(f"[!] Failed to resolve IP for {domain}", Fore.RED)
                return None, None
            
            # Get ASN information
            asn_info = self._get_asn_info(ip)
            if not asn_info:
                if self.verbose:
                    print_colored(f"[!] Failed to get ASN information for {ip}", Fore.RED)
                return ip, None
            
            return ip, asn_info
            
        except Exception as e:
            if self.verbose:
                print_colored(f"[!] Error in ASN extraction: {str(e)}", Fore.RED)
            return None, None
    
    def _resolve_ip(self, domain):
        """Resolve domain to IP address"""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            if self.verbose:
                print_colored(f"[!] Could not resolve {domain}", Fore.RED)
            return None
    
    def _get_asn_info(self, ip):
        """Get ASN information for an IP address"""
        try:
            # First try with ipwhois
            try:
                whois = IPWhois(ip)
                results = whois.lookup_rdap(depth=1)
                asn_info = {
                    'asn': results.get('asn'),
                    'org': results.get('network', {}).get('name'),
                    'cidr': results.get('network', {}).get('cidr'),
                    'country': results.get('asn_country_code')
                }
                return asn_info
            except Exception:
                if self.verbose:
                    print_colored(f"[!] Failed to get ASN info with IPWhois, trying fallback method", Fore.YELLOW)
            
            # Fallback method using online services
            try:
                response = requests.get(f"https://api.hackertarget.com/aslookup/?q={ip}", timeout=10)
                if response.status_code == 200 and not response.text.startswith('error'):
                    data = response.text.strip().split('\n')
                    if len(data) >= 3:
                        asn = data[0].split(',')[0]
                        org = data[1]
                        cidr = None
                        country = data[0].split(',')[1] if ',' in data[0] else None
                        
                        # Try to get CIDR from another API
                        try:
                            cidr_response = requests.get(f"https://api.hackertarget.com/ipinfo/?q={ip}", timeout=10)
                            if cidr_response.status_code == 200 and 'Error' not in cidr_response.text:
                                for line in cidr_response.text.strip().split('\n'):
                                    if line.startswith('CIDR:'):
                                        cidr = line.split(':', 1)[1].strip()
                                        break
                        except:
                            pass
                        
                        asn_info = {
                            'asn': asn,
                            'org': org,
                            'cidr': cidr,
                            'country': country
                        }
                        return asn_info
            except:
                pass
            
            # If all else fails, return None
            return None
            
        except Exception as e:
            if self.verbose:
                print_colored(f"[!] Error getting ASN info: {str(e)}", Fore.RED)
            return None