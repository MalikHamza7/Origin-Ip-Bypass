#!/usr/bin/env python3
"""
IP Range Finder module for finding IP ranges for an ASN
"""

import random
import socket
import ipaddress
import requests
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from .utils import print_colored, print_status
from colorama import Fore

class IPRangeFinder:
    """Class for finding IP ranges for an ASN and verifying live IPs"""
    
    def __init__(self, verbose=False):
        """Initialize the IPRangeFinder class"""
        self.verbose = verbose
        self.web_ports = [80, 443, 8080, 8443, 3000, 4443, 8000, 8888]
    
    def find_ip_ranges(self, asn):
        """
        Find IP ranges for an ASN
        
        Args:
            asn (str): ASN number (e.g., "AS13335")
            
        Returns:
            list: List of IP ranges (CIDR notation)
        """
        if not asn:
            return []
        
        # Make sure ASN is in correct format
        if not isinstance(asn, str):
            asn = str(asn)
        
        if not asn.startswith('AS'):
            asn = f"AS{asn}"
        
        ip_ranges = []
        
        # Method 1: RIPEstat API
        try:
            url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                prefixes = data.get('data', {}).get('prefixes', [])
                if isinstance(prefixes, list):
                    ip_ranges.extend([prefix for prefix in prefixes if isinstance(prefix, str)])
        except Exception as e:
            if self.verbose:
                print_colored(f"[!] Error with RIPEstat API: {str(e)}", Fore.RED)
        
        # Method 2: BGPView API
        if not ip_ranges:
            try:
                url = f"https://api.bgpview.io/asn/{asn.replace('AS', '')}/prefixes"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    ipv4_prefixes = data.get('data', {}).get('ipv4_prefixes', [])
                    for prefix in ipv4_prefixes:
                        if isinstance(prefix, dict) and 'prefix' in prefix:
                            ip_ranges.append(prefix['prefix'])
            except Exception as e:
                if self.verbose:
                    print_colored(f"[!] Error with BGPView API: {str(e)}", Fore.RED)
        
        # Method 3: HackerTarget ASN lookup
        if not ip_ranges:
            try:
                url = f"https://api.hackertarget.com/aslookup/?q={asn}"
                response = requests.get(url, timeout=10)
                if response.status_code == 200 and not response.text.startswith('error'):
                    lines = response.text.strip().split('\n')
                    for line in lines:
                        if '/' in line:  # CIDR notation
                            parts = line.split()
                            for part in parts:
                                if '/' in part and part[0].isdigit():
                                    ip_ranges.append(part)
            except Exception as e:
                if self.verbose:
                    print_colored(f"[!] Error with HackerTarget API: {str(e)}", Fore.RED)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_ranges = []
        for ip_range in ip_ranges:
            if ip_range not in seen and isinstance(ip_range, str):
                seen.add(ip_range)
                unique_ranges.append(ip_range)
        
        return unique_ranges
    
    def verify_live_ips(self, ip_ranges, max_per_range=3):
        """
        Verify which IPs in the ranges are live and check for open web ports
        
        Args:
            ip_ranges (list): List of IP ranges in CIDR notation
            max_per_range (int): Maximum number of IPs to check per range
            
        Returns:
            list: List of dictionaries containing live IPs and their open ports
        """
        if not ip_ranges:
            return []
        
        ips_to_check = []
        
        # Generate IPs to check from each range
        for ip_range in ip_ranges:
            try:
                network = ipaddress.ip_network(ip_range)
                # For small networks, check all hosts
                if network.num_addresses <= max_per_range:
                    for ip in network.hosts():
                        ips_to_check.append(str(ip))
                # For larger networks, sample random IPs
                else:
                    hosts = list(network.hosts())
                    sampled_ips = random.sample(hosts, min(max_per_range, len(hosts)))
                    for ip in sampled_ips:
                        ips_to_check.append(str(ip))
            except Exception as e:
                if self.verbose:
                    print_colored(f"[!] Error parsing IP range {ip_range}: {str(e)}", Fore.RED)
        
        # Check if IPs are live and scan for open web ports
        live_ips = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for ip in ips_to_check:
                futures.append(executor.submit(self._check_ip_and_ports, ip))
            
            for i, future in enumerate(tqdm(futures, desc="Verifying IPs", disable=not self.verbose)):
                result = future.result()
                if result:
                    live_ips.append(result)
        
        return live_ips
    
    def _check_ip_and_ports(self, ip):
        """
        Check if an IP is live and scan for open web ports
        
        Args:
            ip (str): IP address to check
            
        Returns:
            dict: Dictionary containing IP and open ports information
        """
        open_ports = []
        
        for port in self.web_ports:
            try:
                # Try to connect with a short timeout
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((ip, port))
                s.close()
                
                if result == 0:
                    # Try HTTP request for additional verification
                    try:
                        protocol = "https" if port in [443, 8443, 4443] else "http"
                        url = f"{protocol}://{ip}:{port}"
                        response = requests.get(url, timeout=3, verify=False, allow_redirects=True)
                        if response.status_code:
                            open_ports.append({
                                "port": port,
                                "protocol": protocol,
                                "status_code": response.status_code
                            })
                    except:
                        # If HTTP request fails but port is open, still include it
                        open_ports.append({
                            "port": port,
                            "protocol": "unknown",
                            "status_code": None
                        })
            except:
                continue
        
        if open_ports:
            return {
                "ip": ip,
                "open_ports": open_ports
            }
        
        return None