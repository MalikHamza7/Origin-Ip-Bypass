#!/usr/bin/env python3
"""
WAF Detector module for detecting Web Application Firewalls
"""

import re
import requests
import urllib3
from requests.exceptions import RequestException
from .utils import print_colored, print_status
from colorama import Fore

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WAFDetector:
    """Class for detecting WAF presence on a website"""
    
    def __init__(self, verbose=False):
        """Initialize the WAFDetector class"""
        self.verbose = verbose
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'close',
        }
        self.waf_signatures = {
            'Cloudflare': [
                'cloudflare-nginx',
                'cloudflare',
                '__cfduid',
                'cf-ray',
                'cf-cache-status'
            ],
            'AWS WAF': [
                'x-amzn-waf',
                'aws-waf',
                'x-amz-cf-id'
            ],
            'Akamai': [
                'akamai',
                'akamaighost',
                'x-akamai-transformed'
            ],
            'Imperva/Incapsula': [
                'incapsula',
                'visid_incap',
                '_incapsula',
                'incap_ses'
            ],
            'Sucuri': [
                'sucuri',
                'x-sucuri-id',
                'x-sucuri-cache'
            ],
            'Barracuda': [
                'barracuda',
                'barra_counter_session'
            ],
            'F5 BIG-IP': [
                'big-ip',
                'bigip',
                'f5',
                'x-f5-'
            ],
            'Fortinet FortiWeb': [
                'fortigate',
                'fortiweb',
                'forticdn'
            ],
            'ModSecurity': [
                'mod_security',
                'modsecurity',
                'OWASP ModSecurity Core Rule Set'
            ],
            'Wordfence': [
                'wordfence',
                'wfvt_',
                'wf_loginalerted'
            ]
        }

    def detect_waf(self, domain):
        """
        Detect if a WAF is protecting the domain
        
        Args:
            domain (str): Domain to check for WAF
            
        Returns:
            str: WAF name if detected, False if no WAF detected
        """
        try:
            # Check if domain starts with http
            if not domain.startswith(('http://', 'https://')):
                domain = f'https://{domain}'
            
            # Try to detect WAF based on normal request
            response = self._make_request(domain)
            if not response:
                if self.verbose:
                    print_colored(f"[!] Could not connect to {domain}", Fore.RED)
                return False
            
            waf = self._check_response(response)
            if waf:
                return waf
            
            # Try to detect WAF based on attack pattern request
            attack_response = self._make_attack_request(domain)
            if not attack_response:
                return False
            
            waf = self._check_response(attack_response)
            if waf:
                return waf
            
            # Check for WAF based on status code difference
            if response.status_code != attack_response.status_code and attack_response.status_code in [403, 406, 429, 503]:
                return "Generic WAF (based on behavior)"
            
            return False
            
        except Exception as e:
            if self.verbose:
                print_colored(f"[!] Error while detecting WAF: {str(e)}", Fore.RED)
            return False
    
    def _make_request(self, url):
        """Make a normal request to the URL"""
        try:
            # Set verify=False to ignore SSL certificate validation
            response = requests.get(
                url,
                headers=self.headers,
                timeout=10,
                allow_redirects=True,
                verify=False
            )
            return response
        except RequestException:
            return None
    
    def _make_attack_request(self, url):
        """Make a request with attack patterns to trigger WAF"""
        attack_patterns = [
            "' OR 1=1 --",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "/?wp-config.php"
        ]
        
        for pattern in attack_patterns:
            try:
                attack_url = f"{url}/{pattern}"
                # Set verify=False to ignore SSL certificate validation
                response = requests.get(
                    attack_url,
                    headers=self.headers,
                    timeout=10,
                    allow_redirects=True,
                    verify=False
                )
                return response
            except RequestException:
                continue
        
        return None
    
    def _check_response(self, response):
        """Check response for WAF signatures"""
        if not response:
            return False
        
        # Check response headers for WAF signatures
        for waf_name, signatures in self.waf_signatures.items():
            for signature in signatures:
                # Check in response headers
                for header, value in response.headers.items():
                    if signature.lower() in header.lower() or signature.lower() in value.lower():
                        return waf_name
                
                # Check in response cookies
                for cookie in response.cookies:
                    if signature.lower() in cookie.name.lower() or signature.lower() in cookie.value.lower():
                        return waf_name
                
                # Check in response content if it's HTML
                if 'text/html' in response.headers.get('Content-Type', ''):
                    if signature.lower() in response.text.lower():
                        return waf_name
        
        # Check for common WAF response patterns
        if 'text/html' in response.headers.get('Content-Type', ''):
            waf_phrases = [
                'blocked by web application firewall',
                'security incident has been logged',
                'suspicious activity detected',
                'access to this page has been blocked',
                'your request has been blocked',
                'your IP address has been flagged',
                'the requested URL was rejected',
                'this request was blocked by the security rules'
            ]
            
            for phrase in waf_phrases:
                if phrase in response.text.lower():
                    return "Generic WAF (text pattern)"
        
        return False