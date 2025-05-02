#!/usr/bin/env python3
"""
Utility functions and classes for the Web Origin IP Bypass tool
"""

import os
import sys
import time
import threading
from colorama import Fore, Style

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_colored(message, color):
    """Print a colored message"""
    print(f"{color}{message}{Style.RESET_ALL}")

def print_status(message, status_type="info"):
    """Print a status message with appropriate coloring"""
    
    if status_type == "success":
        color = Fore.GREEN
        prefix = "[+] "
    elif status_type == "info":
        color = Fore.CYAN
        prefix = "[*] "
    elif status_type == "warning":
        color = Fore.YELLOW
        prefix = "[!] "
    elif status_type == "error":
        color = Fore.RED
        prefix = "[✗] "
    else:
        color = Fore.WHITE
        prefix = "[*] "
    
    print(f"{color}{prefix}{message}{Style.RESET_ALL}")

class Spinner:
    """A terminal spinner animation for long-running tasks"""
    
    def __init__(self, message="Loading..."):
        """Initialize the spinner with a message"""
        self.message = message
        self.is_running = False
        self.spinner_thread = None
        self.spinner_chars = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']
        self.spinner_idx = 0
    
    def _spin(self):
        """Internal method to display the spinning animation"""
        while self.is_running:
            sys.stdout.write(f"\r{Fore.CYAN}{self.spinner_chars[self.spinner_idx]} {self.message}{Style.RESET_ALL}")
            sys.stdout.flush()
            self.spinner_idx = (self.spinner_idx + 1) % len(self.spinner_chars)
            time.sleep(0.1)
    
    def __enter__(self):
        """Start the spinner when entering the context"""
        self.is_running = True
        self.spinner_thread = threading.Thread(target=self._spin)
        self.spinner_thread.daemon = True
        self.spinner_thread.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop the spinner when exiting the context"""
        self.is_running = False
        if self.spinner_thread:
            self.spinner_thread.join()
        sys.stdout.write('\r' + ' ' * (len(self.message) + 10) + '\r')
        sys.stdout.flush()