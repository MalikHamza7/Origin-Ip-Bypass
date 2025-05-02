#!/usr/bin/env python3
"""
Banner module for displaying the tool's banner
"""

from colorama import Fore, Style

def print_banner():
    """Print the tool's banner"""
    banner = f"""{Fore.CYAN}
 __        __   _     ___       _       _         ___ ___  
 \\ \\      / /__| |__ / _ \\ _ __(_) __ _(_)_ __   |_ _| _ \\ 
  \\ \\ /\\ / / _ \\ '_ \\| | | | '__| |/ _` | | '_ \\   | ||  _/ 
   \\ V  V /  __/ |_) | |_| | |  | | (_| | | | | |  | || |_  
    \\_/\\_/ \\___|_.__/ \\___/|_|  |_|\\__, |_|_| |_| |___|___/ 
                                   |___/                    
    {Fore.GREEN}┌─────────────────────────────────────────────────┐
    │      {Fore.WHITE}Web Origin IP Bypass - Version 1.0{Fore.GREEN}          │
    │                                                     │
    │      {Fore.WHITE}Developed By M Hamza{Fore.GREEN}                        │
    └─────────────────────────────────────────────────────┘{Style.RESET_ALL}
    """
    print(banner)
    print(f"{Fore.YELLOW}A tool to discover origin IPs by bypassing WAF protection{Style.RESET_ALL}\n")