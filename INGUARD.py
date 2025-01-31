#!/usr/bin/env python3
import os
import re
import sys
import time
import subprocess
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

# ASCII Art
ASCII_ART = f"""
{Fore.CYAN}
  ██╗███╗   ██╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
  ██║████╗  ██║    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██║██╔██╗ ██║    ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║██║╚██╗██║    ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║██║ ╚████║    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝╚═╝  ╚═══╝     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
{Fore.YELLOW}
         [Code Injection Detector & EDR Simulator]
{Style.RESET_ALL}
"""

# Configuration
VULNERABLE_ENDPOINT = "http://localhost:5000/submit"
MALICIOUS_PAYLOADS = [
    "<script>alert('XSS Demo');</script>",
    "'; DROP TABLE users;--",
    "|| ls -la /etc/passwd"
]

def print_banner():
    """Display ASCII art and menu"""
    print(ASCII_ART)
    print(f"{Fore.GREEN}[1] Start Injection Detection")
    print(f"[2] Simulate EDR Bypass (Linux LD_PRELOAD)")
    print(f"[3] Launch Web App Test Environment")
    print(f"[4] Exit{Style.RESET_ALL}")

def detect_injection(payload):
    """Basic code injection detection using regex"""
    patterns = [
        r"(<script>.*?</script>)",  # XSS
        r"(\b(DROP|DELETE|INSERT)\b)",  # SQLi
        r"(;.*?\\w+.*?)",  # Command injection
    ]
    for pattern in patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    return False

def simulate_edr_bypass():
    """Linux version of preloading-based bypass"""
    print(f"\n{Fore.YELLOW}[*] Compiling malicious shared object...")
    with open("malicious_lib.c", "w") as f:
        f.write("""#include <stdio.h>
#include <unistd.h>
__attribute__((constructor)) void init() {
    printf("[+] Malicious library loaded!\\n");
    // Add hook bypass logic here
}""")
    
    subprocess.run(["gcc", "-shared", "-fPIC", "-o", "malicious.so", "malicious_lib.c"])
    print(f"{Fore.GREEN}[+] Simulating EDR bypass via LD_PRELOAD:")
    os.environ["LD_PRELOAD"] = "./malicious.so"
    subprocess.run(["ls"])  # This will trigger our malicious library

def web_app_test_environment():
    """Run vulnerable Flask web app for testing"""
    print(f"\n{Fore.CYAN}[*] Starting vulnerable web app on port 5000...")
    from flask import Flask, request
    app = Flask(__name__)

    @app.route('/submit', methods=['POST'])
    def submit():
        user_input = request.form.get('input')
        if detect_injection(user_input):
            return f"{Fore.RED}Blocked malicious payload!{Style.RESET_ALL}"
        return "Submission successful!"

    app.run(debug=True)

def main():
    while True:
        print_banner()
        choice = input(f"\n{Fore.BLUE}Select an option: {Style.RESET_ALL}")

        if choice == "1":
            payload = input("Enter payload to test: ")
            if detect_injection(payload):
                print(f"{Fore.RED}🚨 Malicious injection detected!{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}✅ Payload appears safe{Style.RESET_ALL}")

        elif choice == "2":
            simulate_edr_bypass()

        elif choice == "3":
            web_app_test_environment()

        elif choice == "4":
            sys.exit(0)

if __name__ == "__main__":
    main()