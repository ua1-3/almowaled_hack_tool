import sys
import shutil
import subprocess
import json
import argparse
import socket

REQUIRED_SYS_TOOLS = ["nmap", "curl"]
REQUIRED_PYTHON_LIBS = ["requests", "colorama"]

def check_and_install_dependencies():
    print("[*] Checking environment dependencies...")

    for tool in REQUIRED_SYS_TOOLS:
        if shutil.which(tool) is None:
            print(f"[!] System tool '{tool}' not found. Installing via Bash...")
            try:
                cmd = f"sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {tool}"
                subprocess.run(cmd, shell=True, check=True)
                print(f"[+] '{tool}' installed successfully!")
            except subprocess.CalledProcessError:
                print(f"[-] Error installing '{tool}'. Make sure you run the script with sudo.")
        else:
            pass

    for lib in REQUIRED_PYTHON_LIBS:
        try:
            __import__(lib)
        except ImportError:
            print(f"[!] Python library '{lib}' missing. Installing...")
            subprocess.run([sys.executable, "-m", "pip", "install", lib], check=True)

check_and_install_dependencies()

print("\n[+] Environment is ready! Starting scanner...")

import requests
from colorama import fore, Style

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", required=True, help="Target URL")
args = parser.parse_args()

url = args.url