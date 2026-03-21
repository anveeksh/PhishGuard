"""
utils/banner.py — PhishGuard UI Banner & Color Helpers
Author: Anveeksh Rao | github.com/anveeksh
"""
from pyfiglet import figlet_format
from colorama import Fore, Style, init
init(autoreset=True)

def print_banner():
    print(Fore.GREEN + figlet_format("PhishGuard", font="slant"))
    print(Fore.YELLOW + "  " + "="*52)
    print(Fore.CYAN   + "   AI-Powered Phishing URL Detection System")
    print(Fore.GREEN  + "   By Anveeksh Rao | github.com/anveeksh")
    print(Fore.RED    + "   MS Cybersecurity | Northeastern University")
    print(Fore.YELLOW + "  " + "="*52)
    print(Style.RESET_ALL)

def print_menu():
    print(Fore.YELLOW + "\n  ╔══════════════════════════════════════════════════╗")
    print(Fore.YELLOW +   "  ║         PhishGuard v1.0 — Main Menu              ║")
    print(Fore.YELLOW +   "  ╠══════════════════════════════════════════════════╣")
    print(Fore.CYAN   +   "  ║  [1]  Download & Prepare Dataset                ║")
    print(Fore.CYAN   +   "  ║  [2]  Train All Models                          ║")
    print(Fore.CYAN   +   "  ║  [3]  Scan Single URL                           ║")
    print(Fore.CYAN   +   "  ║  [4]  Batch Scan from File                      ║")
    print(Fore.CYAN   +   "  ║  [5]  Compare Model Performance                 ║")
    print(Fore.CYAN   +   "  ║  [6]  Generate Research Report (PDF)            ║")
    print(Fore.RED    +   "  ║  [0]  Exit                                      ║")
    print(Fore.YELLOW +   "  ╚══════════════════════════════════════════════════╝")

def print_module_header(title):
    print(Fore.GREEN + f"\n  ══════════════════════════════════════════════════")
    print(Fore.GREEN + f"   {title}")
    print(Fore.GREEN + f"  ══════════════════════════════════════════════════\n")

def success(msg): print(Fore.GREEN  + f"  [✔] {msg}" + Style.RESET_ALL)
def error(msg):   print(Fore.RED    + f"  [✘] {msg}" + Style.RESET_ALL)
def info(msg):    print(Fore.CYAN   + f"  [*] {msg}" + Style.RESET_ALL)
def warn(msg):    print(Fore.YELLOW + f"  [!] {msg}" + Style.RESET_ALL)
def phish(msg):   print(Fore.RED    + Style.BRIGHT + f"  [PHISHING] {msg}" + Style.RESET_ALL)
def legit(msg):   print(Fore.GREEN  + Style.BRIGHT + f"  [LEGIT   ] {msg}" + Style.RESET_ALL)
