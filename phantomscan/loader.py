import time
from colorama import Fore, init

init(autoreset=True)

def boot_sequence():
    steps = [
        "[+] Loading AI Engine...",
        "[+] Initializing Recon Module...",
        "[+] Activating Exploit Analyzer...",
        "[+] Connecting to Threat Intelligence...",
        "[+] PhantomScan Ready."
    ]

    for step in steps:
        print(Fore.GREEN + step)
        time.sleep(0.7)
