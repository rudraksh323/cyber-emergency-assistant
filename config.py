"""
Cyber Emergency Assistant - configuration and static data.
"""

import platform
from pathlib import Path

APP_NAME = "Cyber Emergency Assistant"
VERSION = "1.1"
OS_NAME = platform.system()
BASE_DIR = Path(__file__).resolve().parent
INCIDENT_DIR = BASE_DIR / "incidents"

HOSTS_FILE = (
    Path(r"C:\Windows\System32\drivers\etc\hosts")
    if OS_NAME == "Windows"
    else Path("/etc/hosts")
)

TRUSTED_DNS = ["1.1.1.1", "9.9.9.9"]

BRANDS = [
    "google", "gmail", "paypal", "amazon", "apple", "microsoft", "netflix",
    "facebook", "instagram", "whatsapp", "linkedin", "sbi", "hdfcbank",
    "icicibank", "paytm", "phonepe", "irctc",
]

BAD_TLDS = {"xyz", "tk", "ml", "ga", "cf", "gq", "top", "click", "loan"}

RED_FLAG_WORDS = [
    "login", "verify", "secure", "account", "update", "confirm", "password",
    "otp", "kyc", "urgent", "suspended", "prize", "winner",
]

GUIDANCE = [
    "Stay calm, if the network is disconnected the attacker cannot reach this machine anymore.",
    "Do not restart the computer yet, running processes can still be useful evidence.",
    "From a different, trusted device, change your email and bank passwords.",
    "Turn on two factor authentication on those accounts while you are at it.",
    "Call your bank if any payment or net banking page was involved.",
    "Run a full scan with an updated antivirus program.",
    "Only reconnect to the internet once that scan comes back clean.",
    "Keep the incident report, it can be attached to a cybercrime complaint.",
]
