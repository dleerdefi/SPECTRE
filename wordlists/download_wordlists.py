#!/usr/bin/env python3
"""
Download and generate WiFi-specific wordlists from various sources
"""

import os
import requests
import hashlib
from pathlib import Path
from typing import List, Set
import itertools
import string

DEFAULT_WORDLIST_DIR = Path(__file__).resolve().parent

class WordlistManager:
    def __init__(self, base_dir=None):
        if base_dir is None:
            base_dir = DEFAULT_WORDLIST_DIR
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)

    def download_from_url(self, url: str, filename: str, category: str = "targeted"):
        """Download wordlist from URL"""
        target_path = self.base_dir / category / filename
        target_path.parent.mkdir(exist_ok=True)

        try:
            print(f"Downloading {filename} from {url[:50]}...")
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            with open(target_path, 'wb') as f:
                f.write(response.content)

            lines = len(response.content.decode('utf-8', errors='ignore').splitlines())
            print(f"✓ Downloaded {filename}: {lines} passwords")
            return True
        except Exception as e:
            print(f"✗ Failed to download {filename}: {e}")
            return False

    def generate_default_passwords(self):
        """Generate common default router passwords"""
        print("\nGenerating default router passwords...")

        defaults = []

        # Common router default passwords
        router_defaults = [
            "admin", "password", "1234", "12345", "123456", "1234567", "12345678",
            "123456789", "1234567890", "admin123", "admin1234", "password123",
            "password1", "password1234", "pass", "passw0rd", "default",
            "guest", "user", "root", "toor", "public", "private",
            "changeme", "change_me", "letmein", "access", "secret",
            "cisco", "cisco123", "linksys", "netgear", "dlink", "belkin",
            "asus", "tplink", "router", "wireless", "wifi", "internet",
            "network", "home", "setup", "test", "blank", "",
            # ISP defaults
            "attadmin", "verizon", "comcast", "xfinity", "spectrum",
            "frontier", "centurylink", "cox", "optimum", "mediacom"
        ]

        # Manufacturer-specific patterns
        manufacturers = {
            "netgear": ["netgear1", "routerlogin", "Netgear1", "NETGEAR"],
            "linksys": ["admin", "linksys", "cisco", "Cisco123"],
            "dlink": ["admin", "dlink", "D-Link", "blank"],
            "tplink": ["admin", "tplink", "TP-Link", "admin123"],
            "asus": ["admin", "asus", "router", "RT-AC68U"],
            "belkin": ["admin", "belkin", "belkin.xxx", "belkin123"],
            "cisco": ["cisco", "cisco123", "Cisco123", "admin"],
            "ubiquiti": ["ubnt", "admin", "ui", "unifi"],
            "mikrotik": ["admin", "", "mikrotik", "RouterOS"],
            "huawei": ["admin", "huawei", "huawei123", "user"]
        }

        defaults.extend(router_defaults)
        for brand, passwords in manufacturers.items():
            defaults.extend(passwords)

        # Remove duplicates and empty strings
        defaults = list(set([p for p in defaults if p]))

        output_path = self.base_dir / "default-passwords" / "router-defaults.txt"
        output_path.parent.mkdir(exist_ok=True)

        with open(output_path, 'w') as f:
            for pwd in sorted(defaults):
                f.write(pwd + '\n')

        print(f"✓ Generated {len(defaults)} default passwords")
        return defaults

    def generate_isp_patterns(self):
        """Generate ISP-specific password patterns"""
        print("\nGenerating ISP-specific patterns...")

        patterns = []

        # AT&T U-verse pattern: 10 digits
        for _ in range(100):  # Sample set
            patterns.append(''.join([str(i) for i in range(10)]))

        # Verizon FiOS pattern: [word][3-4 digits]
        verizon_words = ["quick", "brown", "lazy", "happy", "sunny", "green", "blue", "red"]
        for word in verizon_words:
            for num in range(100, 1000, 111):
                patterns.append(f"{word}{num}")

        # Xfinity pattern: [adjective][noun][3 digits]
        adjectives = ["fast", "quick", "slow", "big", "small", "red", "blue", "green"]
        nouns = ["cat", "dog", "fox", "net", "web", "wifi", "link", "box"]
        for adj in adjectives[:4]:
            for noun in nouns[:4]:
                for num in range(100, 300, 50):
                    patterns.append(f"{adj}{noun}{num}")

        # Spectrum pattern: [word][word][digits]
        spectrum_words = ["secure", "home", "net", "wifi", "fast", "speed"]
        for w1 in spectrum_words[:3]:
            for w2 in spectrum_words[3:]:
                patterns.append(f"{w1}{w2}2024")

        output_path = self.base_dir / "isp-specific" / "isp-patterns.txt"
        output_path.parent.mkdir(exist_ok=True)

        with open(output_path, 'w') as f:
            for pattern in patterns:
                f.write(pattern + '\n')

        print(f"✓ Generated {len(patterns)} ISP patterns")
        return patterns

    def generate_common_wifi_passwords(self):
        """Generate common WiFi password patterns"""
        print("\nGenerating common WiFi passwords...")

        passwords = []

        # Common patterns
        base_words = ["wifi", "internet", "network", "wireless", "router", "home", "guest"]

        # Add year variations
        for word in base_words:
            for year in range(2020, 2025):
                passwords.append(f"{word}{year}")
                passwords.append(f"{word.capitalize()}{year}")
                passwords.append(f"{word}@{year}")

        # Add number patterns
        for word in base_words:
            for num in ["123", "1234", "12345", "123456", "111", "000", "777", "999"]:
                passwords.append(f"{word}{num}")
                passwords.append(f"{num}{word}")

        # Keyboard walks
        keyboard_walks = [
            "qwerty", "qwerty123", "qwertyuiop", "123456789", "987654321",
            "asdfghjkl", "zxcvbnm", "1qaz2wsx", "qazwsx", "qazwsxedc",
            "1234qwer", "qwer1234", "abcd1234", "1234abcd"
        ]
        passwords.extend(keyboard_walks)

        # Common substitutions
        leet_speak = {
            "password": ["p@ssw0rd", "p@ssword", "passw0rd", "p455w0rd"],
            "admin": ["@dm1n", "adm!n", "@dmin", "4dm1n"],
            "wifi": ["w1f1", "w!f!", "w1fi", "wifi!"],
            "internet": ["1nternet", "!nternet", "int3rn3t", "intern3t"],
            "network": ["n3tw0rk", "netw0rk", "n3twork", "ne7work"]
        }

        for original, variations in leet_speak.items():
            passwords.extend(variations)

        # Phone numbers pattern (10 digits)
        sample_phones = [
            "5551234567", "1234567890", "9876543210", "1112223333",
            "5555555555", "1231231234", "9999999999", "8888888888"
        ]
        passwords.extend(sample_phones)

        # Remove duplicates
        passwords = list(set(passwords))

        output_path = self.base_dir / "targeted" / "common-wifi.txt"
        output_path.parent.mkdir(exist_ok=True)

        with open(output_path, 'w') as f:
            for pwd in sorted(passwords):
                f.write(pwd + '\n')

        print(f"✓ Generated {len(passwords)} common WiFi passwords")
        return passwords

    def generate_date_based(self):
        """Generate date-based passwords"""
        print("\nGenerating date-based passwords...")

        dates = []

        # Years
        for year in range(2015, 2025):
            dates.append(str(year))
            dates.append(f"password{year}")
            dates.append(f"wifi{year}")
            dates.append(f"admin{year}")

        # Months
        months = ["january", "february", "march", "april", "may", "june",
                 "july", "august", "september", "october", "november", "december"]

        for month in months:
            dates.append(month)
            dates.append(f"{month}2024")
            dates.append(f"{month[:3]}2024")

        # Seasons
        for season in ["spring", "summer", "fall", "autumn", "winter"]:
            dates.append(season)
            dates.append(f"{season}2024")
            dates.append(f"{season}24")

        # Special dates
        dates.extend([
            "01012024", "12252024", "07042024", "10312024",
            "newyear2024", "christmas2024", "july4th", "halloween2024"
        ])

        output_path = self.base_dir / "generated" / "dates-2024.txt"
        output_path.parent.mkdir(exist_ok=True)

        with open(output_path, 'w') as f:
            for date in sorted(set(dates)):
                f.write(date + '\n')

        print(f"✓ Generated {len(dates)} date-based passwords")
        return dates

    def create_top_wifi_list(self):
        """Create curated top WiFi passwords list"""
        print("\nCreating top WiFi passwords list...")

        # Most common WiFi passwords based on research
        top_passwords = [
            # Top 50 most common
            "password", "12345678", "123456789", "12345", "1234567890",
            "password123", "123456", "1234567", "qwerty", "abc123",
            "111111", "123123", "admin", "letmein", "welcome",
            "monkey", "dragon", "master", "sunshine", "princess",
            "password1", "123456789a", "qwertyuiop", "superman", "iloveyou",
            "trustno1", "1234", "000000", "password123!", "guest",
            "default", "changeme", "admin123", "root", "toor",
            "pass", "test", "guest123", "demo", "oracle",
            "secret", "internet", "wireless", "wifi", "network",
            "router", "home", "public", "private", "secure",

            # Common variations
            "Password1", "Password123", "Admin123", "Welcome1", "Letmein1",
            "Password1!", "Admin@123", "Pass@123", "Root@123", "Test@123",

            # ISP defaults (samples)
            "2WIRE123", "ATTXXXXX", "NETGEAR1", "Linksys", "admin1234"
        ]

        output_path = self.base_dir / "targeted" / "top-100-wifi.txt"
        output_path.parent.mkdir(exist_ok=True)

        with open(output_path, 'w') as f:
            for pwd in top_passwords:
                f.write(pwd + '\n')

        print(f"✓ Created top {len(top_passwords)} WiFi passwords list")
        return top_passwords

    def download_github_lists(self):
        """Download wordlists from GitHub repositories"""
        print("\nDownloading wordlists from GitHub...")

        # Known good WiFi wordlist sources
        sources = [
            {
                "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt",
                "filename": "probable-wpa-top4800.txt",
                "category": "targeted"
            },
            {
                "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
                "filename": "common-ssh-passwords.txt",
                "category": "targeted"
            },
            {
                "url": "https://raw.githubusercontent.com/jeanphorn/wordlist/master/router_default_password.txt",
                "filename": "router-default-passwords-github.txt",
                "category": "default-passwords"
            }
        ]

        for source in sources:
            self.download_from_url(source["url"], source["filename"], source["category"])

    def create_summary(self):
        """Create summary of all wordlists"""
        print("\n" + "="*50)
        print("WORDLIST SUMMARY")
        print("="*50)

        total_passwords = 0

        for category in ["default-passwords", "targeted", "generated", "isp-specific"]:
            category_path = self.base_dir / category
            if category_path.exists():
                print(f"\n{category.upper()}:")
                for file in category_path.glob("*.txt"):
                    with open(file, 'r') as f:
                        count = sum(1 for line in f)
                        total_passwords += count
                        print(f"  {file.name}: {count} passwords")

        print(f"\nTOTAL PASSWORDS: {total_passwords}")

        # Create master list
        print("\nCreating master wordlist...")
        master_path = self.base_dir / "master-wifi-wordlist.txt"
        all_passwords = set()

        for category in ["default-passwords", "targeted", "generated", "isp-specific"]:
            category_path = self.base_dir / category
            if category_path.exists():
                for file in category_path.glob("*.txt"):
                    with open(file, 'r') as f:
                        all_passwords.update(line.strip() for line in f if line.strip())

        with open(master_path, 'w') as f:
            for pwd in sorted(all_passwords):
                f.write(pwd + '\n')

        print(f"✓ Master wordlist created: {len(all_passwords)} unique passwords")
        print(f"  Location: {master_path}")

def main():
    manager = WordlistManager()

    print("WiFi Wordlist Generator & Downloader")
    print("="*50)

    # Generate wordlists
    manager.generate_default_passwords()
    manager.generate_isp_patterns()
    manager.generate_common_wifi_passwords()
    manager.generate_date_based()
    manager.create_top_wifi_list()

    # Download from GitHub
    manager.download_github_lists()

    # Create summary
    manager.create_summary()

    print("\n✅ Wordlist generation complete!")

if __name__ == "__main__":
    main()
