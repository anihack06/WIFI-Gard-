
WiFiGuard Auditor
WiFiGuard Auditor is an open-source command line tool for Termux and Linux systems that helps you passively review nearby Wi-Fi networks. It scans visible access points, highlights common security misconfigurations, audits an owner-known Wi-Fi passphrase against a local wordlist, and saves reports in TXT or JSON format.

Features
Scan nearby Wi-Fi networks with numbered results
Select a network interactively or by CLI option
Show SSID, BSSID, signal strength, channel, encryption type, and hidden SSID status
Flag open networks, weak legacy encryption, default SSID names, WPS exposure, and weak-signal zones
Audit an owner-known passphrase with a progress bar
Export reports in TXT and JSON
Run on Termux, Kali Linux, Ubuntu, and other Linux systems
Safety Notice
WiFiGuard Auditor is intended for defensive and owner-authorized security reviews only.

It performs passive discovery using local tools such as termux-wifi-scaninfo, nmcli, and iwlist
It does not capture handshakes, disconnect users, or perform live cracking against nearby networks
The passphrase audit works only with a password the network owner already knows and enters locally
Supported Backends
WiFiGuard Auditor automatically picks the first available backend in this order:

termux-wifi-scaninfo
nmcli
iwlist
Requirements
Python 3.10+
A supported Wi-Fi scan backend:
termux-wifi-scaninfo for Termux
nmcli for most desktop Linux systems
iwlist as a fallback on Linux
A wireless adapter recognized by the system
Installation
Replace the GitHub URL below with your real repository URL after publishing:

git clone https://github.com/<your-username>/wifiguard-auditor.git
cd wifiguard-auditor
Termux Installation
Install required packages:

pkg update && pkg upgrade
pkg install git python termux-api
Install the companion Android app:

Install the Termux:API app from F-Droid or another trusted source
Grant Termux location permission in Android settings
Clone and install:

git clone 
cd wifiguard-auditor
pip install .
Run:

wifiguard scan
Kali Linux Installation
Install system dependencies:

sudo apt update
sudo apt install -y git python3 python3-pip python3-venv network-manager wireless-tools iw
Clone the repository:

git clone https://github.com/<your-username>/wifiguard-auditor.git
cd wifiguard-auditor
Optional virtual environment:

python3 -m venv .venv
source .venv/bin/activate
Install the tool:

python3 -m pip install .
Run:

wifiguard scan
If you want to force the fallback scanner:

sudo wifiguard scan --backend iwlist --interface wlan0
Ubuntu Installation
Install system dependencies:

sudo apt update
sudo apt install -y git python3 python3-pip python3-venv network-manager wireless-tools iw
Clone the repository:

git clone https://github.com/<your-username>/wifiguard-auditor.git
cd wifiguard-auditor
Optional virtual environment:

python3 -m venv .venv
source .venv/bin/activate
Install the tool:

python3 -m pip install .
Run:

wifiguard scan
Other Linux Systems
If your distribution is not listed above, install:

git
python3
python3-pip
one supported Wi-Fi scanner backend
Then:

git clone https://github.com/<your-username>/wifiguard-auditor.git
cd wifiguard-auditor
python3 -m pip install .
Quick Start
Scan nearby networks:

wifiguard scan
Scan and save a TXT report:

wifiguard scan --report reports/audit.txt
Scan and save a JSON report:

wifiguard scan --report reports/audit.json --report-format json
Audit an owner-known Wi-Fi passphrase:

wifiguard scan --prompt-password
Run only the passphrase audit:

wifiguard audit-passphrase --prompt-password
How To Use
1. Scan Nearby Wi-Fi Networks
wifiguard scan
The tool lists nearby access points with:

number
SSID
BSSID
signal level
channel
encryption type
hidden status
WPS status
number of findings
2. Select a Network
Interactive selection:

wifiguard scan
Non-interactive selection:

wifiguard scan --select 2 --non-interactive
3. Audit Your Own Wi-Fi Password
Prompt for the passphrase:

wifiguard scan --prompt-password
Provide the passphrase directly:

wifiguard audit-passphrase --known-password "MySecurePass123!"
4. Use a Custom Wordlist
wifiguard scan --wordlist ./my-wordlist.txt --prompt-password
Or:

wifiguard audit-passphrase --wordlist ./my-wordlist.txt --prompt-password
5. Save Reports
Save a TXT report:

wifiguard scan --report reports/home-audit.txt
Save a JSON report:

wifiguard scan --report reports/home-audit.json --report-format json
6. Choose a Specific Backend
Use nmcli:

wifiguard scan --backend nmcli
Use iwlist:

sudo wifiguard scan --backend iwlist --interface wlan0
Default Wordlist Behavior
When you run a passphrase audit, WiFiGuard Auditor resolves the wordlist in this order:

--wordlist <path> if you provide one
./password-wordlist.txt in the current working directory
password-wordlist.txt in the repository root
no wordlist, which means the tool falls back to strength-only evaluation
If you run the tool directly from this repository checkout, the included password-wordlist.txt is used automatically when available.

Example Workflow
Run wifiguard scan
Choose the network you want to review
Read the security details and findings
If you own that network, run the passphrase audit
Export the results as TXT or JSON
Development
Install development dependencies:

python3 -m pip install -e .[dev]
Run tests:

pytest
Troubleshooting
If no networks appear, make sure Wi-Fi is enabled and your adapter is supported
On Termux, verify that the Termux:API app is installed and location permission is granted
On Linux, iwlist may require sudo or additional wireless permissions
If wifiguard is not found after installation, run it with python3 -m wifiguard_auditor
If you installed the project outside the repository checkout, pass your own file with --wordlist or place password-wordlist.txt in the working directory
Limitations
Wireless scan results depend on hardware, drivers, and operating system support
Some backends do not expose full WPS or signal details
Hidden SSID detection depends on what the local scan backend reports
iwlist output differs slightly between distributions and adapters
License
MIT
