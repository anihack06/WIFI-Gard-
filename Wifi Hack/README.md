# WiFiGuard Auditor

WiFiGuard Auditor is a colorful, open-source command line tool for passive Wi-Fi security reviews on Termux, Kali Linux, Ubuntu, and other Linux systems. It scans nearby access points, summarizes security settings, highlights common misconfigurations, and can evaluate an owner-supplied Wi-Fi passphrase against a repo-default or user-supplied wordlist without attempting live attacks against a target network.

## Features

- Scan nearby Wi-Fi networks and list them with numbered output
- Select a network interactively or by CLI flag
- Show SSID, BSSID, signal strength, channel, encryption type, and hidden SSID status
- Flag common issues such as open networks, WEP/WPA legacy modes, WPS exposure, default SSID naming, and weak-signal coverage areas
- Audit a known Wi-Fi passphrase against a local wordlist with a progress bar
- Export reports in TXT or JSON
- Use a modular Python codebase with separate scanning, analysis, reporting, and UI layers

## Safety Model

WiFiGuard Auditor is designed for defensive and owner-authorized use.

- It performs passive discovery using local platform tools such as `nmcli`, `iwlist`, or `termux-wifi-scaninfo`
- It does not capture handshakes, deauthenticate clients, or attempt live password guessing against nearby networks
- The passphrase audit works only with a password the owner already knows and supplies to the tool

## Supported Backends

The tool automatically picks the best available scanner backend in this order:

1. `termux-wifi-scaninfo`
2. `nmcli`
3. `iwlist`

Notes:

- On Termux, Wi-Fi scanning requires the Termux:API app and Android location permission
- On Ubuntu and Kali, `nmcli` is the best default when NetworkManager is present
- `iwlist` can provide useful fallback coverage on minimal systems, though some distributions require elevated privileges for scans
- WPS detection is best-effort and depends on what the local platform scanner exposes

## Installation

### Termux

Install the requirements:

```bash
pkg update && pkg upgrade
pkg install python termux-api
```

Install the companion Android app:

1. Install the `Termux:API` app from F-Droid or another trusted source
2. Open Android app settings and grant Termux location permission

Install WiFiGuard Auditor:

```bash
pip install .
```

Run it:

```bash
wifiguard scan
```

### Kali Linux

Install system packages:

```bash
sudo apt update
sudo apt install -y python3 python3-pip network-manager wireless-tools iw
```

Install the tool:

```bash
python3 -m pip install .
```

Run it:

```bash
wifiguard scan
```

If you want the fallback backend explicitly:

```bash
sudo wifiguard scan --backend iwlist --interface wlan0
```

### Ubuntu

Install system packages:

```bash
sudo apt update
sudo apt install -y python3 python3-pip network-manager wireless-tools iw
```

Install the tool:

```bash
python3 -m pip install .
```

Run it:

```bash
wifiguard scan
```

### Other Linux Systems

Make sure you have:

- Python 3.10+
- One supported Wi-Fi scan backend:
  - `nmcli`
  - `iwlist`
- A wireless interface recognized by the system

Then install the project:

```bash
python3 -m pip install .
```

## Usage

### Basic Scan

```bash
wifiguard scan
```

### Force a Backend

```bash
wifiguard scan --backend nmcli
```

### Select a Network Non-Interactively

```bash
wifiguard scan --select 2 --non-interactive
```

### Save a JSON Report

```bash
wifiguard scan --report reports/office-audit.json --report-format json
```

### Save a TXT Report

```bash
wifiguard scan --report reports/office-audit.txt
```

### Audit an Owner-Known Passphrase Against a Wordlist

```bash
wifiguard scan --prompt-password
```

Or:

```bash
wifiguard audit-passphrase --prompt-password
```

When you run the tool from the project checkout, it automatically uses `./password-wordlist.txt` if present and otherwise falls back to the repo-root `password-wordlist.txt`.

### Use a Custom Wordlist

```bash
wifiguard scan --wordlist ./my-audit-list.txt --prompt-password
```

Or:

```bash
wifiguard audit-passphrase --wordlist ./my-audit-list.txt --prompt-password
```

### Target a Specific Interface

```bash
wifiguard scan --backend iwlist --interface wlan0
```

## Example Workflow

1. Run `wifiguard scan`
2. Choose a numbered network from the table
3. Review the security breakdown and findings
4. If you own that network, run a passphrase audit with your known password; from the repo checkout the default `password-wordlist.txt` is used automatically
5. Save a TXT or JSON report for records

## Report Formats

### TXT

Human-readable summary with:

- selected network details
- misconfiguration findings
- optional passphrase audit results
- a compact list of all discovered networks

### JSON

Machine-friendly export suitable for:

- dashboards
- automation
- change tracking
- evidence records

## Development

Install with development dependencies:

```bash
python3 -m pip install -e .[dev]
```

Run tests:

```bash
pytest
```

If you install the project outside this repository checkout, pass your own list with `--wordlist` unless you also copy `password-wordlist.txt` into your working directory.

## Project Layout

```text
wifiguard_auditor/
  __init__.py
  __main__.py
  analysis.py
  audit.py
  cli.py
  models.py
  reporting.py
  scanner.py
  ui.py
  utils.py
tests/
  test_analysis.py
  test_audit.py
  test_utils.py
```

## Limitations

- Wireless scanning behavior varies across Android devices, Linux drivers, and distribution packaging
- Some backends do not expose raw dBm, WPS state, or every advanced RSN detail
- Hidden SSID detection is based on what the platform scan reports
- `iwlist` may require root or additional capabilities on some systems

## License

MIT
