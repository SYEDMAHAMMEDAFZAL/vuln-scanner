# 🔍 Automated Vulnerability Assessment Tool

> Python-based network scanner that automates port discovery, 
> service detection, vulnerability identification and PDF report generation.

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Nmap](https://img.shields.io/badge/Tool-Nmap-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## What it does
- Discovers all open ports on a target
- Identifies running services and versions
- Runs vulnerability scripts (NSE)
- Auto-generates a professional PDF report

## Requirements
- Kali Linux or any Linux with Nmap
- Python 3.6+
- Nmap: `sudo apt install nmap`

## Installation
git clone https://github.com/SYEDMAHAMMEDAFZAL/vuln-scanner.git
cd vuln-scanner
pip3 install -r requirements.txt --break-system-packages

## Usage
sudo python3 scanner.py 192.168.1.1
sudo python3 scanner.py 192.168.1.0/24

## Output
PDF report saved to reports/ folder automatically.

## Author
S. Md. Afzal
github.com/SYEDMAHAMMEDAFZAL
linkedin.com/in/syed-mahammed-afzal

## Legal
Only scan systems you own or have written permission to test.
