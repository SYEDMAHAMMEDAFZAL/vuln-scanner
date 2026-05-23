#!/usr/bin/env python3
"""
Automated Vulnerability Assessment Tool
Author: Syed Mahammedafzal
GitHub: github.com/SYEDMAHAMMEDAFZAL
"""
import nmap
import datetime
import sys
import os
from report_gen import generate_report

def banner():
    print("""
\033[92m
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
\033[0m
    \033[94mAutomated Vulnerability Assessment Tool  |  by Afzal\033[0m
    \033[90m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
    """)

def get_target():
    if len(sys.argv) > 1:
        return sys.argv[1]
    target = input("\033[93m[?] Enter Target IP or Range (e.g. 192.168.1.1 or 192.168.1.0/24): \033[0m")
    return target.strip()

def run_scan(target):
    print(f"\n\033[92m[+] Starting scan on: {target}\033[0m")
    print("\033[90m[*] This may take a few minutes...\033[0m\n")

    nm = nmap.PortScanner()

    # Phase 1: Fast port discovery
    print("\033[94m[1/3] Discovering open ports...\033[0m")
    nm.scan(hosts=target, arguments='-T4 -F')

    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append(str(port))

    if not open_ports:
        print("\033[91m[-] No open ports found.\033[0m")
        return None

    port_str = ','.join(open_ports)
    print(f"\033[92m[+] Found open ports: {port_str}\033[0m")

    # Phase 2: Service & version detection
    print("\033[94m[2/3] Detecting services and versions...\033[0m")
    nm.scan(hosts=target, arguments=f'-sV -sC -p {port_str}')

    # Phase 3: Vuln scripts on open ports
    print("\033[94m[3/3] Running vulnerability scripts...\033[0m")
    nm.scan(hosts=target, arguments=f'--script vuln -p {port_str}')

    return nm

def parse_results(nm, target):
    results = {
        'target': target,
        'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'hosts': []
    }

    for host in nm.all_hosts():
        host_data = {
            'ip': host,
            'hostname': nm[host].hostname() or 'N/A',
            'state': nm[host].state(),
            'os_guess': 'N/A',
            'ports': []
        }

        # OS detection if available
        if 'osmatch' in nm[host]:
            if nm[host]['osmatch']:
                host_data['os_guess'] = nm[host]['osmatch'][0].get('name', 'N/A')

        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                port_info = nm[host][proto][port]
                if port_info['state'] != 'open':
                    continue

                vulns = []
                if 'script' in port_info:
                    for script_name, output in port_info['script'].items():
                        if 'vuln' in script_name.lower() or 'CVE' in output:
                            vulns.append({
                                'script': script_name,
                                'output': output[:300]  # trim long outputs
                            })

                host_data['ports'].append({
                    'port': port,
                    'proto': proto,
                    'state': port_info['state'],
                    'service': port_info.get('name', 'unknown'),
                    'version': f"{port_info.get('product','')} {port_info.get('version','')}".strip() or 'N/A',
                    'vulns': vulns
                })

        results['hosts'].append(host_data)

    return results

def print_summary(results):
    print("\n\033[92m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
    print("\033[92m           SCAN SUMMARY\033[0m")
    print("\033[92m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")

    total_ports = 0
    total_vulns = 0

    for host in results['hosts']:
        print(f"\n\033[94m[HOST]\033[0m {host['ip']}  ({host['hostname']})")
        print(f"  State : {host['state']}")
        print(f"  OS    : {host['os_guess']}")
        print(f"  Ports : {len(host['ports'])} open\n")

        for p in host['ports']:
            vuln_tag = f"\033[91m  ⚠ {len(p['vulns'])} vuln(s)\033[0m" if p['vulns'] else ""
            print(f"  \033[93m{p['port']}/{p['proto']}\033[0m  {p['service']}  {p['version']}{vuln_tag}")
            total_ports += 1
            total_vulns += len(p['vulns'])

    print(f"\n\033[90mTotal open ports : {total_ports}")
    print(f"Total vulns found: {total_vulns}\033[0m")

def main():
    banner()

    # Warn user
    print("\033[91m[!] WARNING: Only scan systems you own or have permission to test.\033[0m")
    print("\033[91m[!] Unauthorized scanning is illegal.\033[0m\n")

    target = get_target()

    if not target:
        print("No target provided. Exiting.")
        sys.exit(1)

    nm = run_scan(target)

    if nm is None:
        print("Scan returned no results.")
        sys.exit(1)

    results = parse_results(nm, target)
    print_summary(results)

    # Generate PDF
    print("\n\033[94m[+] Generating PDF report...\033[0m")
    report_path = generate_report(results)
    print(f"\033[92m[✓] Report saved: {report_path}\033[0m")

if __name__ == '__main__':
    main()
