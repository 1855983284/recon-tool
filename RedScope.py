
import argparse
import socket
import whois as whois_lib
import dns.resolver
import requests
import json
import datetime
import subprocess
from bs4 import BeautifulSoup

# -------------------- LOGGER --------------------
def log(msg):
    print(f"[+] {msg}")

# -------------------- WHOIS --------------------
def run_whois(domain):
    try:
        w = whois_lib.whois(domain)
        return str(w)
    except Exception as e:
        return f"WHOIS Error: {e}"

# -------------------- DNS ENUM --------------------
def run_dns(domain):
    records = {}
    for record_type in ["A", "MX", "TXT", "NS"]:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [rdata.to_text() for rdata in answers]
        except:
            records[record_type] = ["No records found"]
    return records

# -------------------- SUBDOMAIN ENUM --------------------
def run_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url)
        subdomains = set()
        for entry in r.json():
            name_value = entry['name_value']
            for sub in name_value.split('\n'):
                subdomains.add(sub.strip())
        return list(subdomains)
    except:
        return ["Subdomain enumeration failed"]

# -------------------- PORT SCANNER --------------------
def run_ports(domain, full_scan=False):
    open_ports = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]
    port_range = range(1, 65536) if full_scan else common_ports
    for port in port_range:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((domain, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except:
            continue
    return open_ports

# -------------------- BANNER GRABBER --------------------
def run_banner(domain, ports):
    banners = []
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((domain, port))

            if port in [80, 8080]:
                http_request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
                s.send(http_request.encode())
                banner = s.recv(1024).decode(errors='ignore').strip()
            elif port in [21, 23, 25]:  # FTP, Telnet, SMTP
                banner = s.recv(1024).decode(errors='ignore').strip()
            elif port == 443:
                banner = "Encrypted service (HTTPS) – Skipped"
            else:
                banner = "No banner or unsupported protocol"

            banners.append(f"Port {port}: {banner if banner else 'No banner returned'}")
            s.close()
        except:
            banners.append(f"Port {port}: No banner")
    return banners

# -------------------- TECH DETECT --------------------
def run_tech(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=5)
        tech = []
        headers = r.headers
        if 'X-Powered-By' in headers:
            tech.append(f"X-Powered-By: {headers['X-Powered-By']}")
        soup = BeautifulSoup(r.text, 'html.parser')
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator:
            tech.append("Generator: " + generator['content'])
        return tech if tech else ["No technologies detected"]
    except:
        return ["Technology detection failed"]

# -------------------- REPORT GENERATOR --------------------
def generate_report(domain, data, format='txt'):
    now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reports/report_{domain}_{now}.{format}"

    import os
    os.makedirs("reports", exist_ok=True)

    if format == 'txt':
        with open(filename, 'w') as f:
            for section, content in data.items():
                f.write(f"\n--- {section.upper()} ---\n")
                if isinstance(content, dict):
                    for k, v in content.items():
                        f.write(f"[{k}]\n")
                        for item in v:
                            f.write(f"  - {item}\n")
                elif isinstance(content, list):
                    for item in content:
                        f.write(f"- {item}\n")
                else:
                    f.write(str(content) + "\n")
    elif format == 'html':
        with open(filename, 'w') as f:
            f.write("<html><head><title>Recon Report</title></head><body>")
            f.write(f"<h1>Report for {domain}</h1>")
            for section, content in data.items():
                f.write(f"<h2>{section.upper()}</h2><ul>")
                if isinstance(content, dict):
                    for k, v in content.items():
                        f.write(f"<li><strong>{k}</strong><ul>")
                        for item in v:
                            f.write(f"<li>{item}</li>")
                        f.write("</ul></li>")
                elif isinstance(content, list):
                    for item in content:
                        f.write(f"<li>{item}</li>")
                else:
                    f.write(f"<li>{str(content)}</li>")
                f.write("</ul>")
            f.write("</body></html>")

    log(f"Report saved as {filename}")

# -------------------- MAIN --------------------
def main():
    parser = argparse.ArgumentParser(description="RedScope - Offensive Recon Toolkit")
    parser.add_argument('--domain', required=True, help='Target domain (e.g., example.com)')
    parser.add_argument('--whois', action='store_true', help='Perform WHOIS lookup')
    parser.add_argument('--dns', action='store_true', help='Enumerate DNS records')
    parser.add_argument('--subdomains', action='store_true', help='Find subdomains')
    parser.add_argument('--ports', action='store_true', help='Perform port scanning')
    parser.add_argument('--full', action='store_true', help='Full port scan (1-65535)')
    parser.add_argument('--banner', action='store_true', help='Grab service banners')
    parser.add_argument('--tech', action='store_true', help='Detect web technologies')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--report', choices=['txt', 'html'], default='txt', help='Report format')

    args = parser.parse_args()
    domain = args.domain
    results = {}

    log(f"Starting recon on {domain}...")

    if args.whois:
        log("Running WHOIS...")
        results['whois'] = run_whois(domain)

    if args.dns:
        log("Running DNS enumeration...")
        results['dns'] = run_dns(domain)

    if args.subdomains:
        log("Running subdomain enumeration...")
        results['subdomains'] = run_subdomains(domain)

    if args.ports:
        if args.full:
            log("Running full port scan (1-65535)...")
            open_ports = run_ports(domain, full_scan=True)
        else:
            log("Running quick scan (common ports)...")
            open_ports = run_ports(domain)
        results['ports'] = open_ports

    if args.banner and 'ports' in results:
        log("Running banner grabbing...")
        results['banners'] = run_banner(domain, results['ports'])

    if args.tech:
        log("Running technology detection...")
        results['tech'] = run_tech(domain)

    generate_report(domain, results, args.report)
    log("Recon finished.")

if __name__ == '__main__':
    main()
