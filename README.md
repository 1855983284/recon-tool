# 🕵️‍♂️ RedScope - Offensive Recon Toolkit


- WHOIS Lookup (استعلام معلومات الدومين)
- DNS Enumeration (A, MX, TXT, NS)
- Subdomain Enumeration (من خلال `crt.sh`)
- Port Scanning:
  - 🔹 Quick Scan (بورتات مشهورة)
  - 🔹 Full Scan (من 1 إلى 65535)
- Banner Grabbing
- Web Technology Detection
- TXT/HTML Reporting
- CLI مرن وسهل الاستخدام


```bash
git clone https://github.com/1855983284/recon-tool.git
cd recon-tool


usage:
==>  python RedScope.py --domain (domain-name) --whois --dns --subdomains --ports --banner --tech --report (txt or html) ==> for common ports [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]
==>  python RedScope.py --domain (domain-name) --whois --dns --subdomains --ports --full --banner --tech --report (txt or html) ==> for all ports
