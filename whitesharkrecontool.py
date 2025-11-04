import socket
import subprocess
import dns.resolver
import requests
from bs4 import BeautifulSoup
import nmap
import re
import whois

def get_ip_address(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        print(w)
    except Exception as e:
        print(f"Error fetching WHOIS data: {e}")

def get_geoip_info(ip_address):
    try:
        response = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=10)
        return response.json()
    except Exception as e:
        print(f"Error fetching GeoIP data: {e}")
        return {}

def get_dns_records(domain):
    records = {}

    for record_type in ['A', 'AAAA', 'MX', 'CNAME', 'TXT']:
        try:
            records[record_type] = [str(record) for record in dns.resolver.resolve(domain, record_type)]
        except Exception as e:
            records[record_type] = f"Error: {e}"
    return records

def check_open_ports(target, ports):
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                result = s.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
        except:
            pass
    return open_ports

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Content-Type-Options": "X-Content-Type-Options",
            "X-Frame-Options": "X-Frame-Options",
            "X-XSS-Protection": "X-XSS-Protection"
        }
        missing_headers = [header for header in security_headers if header not in headers]
        return missing_headers
    except Exception as e:
        print(f"Error checking security headers: {e}")
        return []

def test_sql_injection(url):
    try:
        if not url.endswith('/'):
            url += '/'
        sql_payload = "' OR '1'='1"
        response = requests.get(url + "search?query=" + sql_payload, timeout=10)
        error_indicators = ["error", "sql", "syntax", "database"]
        return any(indicator in response.text.lower() for indicator in error_indicators)
    except:
        return False

def test_xss(url):
    try:
        xss_payload = "<script>alert('XSS')</script>"
        response = requests.get(url + "?search=" + xss_payload, timeout=10)
        return xss_payload in response.text
    except:
        return False

def scan_voip_vpn(target_ip):
    nm = nmap.PortScanner()
    voip_ports = [5060, 5070]
    vpn_ports = [1194, 443, 500, 4500]
    all_ports = voip_ports + vpn_ports

    try:
        print(f"\nScanning {target_ip} for VOIP and VPN services...")
        nm.scan(target_ip, ','.join(map(str, all_ports)))
        for port in all_ports:
            if port in nm[target_ip]['tcp']:
                service = nm[target_ip]['tcp'][port]['name']
                state = nm[target_ip]['tcp'][port]['state']
                print(f"Port {port}: {service} is {state}")
            else:
                print(f"Port {port}: No service found")
    except Exception as e:
        print(f"An error occurred during scan: {e}")

def find_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            subdomains = set()
            for entry in response.json():
                subdomain = entry['name_value']
                for sub in subdomain.splitlines():
                    if sub.endswith(domain):
                        subdomains.add(sub)
            return list(subdomains)
        else:
            print("Error: Couldn't retrieve data from crt.sh")
            return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

def google_dork(query, num_results=10):
    url = f"https://www.google.com/search?q={query}&num={num_results}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        results = []
        for item in soup.find_all('h3'):
            parent = item.find_parent('a')
            if parent and 'href' in parent.attrs:
                results.append(parent['href'])
        return results
    except Exception as e:
        print(f"Error during Google Dorking: {e}")
        return []

def get_os_info(url):
    try:
        response = requests.get(url, timeout=10)
        server_header = response.headers.get('Server', 'Not Found')
        print(f"Server Header: {server_header}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def main():
    domain = input("Enter the website domain: ").strip()

    ip_address = get_ip_address(domain)
    print(f"\nIP Address of {domain}: {ip_address}\n")

    url = f"http://{domain}"
    get_os_info(url)

    print("\nWHOIS Lookup:")
    whois_lookup(domain)

    if ip_address:
        geo_info = get_geoip_info(ip_address)
        print(f"\nGeo Info for {ip_address}:")
        print(f"IP: {geo_info.get('ip')}")
        print(f"Country: {geo_info.get('country_name')}")
        print(f"Region: {geo_info.get('region')}")
        print(f"City: {geo_info.get('city')}")
        print(f"ZIP: {geo_info.get('postal')}")
        print(f"Latitude: {geo_info.get('latitude')}")
        print(f"Longitude: {geo_info.get('longitude')}")
        print(f"ISP: {geo_info.get('org')}")

    dns_records = get_dns_records(domain)
    print(f"\nDNS Records for {domain}:")
    for record_type, values in dns_records.items():
        print(f"{record_type}: {values}")

    print("\nChecking open ports...")
    open_ports = check_open_ports(ip_address, [22, 80, 443])
    if open_ports:
        print(f"Open ports: {', '.join(map(str, open_ports))}")
    else:
        print("No open ports found.")

    print("\nChecking HTTP security headers...")
    missing_headers = check_security_headers(url)
    if missing_headers:
        print(f"Missing security headers: {', '.join(missing_headers)}")
    else:
        print("All important security headers are present.")

    print("\nTesting for SQL Injection...")
    if test_sql_injection(url):
        print("Potential SQL Injection vulnerability found.")
    else:
        print("No SQL Injection vulnerability found.")

    print("\nTesting for Cross-Site Scripting (XSS)...")
    if test_xss(url):
        print("Potential XSS vulnerability found.")
    else:
        print("No XSS vulnerability found.")

    scan_voip_vpn(ip_address)

    print(f"\nSubdomains found for {domain}:")
    subdomains = find_subdomains(domain)
    for sub in subdomains:
        print(sub)
        print(f"IP Address: {get_ip_address(sub)}")

    print("\nGoogle Dorking Results:")
    dork_queries = [
        f"inurl:admin site:{domain}",
        f"intitle:index of site:{domain}",
        f"intext:password filetype:log site:{domain}",
        f"filetype:sql 'password' site:{domain}",
        f"inurl:/wp-admin site:{domain}",
        f"inurl:login.php site:{domain}",
        f"intitle:'login page' site:{domain}",
        f"filetype:xls 'password' site:{domain}",
        f"inurl:config.php site:{domain}",
        f"intitle:'index of' 'backup' site:{domain}",
        f"intitle:'index of' 'database' site:{domain}",
        f"inurl:/cgi-bin/ site:{domain}",
        f"ext:xml 'password' site:{domain}",
        f"intitle:'Dashboard Login' site:{domain}",
        f"filetype:doc 'username' site:{domain}",
        f"intitle:'index of' .htaccess site:{domain}",
        f"inurl:ftp:// site:{domain}",
        f"ext:pdf 'confidential' site:{domain}",
    ]

    for query in dork_queries:
        results = google_dork(query)
        print(f"\nResults for query: {query}")
        for result in results:
            print(result)

if __name__ == "__main__":
    main()
