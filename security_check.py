#!/usr/bin/env python3
import re
import subprocess
import socket
from collections import defaultdict
from datetime import datetime
import sys
import os
import pwd
import grp
import stat
import logging
from logging.handlers import RotatingFileHandler
import json
import psutil
import platform
import requests
from ipaddress import ip_address, IPv4Address, IPv6Address
import dns.resolver
import whois
from concurrent.futures import ThreadPoolExecutor, as_completed


class IPAnalyzer:
    def __init__(self):
        self.cache = {}

    def get_ip_details(self, ip):
        """Get detailed information about an IP address"""
        if ip in self.cache:
            return self.cache[ip]

        details = {
            'ip': ip,
            'geolocation': self._get_geolocation(ip),
            'reputation': self._check_reputation(ip),
            'reverse_dns': self._get_reverse_dns(ip),
            'whois': self._get_whois(ip),
            'network_info': self._get_network_info(ip)
        }

        self.cache[ip] = details
        return details

    def _get_geolocation(self, ip):
        """Get geolocation information for an IP"""
        try:
            response = requests.get(f'https://ipapi.co/{ip}/json/')
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country_name'),
                    'region': data.get('region'),
                    'city': data.get('city'),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'org': data.get('org')
                }
        except Exception:
            pass
        return None

    def _check_reputation(self, ip):
        """Check IP reputation using AbuseIPDB API"""
        try:
            headers = {
                'Key': os.getenv('ABUSEIPDB_API_KEY'),
                'Accept': 'application/json',
            }
            response = requests.get(
                f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}',
                headers=headers
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    'abuse_score': data['data']['abuseConfidenceScore'],
                    'total_reports': data['data']['totalReports'],
                    'last_reported': data['data']['lastReportedAt']
                }
        except Exception:
            pass
        return None

    def _get_reverse_dns(self, ip):
        """Get reverse DNS information"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    def _get_whois(self, ip):
        """Get WHOIS information"""
        try:
            w = whois.whois(ip)
            return {
                'organization': w.org,
                'country': w.country,
                'nets': w.nets if hasattr(w, 'nets') else None
            }
        except Exception:
            return None

    def _get_network_info(self, ip):
        """Get network information about the IP"""
        try:
            ip_obj = ip_address(ip)
            return {
                'version': 'IPv4' if isinstance(ip_obj, IPv4Address) else 'IPv6',
                'is_private': ip_obj.is_private,
                'is_global': ip_obj.is_global,
                'reverse_pointer': ip_obj.reverse_pointer
            }
        except Exception:
            return None


class SecurityMonitor:
    def __init__(self, log_dir="/var/log/security_monitor"):
        self.issues = []
        self.critical_issues = []
        self.warnings = []
        self.failed_attempts = defaultdict(lambda: {'count': 0, 'users': set(), 'last_attempt': None})
        self.log_dir = log_dir
        self.ip_analyzer = IPAnalyzer()
        self.setup_logging()

    def setup_logging(self):
        """Set up logging with rotation"""
        os.makedirs(self.log_dir, exist_ok=True)

        log_file = os.path.join(self.log_dir, "security_audit.log")
        self.logger = logging.getLogger('SecurityAudit')
        self.logger.setLevel(logging.INFO)

        handler = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=5
        )

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # Create JSON report file with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.json_report_file = os.path.join(
            self.log_dir,
            f"security_report_{timestamp}.json"
        )

    def check_ssh_config(self):
        """Check SSH configuration for security issues"""
        self.logger.info("Checking SSH configuration...")
        try:
            with open('/etc/ssh/sshd_config', 'r') as f:
                config = f.read()

            checks = {
                'PermitRootLogin': (r'PermitRootLogin\s+yes', 'Root login is permitted'),
                'PasswordAuthentication': (r'PasswordAuthentication\s+yes', 'Password authentication is enabled'),
                'Port': (r'Port\s+22\s', 'SSH is running on default port 22'),
                'Protocol': (r'Protocol\s+1\s', 'Old SSH protocol 1 is enabled'),
                'X11Forwarding': (r'X11Forwarding\s+yes', 'X11 forwarding is enabled'),
                'MaxAuthTries': (r'MaxAuthTries\s+([6-9]|[1-9][0-9]+)', 'High number of authentication tries allowed')
            }

            for check, (pattern, message) in checks.items():
                if re.search(pattern, config):
                    self.warnings.append(f"SSH Warning: {message}")

        except Exception as e:
            self.issues.append(f"Error checking SSH config: {str(e)}")

    def check_open_ports(self):
        """Check for open ports and identify services"""
        self.logger.info("Checking open ports...")
        try:
            result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True)

            # Common ports and their services
            common_ports = {
                '22': 'SSH', '80': 'HTTP', '443': 'HTTPS',
                '21': 'FTP', '25': 'SMTP', '53': 'DNS',
                '3306': 'MySQL', '5432': 'PostgreSQL',
                '27017': 'MongoDB', '6379': 'Redis'
            }

            open_ports = re.findall(r':(\d+)\s', result.stdout)

            for port in set(open_ports):
                service = common_ports.get(port, 'Unknown')
                if port not in common_ports:
                    self.warnings.append(f"Unusual port {port} is open")
                self.logger.info(f"Found open port {port} ({service})")

        except Exception as e:
            self.issues.append(f"Error checking open ports: {str(e)}")

    def check_system_updates(self):
        """Check for available system updates"""
        self.logger.info("Checking for system updates...")
        try:
            if os.path.exists('/usr/bin/apt'):
                update_check = subprocess.run(['apt-get', '-s', 'upgrade'], capture_output=True, text=True)
                if 'upgraded,' in update_check.stdout:
                    self.warnings.append("System updates are available")
            elif os.path.exists('/usr/bin/yum'):
                update_check = subprocess.run(['yum', 'check-update'], capture_output=True, text=True)
                if update_check.returncode == 100:
                    self.warnings.append("System updates are available")
        except Exception as e:
            self.issues.append(f"Error checking system updates: {str(e)}")

    def check_disk_space(self):
        """Check disk space usage"""
        self.logger.info("Checking disk space...")
        try:
            for partition in psutil.disk_partitions():
                usage = psutil.disk_usage(partition.mountpoint)
                if usage.percent >= 90:
                    self.critical_issues.append(
                        f"Critical disk space usage: {usage.percent}% on {partition.mountpoint}"
                    )
                elif usage.percent >= 80:
                    self.warnings.append(
                        f"High disk space usage: {usage.percent}% on {partition.mountpoint}"
                    )
        except Exception as e:
            self.issues.append(f"Error checking disk space: {str(e)}")

    def check_user_security(self):
        """Check user account security"""
        self.logger.info("Checking user security...")
        try:
            # Check for users with empty passwords
            with open('/etc/shadow', 'r') as f:
                for line in f:
                    if '::' in line:
                        username = line.split(':')[0]
                        self.critical_issues.append(f"User {username} has no password set")

            # Check for users with UID 0 (root privileges)
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    fields = line.split(':')
                    if fields[2] == '0' and fields[0] != 'root':
                        self.critical_issues.append(f"User {fields[0]} has root UID (0)")

        except Exception as e:
            self.issues.append(f"Error checking user security: {str(e)}")

    def check_login_attempts(self):
        """Check for failed login attempts with enhanced IP analysis"""
        self.logger.info("Checking failed login attempts...")
        log_files = ['/var/log/auth.log', '/var/log/secure']
        patterns = {
            'ssh': r'(?P<date>\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)',
            'sudo': r'(?P<date>\w+\s+\d+\s+\d+:\d+:\d+).*sudo:.*authentication failure.*user=(?P<user>\S+).*rhost=(?P<ip>\S+)'
        }

        # Collect all unique IPs first
        unique_ips = set()
        for log_file in log_files:
            if not os.path.exists(log_file):
                continue

            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        for pattern_name, pattern in patterns.items():
                            match = re.search(pattern, line)
                            if match:
                                ip = match.group('ip')
                                date_str = match.group('date')
                                user = match.group('user')

                                self.failed_attempts[ip]['count'] += 1
                                self.failed_attempts[ip]['users'].add(user)
                                self.failed_attempts[ip]['last_attempt'] = date_str
                                unique_ips.add(ip)

            except Exception as e:
                self.issues.append(f"Error reading {log_file}: {str(e)}")

        # Analyze IPs in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_ip = {
                executor.submit(self.ip_analyzer.get_ip_details, ip): ip
                for ip in unique_ips
            }

            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    ip_details = future.result()
                    self.failed_attempts[ip]['ip_details'] = ip_details

                    # Enhanced threat analysis
                    self._analyze_ip_threat(ip, ip_details)

                except Exception as e:
                    self.logger.error(f"Error analyzing IP {ip}: {str(e)}")

    def _analyze_ip_threat(self, ip, ip_details):
        """Analyze IP address for potential threats"""
        if not ip_details:
            return

        # Check for high-risk countries (example list)
        high_risk_countries = {'North Korea', 'Iran', 'Syria'}
        country = ip_details.get('geolocation', {}).get('country')

        if country in high_risk_countries:
            self.critical_issues.append(
                f"Login attempts from high-risk country: {ip} ({country})"
            )

        # Check reputation score
        reputation = ip_details.get('reputation', {})
        if reputation:
            abuse_score = reputation.get('abuse_score', 0)
            if abuse_score > 80:
                self.critical_issues.append(
                    f"High-risk IP detected: {ip} (AbuseIPDB score: {abuse_score})"
                )
            elif abuse_score > 50:
                self.warnings.append(
                    f"Medium-risk IP detected: {ip} (AbuseIPDB score: {abuse_score})"
                )

        # Check for multiple users targeted
        if len(self.failed_attempts[ip]['users']) > 5:
            self.critical_issues.append(
                f"Possible user enumeration from {ip} "
                f"(attempted {len(self.failed_attempts[ip]['users'])} different users)"
            )

    def check_firewall(self):
        """Check firewall status and configuration"""
        self.logger.info("Checking firewall status...")
        try:
            # Check UFW status
            ufw_result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
            if 'Status: inactive' in ufw_result.stdout:
                self.critical_issues.append("UFW firewall is not enabled")
            else:
                self.logger.info("Firewall is active")
        except FileNotFoundError:
            try:
                # Check iptables if UFW is not installed
                iptables_result = subprocess.run(['iptables', '-L'], capture_output=True, text=True)
                if 'Chain INPUT (policy ACCEPT)' in iptables_result.stdout:
                    self.warnings.append("Default iptables policy is ACCEPT")
            except FileNotFoundError:
                self.critical_issues.append("No firewall (UFW/iptables) found")

    def generate_report(self):
        """Generate enhanced JSON report with all findings"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'hostname': socket.gethostname(),
            'system_info': {
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'machine': platform.machine()
            },
            'critical_issues': self.critical_issues,
            'issues': self.issues,
            'warnings': self.warnings,
            'failed_login_attempts': {
                ip: {
                    'count': data['count'],
                    'users': list(data['users']),
                    'last_attempt': data['last_attempt'],
                    'ip_details': data['ip_details']
                }
                for ip, data in self.failed_attempts.items()
            }
        }

        try:
            with open(self.json_report_file, 'w') as f:
                json.dump(report, f, indent=4)
            self.logger.info(f"Report generated: {self.json_report_file}")
        except Exception as e:
            self.logger.error(f"Failed to write report: {str(e)}")

    def run_audit(self):
        """Run all security checks"""
        self.logger.info("Starting security audit...")

        checks = [
            self.check_ssh_config,
            self.check_open_ports,
            self.check_system_updates,
            self.check_disk_space,
            self.check_user_security,
            self.check_login_attempts,
            self.check_firewall
        ]

        for check in checks:
            try:
                check()
            except Exception as e:
                self.logger.error(f"Error in {check.__name__}: {str(e)}")

        self.generate_report()
        self.print_summary()

    def print_summary(self):
        """Print an enhanced summary of findings"""
        print("\n=== Security Audit Summary ===")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Hostname: {socket.gethostname()}")

        print("\nCritical Issues:")
        for issue in self.critical_issues:
            print(f"❌ {issue}")

        print("\nWarnings:")
        for warning in self.warnings:
            print(f"⚠️  {warning}")

        print("\nFailed Login Attempts:")
        for ip, data in self.failed_attempts.items():
            ip_details = data.get('ip_details', {})
            geo = ip_details.get('geolocation', {})
            reputation = ip_details.get('reputation', {})

            print(f"\n🔒 IP: {ip}")
            print(f"   Attempts: {data['count']}")
            print(f"   Location: {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}")
            if reputation:
                print(f"   Risk Score: {reputation.get('abuse_score', 'Unknown')}")
            print(f"   Targeted Users: {len(data['users'])}")
            print(f"   Last Attempt: {data['last_attempt']}")

        print(f"\nFull report saved to: {self.json_report_file}")


def main():
    if os.geteuid() != 0:
        print("This script must be run as root (sudo)")
        sys.exit(1)

    monitor = SecurityMonitor()
    monitor.run_audit()


if __name__ == "__main__":
    main()