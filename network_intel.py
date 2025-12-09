"""
Network Intelligence Module
Provides OS fingerprinting, service detection, and vulnerability analysis
"""

import socket
import re
from typing import Dict, Optional, Tuple


class NetworkIntelligence:
    """Advanced network intelligence and fingerprinting"""
    
    # OS Detection based on TTL values
    OS_TTL_MAP = {
        64: "Linux/Unix/macOS",
        128: "Windows",
        255: "Cisco/Network Device",
        32: "Windows 95/98",
        60: "macOS (older)",
        254: "Solaris/AIX"
    }
    
    # Common service banners
    SERVICE_SIGNATURES = {
        'SSH': [
            (r'SSH-(\d+\.\d+)-OpenSSH[_-](\S+)', 'OpenSSH'),
            (r'SSH-(\d+\.\d+)-Cisco', 'Cisco SSH'),
            (r'SSH-(\d+\.\d+)', 'Generic SSH')
        ],
        'HTTP': [
            (r'Server: Apache/(\S+)', 'Apache'),
            (r'Server: nginx/(\S+)', 'nginx'),
            (r'Server: Microsoft-IIS/(\S+)', 'Microsoft IIS'),
            (r'Server: lighttpd/(\S+)', 'lighttpd')
        ],
        'FTP': [
            (r'220.*ProFTPD (\S+)', 'ProFTPD'),
            (r'220.*vsftpd (\S+)', 'vsftpd'),
            (r'220.*FileZilla Server (\S+)', 'FileZilla'),
            (r'220.*Microsoft FTP', 'Microsoft FTP')
        ],
        'SMTP': [
            (r'220.*Postfix', 'Postfix'),
            (r'220.*Sendmail (\S+)', 'Sendmail'),
            (r'220.*Microsoft ESMTP', 'Microsoft Exchange')
        ]
    }
    
    # Known vulnerabilities for common versions
    VULNERABILITY_HINTS = {
        'OpenSSH_7.4': ['CVE-2018-15473: Username enumeration'],
        'Apache/2.4.49': ['CVE-2021-41773: Path traversal'],
        'nginx/1.18.0': ['Potential outdated version'],
        'vsftpd 2.3.4': ['CVE-2011-2523: Backdoor vulnerability'],
        'ProFTPD 1.3.3c': ['CVE-2010-4221: SQL injection']
    }
    
    def __init__(self, scapy_module=None):
        """
        Initialize network intelligence module
        
        Args:
            scapy_module: Reference to scapy module for advanced operations
        """
        self.scapy = scapy_module
    
    def detect_os_by_ttl(self, ip: str, timeout: float = 1.0) -> Optional[str]:
        """
        Detect OS based on TTL value from ICMP ping
        
        Args:
            ip: Target IP address
            timeout: Timeout for ping response
            
        Returns:
            Detected OS or None
        """
        if self.scapy is None:
            return None
        
        try:
            # Send ICMP ping
            packet = self.scapy.IP(dst=ip)/self.scapy.ICMP()
            response = self.scapy.sr1(packet, timeout=timeout, verbose=False)
            
            if response:
                ttl = response.ttl
                # Find closest TTL match
                for base_ttl, os_name in sorted(self.OS_TTL_MAP.items()):
                    if abs(ttl - base_ttl) <= 10:  # Allow some hops
                        return f"{os_name} (TTL: {ttl})"
            
            return None
        except Exception as e:
            return None
    
    def grab_banner(self, ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
        """
        Grab service banner from a port
        
        Args:
            ip: Target IP address
            port: Target port
            timeout: Connection timeout
            
        Returns:
            Service banner or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Send initial probe for some services
            if port == 80:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 25:  # SMTP
                pass  # SMTP sends banner automatically
            elif port == 21:  # FTP
                pass  # FTP sends banner automatically
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
            
        except Exception:
            return None
    
    def detect_service(self, ip: str, port: int, banner: Optional[str] = None) -> Dict[str, str]:
        """
        Detect service type and version
        
        Args:
            ip: Target IP address
            port: Target port
            banner: Optional pre-grabbed banner
            
        Returns:
            Dictionary with service info
        """
        result = {
            'service': 'Unknown',
            'version': 'Unknown',
            'product': 'Unknown'
        }
        
        # Grab banner if not provided
        if banner is None:
            banner = self.grab_banner(ip, port)
        
        if not banner:
            # Fallback to common port mappings
            port_services = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
                80: 'HTTP', 443: 'HTTPS', 3389: 'RDP', 
                554: 'RTSP', 8080: 'HTTP-Proxy', 8554: 'RTSP'
            }
            result['service'] = port_services.get(port, 'Unknown')
            return result
        
        # Try to match banner against signatures
        for service_type, patterns in self.SERVICE_SIGNATURES.items():
            for pattern, product in patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    result['service'] = service_type
                    result['product'] = product
                    if match.groups():
                        result['version'] = match.group(1) if len(match.groups()) == 1 else match.group(2)
                    return result
        
        # If no match, return service based on port
        result['service'] = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            80: 'HTTP', 443: 'HTTPS', 3389: 'RDP'
        }.get(port, 'Unknown')
        
        return result
    
    def get_vulnerability_hints(self, service_info: Dict[str, str]) -> list:
        """
        Get vulnerability hints for detected service
        
        Args:
            service_info: Service information dictionary
            
        Returns:
            List of vulnerability hints
        """
        hints = []
        
        # Check for exact version matches
        product = service_info.get('product', '')
        version = service_info.get('version', '')
        
        if product and version:
            key = f"{product}_{version}"
            if key in self.VULNERABILITY_HINTS:
                hints.extend(self.VULNERABILITY_HINTS[key])
            
            # Check for partial matches
            for vuln_key, vuln_hints in self.VULNERABILITY_HINTS.items():
                if product in vuln_key:
                    hints.extend([f"Potential: {h}" for h in vuln_hints])
        
        return hints
    
    def analyze_tcp_window(self, ip: str) -> Optional[int]:
        """
        Analyze TCP window size for OS fingerprinting
        
        Args:
            ip: Target IP address
            
        Returns:
            TCP window size or None
        """
        if self.scapy is None:
            return None
        
        try:
            # Send SYN packet
            packet = self.scapy.IP(dst=ip)/self.scapy.TCP(dport=80, flags='S')
            response = self.scapy.sr1(packet, timeout=1, verbose=False)
            
            if response and response.haslayer(self.scapy.TCP):
                return response[self.scapy.TCP].window
            
            return None
        except Exception:
            return None
    
    def comprehensive_scan(self, ip: str, open_ports: list) -> Dict:
        """
        Perform comprehensive intelligence gathering
        
        Args:
            ip: Target IP address
            open_ports: List of open ports
            
        Returns:
            Dictionary with all gathered intelligence
        """
        intel = {
            'ip': ip,
            'os': self.detect_os_by_ttl(ip),
            'services': {},
            'vulnerabilities': []
        }
        
        # Scan each open port
        for port in open_ports:
            banner = self.grab_banner(ip, port)
            service_info = self.detect_service(ip, port, banner)
            service_info['banner'] = banner
            
            # Get vulnerability hints
            vulns = self.get_vulnerability_hints(service_info)
            if vulns:
                intel['vulnerabilities'].extend(vulns)
            
            intel['services'][port] = service_info
        
        return intel


def format_service_string(service_info: Dict[str, str]) -> str:
    """
    Format service information as a readable string
    
    Args:
        service_info: Service information dictionary
        
    Returns:
        Formatted string
    """
    service = service_info.get('service', 'Unknown')
    product = service_info.get('product', '')
    version = service_info.get('version', '')
    
    if product != 'Unknown' and version != 'Unknown':
        return f"{service} ({product} {version})"
    elif product != 'Unknown':
        return f"{service} ({product})"
    else:
        return service
