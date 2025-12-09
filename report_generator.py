"""
Report Generator for Recon Tool
Generates professional reports in PDF, JSON, and CSV formats
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any


class ReportGenerator:
    """Generate professional scan reports in multiple formats"""
    
    def __init__(self, output_dir="reports"):
        """
        Initialize report generator
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_json_report(self, scan_data: Dict[str, Any], filename: str = None) -> Path:
        """
        Generate JSON report
        
        Args:
            scan_data: Scan results and metadata
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to generated report
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.json"
        
        filepath = self.output_dir / filename
        
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool': 'Advanced Python Cyber Recon Tool',
                'version': '2.0'
            },
            'scan_info': scan_data.get('scan_info', {}),
            'results': scan_data.get('results', []),
            'statistics': self._calculate_statistics(scan_data.get('results', []))
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        return filepath
    
    def generate_csv_report(self, scan_data: Dict[str, Any], filename: str = None) -> Path:
        """
        Generate CSV report
        
        Args:
            scan_data: Scan results and metadata
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to generated report
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.csv"
        
        filepath = self.output_dir / filename
        
        results = scan_data.get('results', [])
        if not results:
            return None
        
        # Define CSV columns
        fieldnames = ['IP', 'MAC', 'Hostname', 'Vendor', 'OS', 'Open_Ports', 'Services', 'Vulnerabilities']
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                row = {
                    'IP': result.get('IP', ''),
                    'MAC': result.get('MAC', ''),
                    'Hostname': result.get('Hostname', ''),
                    'Vendor': result.get('Vendor', ''),
                    'OS': result.get('OS', ''),
                    'Open_Ports': ', '.join(map(str, result.get('open_ports', []))),
                    'Services': self._format_services(result.get('services', {})),
                    'Vulnerabilities': '; '.join(result.get('vulnerabilities', []))
                }
                writer.writerow(row)
        
        return filepath
    
    def generate_html_report(self, scan_data: Dict[str, Any], filename: str = None) -> Path:
        """
        Generate HTML report
        
        Args:
            scan_data: Scan results and metadata
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to generated report
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.html"
        
        filepath = self.output_dir / filename
        
        results = scan_data.get('results', [])
        scan_info = scan_data.get('scan_info', {})
        stats = self._calculate_statistics(results)
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Network Scan Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a1a;
            color: #e0e0e0;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #2a2a2a;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,255,0,0.1);
        }}
        h1 {{
            color: #00ff00;
            border-bottom: 2px solid #00ff00;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #00cc00;
            margin-top: 30px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-box {{
            background: #1a1a1a;
            padding: 20px;
            border-radius: 5px;
            border-left: 4px solid #00ff00;
        }}
        .stat-label {{
            color: #888;
            font-size: 0.9em;
        }}
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #00ff00;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th {{
            background: #1a1a1a;
            color: #00ff00;
            padding: 12px;
            text-align: left;
            border-bottom: 2px solid #00ff00;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #444;
        }}
        tr:hover {{
            background: #333;
        }}
        .vulnerability {{
            color: #ff6b6b;
            font-weight: bold;
        }}
        .service {{
            color: #4dabf7;
        }}
        .timestamp {{
            color: #888;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Network Reconnaissance Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <h2>📊 Scan Statistics</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-label">Total Devices</div>
                <div class="stat-value">{stats['total_devices']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Open Ports</div>
                <div class="stat-value">{stats['total_open_ports']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Services Detected</div>
                <div class="stat-value">{stats['services_detected']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Vulnerabilities</div>
                <div class="stat-value">{stats['vulnerabilities_found']}</div>
            </div>
        </div>
        
        <h2>🖥️ Discovered Devices</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>Vendor</th>
                    <th>OS</th>
                    <th>Open Ports</th>
                    <th>Services</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for result in results:
            ip = result.get('IP', '')
            hostname = result.get('Hostname', 'N/A')
            vendor = result.get('Vendor', 'N/A')
            os = result.get('OS', 'N/A')
            ports = ', '.join(map(str, result.get('open_ports', [])))
            services = self._format_services_html(result.get('services', {}))
            
            html_content += f"""
                <tr>
                    <td><strong>{ip}</strong></td>
                    <td>{hostname}</td>
                    <td>{vendor}</td>
                    <td>{os}</td>
                    <td>{ports}</td>
                    <td class="service">{services}</td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w') as f:
            f.write(html_content)
        
        return filepath
    
    def _calculate_statistics(self, results: List[Dict]) -> Dict[str, int]:
        """Calculate statistics from scan results"""
        stats = {
            'total_devices': len(results),
            'total_open_ports': 0,
            'services_detected': 0,
            'vulnerabilities_found': 0
        }
        
        for result in results:
            stats['total_open_ports'] += len(result.get('open_ports', []))
            stats['services_detected'] += len(result.get('services', {}))
            stats['vulnerabilities_found'] += len(result.get('vulnerabilities', []))
        
        return stats
    
    def _format_services(self, services: Dict) -> str:
        """Format services dictionary as string for CSV"""
        if not services:
            return ''
        
        service_list = []
        for port, info in services.items():
            service = info.get('service', 'Unknown')
            product = info.get('product', '')
            if product and product != 'Unknown':
                service_list.append(f"{port}:{service}({product})")
            else:
                service_list.append(f"{port}:{service}")
        
        return ', '.join(service_list)
    
    def _format_services_html(self, services: Dict) -> str:
        """Format services dictionary as HTML"""
        if not services:
            return 'None'
        
        service_list = []
        for port, info in services.items():
            service = info.get('service', 'Unknown')
            product = info.get('product', '')
            if product and product != 'Unknown':
                service_list.append(f"{port}:{service} ({product})")
            else:
                service_list.append(f"{port}:{service}")
        
        return '<br>'.join(service_list)


def create_scan_data_structure(results: List[Dict], scan_info: Dict = None) -> Dict:
    """
    Create standardized scan data structure for reporting
    
    Args:
        results: List of scan results
        scan_info: Optional scan metadata
        
    Returns:
        Structured scan data
    """
    return {
        'scan_info': scan_info or {
            'scan_time': datetime.now().isoformat(),
            'scan_type': 'Network Reconnaissance'
        },
        'results': results
    }
