#!/usr/bin/env python3
"""
ZERO Scanner - Advanced SMB Security Assessment Tool
Author: .Zer0
Version: 1.0
License: MIT
"""

import os
import sys
import json
import socket
import argparse
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"
    GRAY = "\033[90m"

def show_zero_art():
    """Display ZERO ASCII art"""
    zero_art = f"""{Colors.CYAN}{Colors.BOLD}
███████╗███████╗██████╗  ██████╗ 
╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
  ███╔╝ █████╗  ██████╔╝██║   ██║
 ███╔╝  ██╔══╝  ██╔══██╗██║   ██║
███████╗███████╗██║  ██║╚██████╔╝
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ 
                                  

{Colors.END}"""
    print(zero_art)

def show_banner():
    """Display scanner banner"""
    show_zero_art()
    banner = f"""{Colors.PURPLE}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                    .ZER0 SCANNER v1.0                        ║
║          Advanced SMB Security Assessment Tool               ║
║                 Author: .Zer0 | github.com/zeroaualy         ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}"""
    print(banner)

# Port definitions
SMB_PORTS = {
    "basic": {
        "name": "Basic SMB Ports",
        "ports": [
            {"port": 139, "protocol": "tcp", "service": "NetBIOS Session"},
            {"port": 445, "protocol": "tcp", "service": "SMB over TCP"}
        ]
    },
    "advanced": {
        "name": "Advanced SMB/AD Ports",
        "ports": [
            # SMB Core Ports
            {"port": 139, "protocol": "tcp", "service": "NetBIOS Session"},
            {"port": 445, "protocol": "tcp", "service": "SMB over TCP"},
            {"port": 137, "protocol": "udp", "service": "NetBIOS Name Service"},
            {"port": 138, "protocol": "udp", "service": "NetBIOS Datagram"},
            
            # RPC and DCOM
            {"port": 135, "protocol": "tcp", "service": "MSRPC"},
            
            # Active Directory
            {"port": 389, "protocol": "tcp", "service": "LDAP"},
            {"port": 636, "protocol": "tcp", "service": "LDAPS"},
            {"port": 3268, "protocol": "tcp", "service": "Global Catalog"},
            {"port": 3269, "protocol": "tcp", "service": "Global Catalog SSL"},
            
            # Kerberos
            {"port": 88, "protocol": "tcp", "service": "Kerberos"},
            {"port": 464, "protocol": "tcp", "service": "Kerberos Password"},
            
            # Other related services
            {"port": 53, "protocol": "tcp", "service": "DNS"},
            {"port": 53, "protocol": "udp", "service": "DNS"},
            {"port": 123, "protocol": "udp", "service": "NTP"},
            {"port": 42, "protocol": "tcp", "service": "WINS"},
            {"port": 42, "protocol": "udp", "service": "WINS"},
            
            # RDP (often on same servers)
            {"port": 3389, "protocol": "tcp", "service": "RDP"},
            
            # File sharing alternatives
            {"port": 2049, "protocol": "tcp", "service": "NFS"},
            {"port": 21, "protocol": "tcp", "service": "FTP"},
            {"port": 22, "protocol": "tcp", "service": "SSH/SFTP"}
        ]
    }
}

class PortChecker:
    """Port checking utilities"""
    
    @staticmethod
    def check_port_socket(target, port, protocol="tcp", timeout=2):
        """Check port using socket"""
        try:
            if protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:  # udp
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            sock.settimeout(timeout)
            
            if protocol == "tcp":
                result = sock.connect_ex((target, port))
                sock.close()
                return result == 0
            else:
                # UDP check is less reliable
                sock.sendto(b'\x00', (target, port))
                sock.settimeout(1)
                sock.recvfrom(1024)
                sock.close()
                return True
        except socket.timeout:
            # UDP timeout might mean port is open/filtered
            if protocol == "udp":
                return "filtered"
            return False
        except ConnectionRefusedError:
            return False
        except Exception:
            return False
    
    @staticmethod
    def check_port_nmap(target, port, protocol="tcp", timeout=5):
        """Check port using nmap"""
        try:
            cmd = f"nmap -p {port} -s{'U' if protocol == 'udp' else 'S'} -Pn --open -T4 {target} 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            
            if protocol == "udp":
                return "open|filtered" in result.stdout
            return f"{port}/tcp" in result.stdout and "open" in result.stdout
        except:
            return False
    
    @staticmethod
    def check_port_netcat(target, port, protocol="tcp", timeout=2):
        """Check port using netcat"""
        try:
            if protocol == "tcp":
                cmd = f"timeout {timeout} nc -zv -w1 {target} {port} 2>&1"
            else:
                cmd = f"timeout {timeout} nc -zu -w1 {target} {port} 2>&1"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return "succeeded" in result.stdout or "open" in result.stdout
        except:
            return False

class ZeroScanner:
    def __init__(self, target, output=None, verbose=False, force=False, scan_mode="basic"):
        self.target = target
        self.output_file = output
        self.verbose = verbose
        self.force = force
        self.scan_mode = scan_mode
        self.scan_results = {}
        self.port_checker = PortChecker()
        
    def log(self, message, level="INFO", end="\n"):
        """Log messages with colors"""
        level_colors = {
            "INFO": Colors.BLUE,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
            "SCAN": Colors.PURPLE,
            "DEBUG": Colors.GRAY
        }
        
        color = level_colors.get(level, Colors.WHITE)
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        log_msg = f"{Colors.GRAY}[{timestamp}]{Colors.END} {color}[{level}]{Colors.END} {message}"
        print(log_msg, end=end)
        
        if self.output_file and level in ["SUCCESS", "WARNING", "ERROR", "SCAN"]:
            with open(self.output_file, 'a') as f:
                f.write(f"[{timestamp}] [{level}] {message}\n")
    
    def check_dependencies(self):
        """Check for required tools"""
        tools = ['nmap', 'smbclient', 'nc']
        available = []
        missing = []
        
        for tool in tools:
            try:
                if tool == 'nc':
                    subprocess.run(['which', 'nc'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                else:
                    subprocess.run([tool, '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                available.append(tool)
                self.log(f"{tool} found", "SUCCESS")
            except:
                missing.append(tool)
                self.log(f"{tool} not found", "WARNING")
        
        if missing:
            self.log(f"Missing tools: {', '.join(missing)}", "ERROR")
            if 'nmap' in missing:
                self.log("Nmap is essential for accurate scanning", "ERROR")
        
        return len(missing) == 0
    
    def scan_ports(self):
        """Scan SMB ports based on selected mode"""
        mode = SMB_PORTS.get(self.scan_mode, SMB_PORTS["basic"])
        
        self.log(f"Starting {mode['name']} scan...", "SCAN")
        self.log(f"Mode: {self.scan_mode.upper()} ({len(mode['ports'])} ports)", "INFO")
        
        open_ports = []
        
        # Use ThreadPoolExecutor for parallel scanning
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {}
            
            for port_info in mode['ports']:
                future = executor.submit(
                    self.check_single_port,
                    port_info['port'],
                    port_info['protocol'],
                    port_info['service']
                )
                future_to_port[future] = port_info
            
            for future in as_completed(future_to_port):
                port_info = future_to_port[future]
                try:
                    is_open, methods = future.result()
                    
                    if is_open or (isinstance(is_open, str) and is_open in ["open", "filtered"]):
                        status = "OPEN" if is_open == True else is_open.upper()
                        color = Colors.GREEN if is_open == True else Colors.YELLOW
                        self.log(f"  Port {port_info['port']}/{port_info['protocol']} ({port_info['service']}): {color}{status}{Colors.END}", "SUCCESS")
                        open_ports.append({
                            'port': port_info['port'],
                            'protocol': port_info['protocol'],
                            'service': port_info['service'],
                            'status': status,
                            'methods': methods
                        })
                    else:
                        if self.verbose:
                            self.log(f"  Port {port_info['port']}/{port_info['protocol']}: {Colors.RED}CLOSED{Colors.END}", "DEBUG")
                except Exception as e:
                    self.log(f"Error scanning port {port_info['port']}: {e}", "ERROR")
        
        self.scan_results['ports'] = open_ports
        self.scan_results['total_scanned'] = len(mode['ports'])
        self.scan_results['open_ports'] = len(open_ports)
        
        # Summary
        self.log(f"\n📊 Port Scan Summary:", "INFO")
        self.log(f"  Scanned: {len(mode['ports'])} ports", "INFO")
        self.log(f"  Open: {len(open_ports)} ports", "SUCCESS" if open_ports else "WARNING")
        
        if open_ports:
            self.log(f"  Open ports:", "INFO")
            for port in open_ports:
                self.log(f"    • {port['port']}/{port['protocol']} - {port['service']} ({port['status']})", "INFO")
        
        return len(open_ports) > 0 or self.force
    
    def check_single_port(self, port, protocol, service):
        """Check a single port with multiple methods"""
        methods = {}
        
        # Method 1: Socket
        methods['socket'] = self.port_checker.check_port_socket(self.target, port, protocol)
        
        # Method 2: Nmap (if available)
        try:
            methods['nmap'] = self.port_checker.check_port_nmap(self.target, port, protocol)
        except:
            methods['nmap'] = False
        
        # Method 3: Netcat
        methods['netcat'] = self.port_checker.check_port_netcat(self.target, port, protocol)
        
        # Determine final status
        # If any method says it's open, consider it open
        is_open = any(methods.values())
        
        # Special handling for UDP filtered ports
        if protocol == "udp" and methods.get('socket') == "filtered":
            is_open = "filtered"
        
        return is_open, methods
    
    def diagnose_port_445(self):
        """Detailed diagnosis of port 445"""
        self.log("\n🔍 Detailed diagnosis of port 445...", "SCAN")
        
        methods = [
            ("Socket", lambda: self.port_checker.check_port_socket(self.target, 445)),
            ("Netcat", lambda: self.port_checker.check_port_netcat(self.target, 445)),
            ("Nmap", lambda: self.port_checker.check_port_nmap(self.target, 445))
        ]
        
        results = {}
        for method_name, method_func in methods:
            try:
                is_open = method_func()
                results[method_name] = is_open
                status = "OPEN" if is_open else "CLOSED"
                color = Colors.GREEN if is_open else Colors.RED
                self.log(f"  {method_name}: {color}{status}{Colors.END}", "DEBUG")
            except Exception as e:
                results[method_name] = f"Error: {e}"
                self.log(f"  {method_name}: ERROR", "DEBUG")
        
        # Check for common issues
        self.log("  Checking for common issues...", "DEBUG")
        
        # Check if host is online
        try:
            ping_cmd = f"ping -c 1 -W 1 {self.target} 2>&1 | grep 'bytes from'"
            ping_result = subprocess.run(ping_cmd, shell=True, capture_output=True, text=True)
            if ping_result.returncode == 0:
                self.log("  Host is online", "DEBUG")
            else:
                self.log("  Host may be offline or blocking ICMP", "WARNING")
        except:
            pass
        
        return results
    
    def run_nmap_smb_scan(self):
        """Run detailed Nmap SMB scan"""
        self.log("\nRunning detailed SMB scan with Nmap...", "SCAN")
        
        try:
            # Comprehensive SMB scan
            scripts = [
                "smb-os-discovery",
                "smb-security-mode", 
                "smb-protocols",
                "smb2-security-mode",
                "smb2-capabilities"
            ]
            
            cmd = f"nmap -p 139,445 -sV --script {','.join(scripts)} {self.target}"
            
            if self.verbose:
                self.log(f"Command: {cmd}", "DEBUG")
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                self.log("Nmap scan completed successfully", "SUCCESS")
                
                # Parse important information
                if "SMB:" in result.stdout:
                    for line in result.stdout.split('\n'):
                        if "SMB:" in line and "Windows" in line:
                            os_info = line.split("SMB:")[1].strip()
                            self.log(f"OS Detected: {os_info}", "SUCCESS")
                            self.scan_results['os_info'] = os_info
                            break
                
                if self.verbose:
                    print(result.stdout[:1000])  # Show first 1000 chars
                
                self.scan_results['nmap_raw'] = result.stdout
            else:
                self.log("Nmap scan failed", "ERROR")
                
        except subprocess.TimeoutExpired:
            self.log("Nmap scan timed out", "WARNING")
        except Exception as e:
            self.log(f"Nmap error: {e}", "ERROR")
    
    def enumerate_shares(self):
        """Enumerate SMB shares"""
        self.log("\nEnumerating SMB shares...", "SCAN")
        
        try:
            # Try anonymous access first
            cmd = f"smbclient -L //{self.target}/ -N 2>/dev/null | grep -E '^[[:space:]]*[A-Za-z0-9_$]+' || echo 'No shares found'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            shares = []
            lines = result.stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('Sharename') and not line.startswith('---'):
                    parts = line.split()
                    if len(parts) >= 2:
                        share_name = parts[0]
                        share_type = parts[1]
                        comment = ' '.join(parts[2:]) if len(parts) > 2 else ''
                        
                        shares.append({
                            'name': share_name,
                            'type': share_type,
                            'comment': comment
                        })
                        
                        self.log(f"Found share: {share_name} ({share_type}) {comment}", "SUCCESS")
            
            self.scan_results['shares'] = shares
            self.scan_results['shares_count'] = len(shares)
            
            if not shares:
                self.log("No accessible shares found", "WARNING")
                
        except Exception as e:
            self.log(f"Share enumeration error: {e}", "ERROR")
    
    def check_eternalblue(self):
        """Check for MS17-010 EternalBlue vulnerability"""
        self.log("\nChecking for EternalBlue (MS17-010)...", "SCAN")
        
        try:
            cmd = f"nmap -p 445 --script smb-vuln-ms17-010 {self.target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            
            if "VULNERABLE" in result.stdout:
                self.log("🚨 VULNERABLE to EternalBlue (MS17-010)!", "ERROR")
                self.scan_results['eternalblue'] = True
                self.scan_results['eternalblue_details'] = "CRITICAL - Patch immediately!"
            elif "State: VULNERABLE" in result.stdout:
                self.log("⚠️  Possibly vulnerable to EternalBlue", "WARNING")
                self.scan_results['eternalblue'] = "Possibly"
            else:
                self.log("Not vulnerable to EternalBlue", "SUCCESS")
                self.scan_results['eternalblue'] = False
                
        except Exception as e:
            self.log(f"EternalBlue check error: {e}", "ERROR")
    
    def generate_report(self):
        """Generate scan report"""
        self.log("\nGenerating final report...", "INFO")
        
        report = {
            'scanner': 'ZERO Scanner v1.0',
            'author': '.Zer0',
            'target': self.target,
            'scan_date': datetime.now().isoformat(),
            'scan_mode': self.scan_mode,
            'scan_results': self.scan_results,
            'summary': {
                'ports_scanned': self.scan_results.get('total_scanned', 0),
                'ports_open': self.scan_results.get('open_ports', 0),
                'shares_found': self.scan_results.get('shares_count', 0),
                'eternalblue_vulnerable': self.scan_results.get('eternalblue', 'Unknown'),
                'os_detected': self.scan_results.get('os_info', 'Unknown')
            }
        }
        
        # Save JSON report
        if self.output_file:
            json_file = self.output_file.replace('.txt', '.json') if self.output_file.endswith('.txt') else self.output_file + '.json'
            with open(json_file, 'w') as f:
                json.dump(report, f, indent=4, ensure_ascii=False)
            self.log(f"JSON report saved to: {json_file}", "SUCCESS")
        
        # Save text report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        text_file = f"zero_scan_{self.target}_{timestamp}.txt"
        
        with open(text_file, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write(f"ZERO SCANNER REPORT\n")
            f.write(f"Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Mode: {self.scan_mode}\n")
            f.write("="*70 + "\n\n")
            
            # Summary
            f.write("[SUMMARY]\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Ports scanned: {report['summary']['ports_scanned']}\n")
            f.write(f"Ports open: {report['summary']['ports_open']}\n")
            f.write(f"Shares found: {report['summary']['shares_found']}\n")
            f.write(f"EternalBlue vulnerable: {report['summary']['eternalblue_vulnerable']}\n")
            f.write(f"OS detected: {report['summary']['os_detected']}\n\n")
            
            # Open ports
            if self.scan_results.get('ports'):
                f.write("[OPEN PORTS]\n")
                for port in self.scan_results['ports']:
                    f.write(f"  {port['port']}/{port['protocol']} - {port['service']} ({port['status']})\n")
                f.write("\n")
            
            # Shares
            if self.scan_results.get('shares'):
                f.write("[SMB SHARES]\n")
                for share in self.scan_results['shares']:
                    f.write(f"  {share['name']} ({share['type']})")
                    if share.get('comment'):
                        f.write(f" - {share['comment']}")
                    f.write("\n")
                f.write("\n")
            
            # Recommendations
            f.write("[RECOMMENDATIONS]\n")
            if self.scan_results.get('eternalblue') == True:
                f.write("1. CRITICAL: Patch MS17-010 vulnerability immediately!\n")
            if self.scan_results.get('shares_count', 0) > 0:
                f.write("2. Review SMB share permissions\n")
            if self.scan_results.get('ports_open', 0) > 0:
                f.write("3. Consider disabling unused protocols (NetBIOS/SMBv1)\n")
            f.write("4. Enable SMB signing for security\n")
            f.write("5. Use strong passwords for SMB access\n")
        
        self.log(f"Text report saved to: {text_file}", "SUCCESS")
        return report
    
    def print_summary(self):
        """Print scan summary to console"""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}           SCAN COMPLETED - SUMMARY{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}\n")
        
        print(f"{Colors.BOLD}📊 RESULTS:{Colors.END}")
        print(f"  • Target: {self.target}")
        print(f"  • Scan Mode: {self.scan_mode.upper()}")
        print(f"  • Ports Open: {self.scan_results.get('open_ports', 0)}/{self.scan_results.get('total_scanned', 0)}")
        print(f"  • Shares Found: {self.scan_results.get('shares_count', 0)}")
        
        eternalblue = self.scan_results.get('eternalblue')
        if eternalblue == True:
            print(f"  • EternalBlue: {Colors.RED}VULNERABLE (CRITICAL){Colors.END}")
        elif eternalblue == "Possibly":
            print(f"  • EternalBlue: {Colors.YELLOW}POSSIBLY VULNERABLE{Colors.END}")
        else:
            print(f"  • EternalBlue: {Colors.GREEN}NOT VULNERABLE{Colors.END}")
        
        if self.scan_results.get('os_info'):
            print(f"  • OS Detected: {self.scan_results.get('os_info')}")
        
        print(f"\n{Colors.BOLD}🎯 RECOMMENDATIONS:{Colors.END}")
        if eternalblue == True:
            print(f"  1. {Colors.RED}PATCH IMMEDIATELY - MS17-010 vulnerability!{Colors.END}")
        if self.scan_results.get('shares_count', 0) > 0:
            print("  2. Review discovered shares for proper permissions")
        if self.scan_results.get('open_ports', 0) > 2:
            print("  3. Close unnecessary ports")
        print("  4. Enable SMB signing")
        print("  5. Consider using SMBv3 with encryption")
        
        print(f"\n{Colors.GREEN}✓ Reports have been saved to files{Colors.END}")
    
    def run_scan(self):
        """Execute complete scan"""
        try:
            show_banner()
            self.log(f"Starting scan on target: {self.target}", "INFO")
            self.log(f"Scan mode: {self.scan_mode}", "INFO")
            
            # Check dependencies
            if not self.check_dependencies():
                if not self.force:
                    self.log("Some dependencies missing. Use -f to force scan.", "ERROR")
                    return False
            
            # Port scanning
            if not self.scan_ports():
                if not self.force:
                    self.log("No open SMB ports found. Use -f to force scan.", "WARNING")
                    return False
            
            # If port 445 shows different results, diagnose
            if 445 in [p['port'] for p in self.scan_results.get('ports', []) if p.get('status') == 'CLOSED']:
                self.diagnose_port_445()
            
            # Run additional checks if basic ports are open
            basic_ports_open = any(p['port'] in [139, 445] for p in self.scan_results.get('ports', []))
            
            if basic_ports_open or self.force:
                self.run_nmap_smb_scan()
                self.enumerate_shares()
                self.check_eternalblue()
            
            # Generate reports
            self.generate_report()
            self.print_summary()
            
            return True
            
        except KeyboardInterrupt:
            self.log("\nScan interrupted by user", "WARNING")
            return False
        except Exception as e:
            self.log(f"Unexpected error: {e}", "ERROR")
            return False

def main():
    parser = argparse.ArgumentParser(
        description='ZERO Scanner - Advanced SMB Security Assessment Tool by .Zer0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 zero_scanner.py 192.168.1.100           # Basic scan (ports 139,445)
  python3 zero_scanner.py 192.168.1.100 -m full   # Full SMB/AD port scan
  python3 zero_scanner.py 192.168.1.100 -v        # Verbose output
  python3 zero_scanner.py 192.168.1.100 -o report # Save to file
  python3 zero_scanner.py 192.168.1.100 -f        # Force scan
        """
    )
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-m', '--mode', choices=['basic', 'full'], default='basic',
                       help='Scan mode: basic (139,445) or full (all SMB/AD ports)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-f', '--force', action='store_true', 
                       help='Force scan even if ports appear closed')
    parser.add_argument('--no-banner', action='store_true', help='Hide banner')
    
    args = parser.parse_args()
    
    # Create scanner instance
    scanner = ZeroScanner(
        target=args.target,
        output=args.output,
        verbose=args.verbose,
        force=args.force,
        scan_mode=args.mode
    )
    
    if args.no_banner:
        # Override banner display
        scanner.__class__.show_banner = lambda self: None
    
    # Run scan
    success = scanner.run_scan()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()