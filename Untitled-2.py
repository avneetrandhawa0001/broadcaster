#!/usr/bin/env python3
"""
Advanced Network & Port Scanner
For authorized security assessments only.
"""

import socket
import sys
import ipaddress
import threading
import argparse
from datetime import datetime
import concurrent.futures
import json

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def resolve_hostname(hostname):
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def scan_port(ip, port, timeout=1.0):
    """
    Scan a single port on a given IP.
    Returns (port, state, service_name) if open, else None.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            return (port, "open", service)
        return None
    except Exception:
        return None

def scan_host(ip, ports, timeout=1.0, max_workers=100):
    """
    Scan multiple ports on a single host using thread pool.
    """
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                port, state, service = result
                print(f"    {Colors.GREEN}[+] Port {port}/{state} - {service}{Colors.RESET}")
    
    return sorted(open_ports, key=lambda x: x[0])

def ping_sweep(ip_str, timeout=1.0):
    """
    Check if a host is alive via ICMP (simulated with TCP connection to common ports).
    Falls back to TCP ping since raw sockets require root.
    """
    try:
        # Try connecting to common ports as a reachability check
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        # Try port 80 (HTTP) and 443 (HTTPS) and 22 (SSH) - common open ports
        for port in [80, 443, 22]:
            result = sock.connect_ex((str(ip_str), port))
            if result == 0:
                sock.close()
                return True
        sock.close()
        return False
    except:
        return False

def discover_network(network_cidr, timeout=1.0, max_workers=50):
    """
    Discover live hosts on a network using concurrent ping sweeps.
    """
    network = ipaddress.IPv4Network(network_cidr, strict=False)
    live_hosts = []
    total = network.num_addresses
    
    print(f"{Colors.CYAN}[*] Scanning {network_cidr} ({total} addresses){Colors.RESET}")
    print(f"{Colors.YELLOW}[*] This may take a while...{Colors.RESET}\n")
    
    host_list = list(network.hosts())
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping_sweep, str(ip), timeout): ip for ip in host_list}
        
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            ip = futures[future]
            if future.result():
                live_hosts.append(str(ip))
                print(f"{Colors.GREEN}[+] Host alive: {ip}{Colors.RESET}")
            
            # Progress indicator every 100 hosts
            if (i + 1) % 100 == 0:
                print(f"{Colors.YELLOW}[*] Progress: {i+1}/{total} checked{Colors.RESET}")
    
    return sorted(live_hosts)

def dns_reverse_lookup(ip):
    """Attempt reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        return None

def get_banner(ip, port, timeout=2.0):
    """Grab service banner from open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Send a generic probe
        if port == 80 or port == 8080:
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
        elif port == 21:
            pass  # FTP sends banner on connect
        elif port == 25:
            sock.send(b"EHLO scan\r\n")
        elif port == 22:
            pass  # SSH sends banner on connect
        
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200] if banner else None
        except:
            sock.close()
            return None
    except:
        return None

def scan_network_ports(network_cidr, ports, timeout=1.0):
    """
    Full network scan: discover hosts then scan ports on each.
    """
    print(f"{Colors.BOLD}{Colors.CYAN}=== Network & Port Scanner ==={Colors.RESET}")
    print(f"{Colors.CYAN}Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    print(f"{Colors.CYAN}Target: {network_cidr}{Colors.RESET}\n")
    
    # Step 1: Discover live hosts
    print(f"{Colors.BOLD}{Colors.YELLOW}[Phase 1] Network Discovery{Colors.RESET}")
    print("-" * 50)
    live_hosts = discover_network(network_cidr, timeout)
    
    if not live_hosts:
        print(f"\n{Colors.RED}[-] No live hosts found.{Colors.RESET}")
        return
    
    print(f"\n{Colors.GREEN}[+] Found {len(live_hosts)} live host(s){Colors.RESET}\n")
    
    # Step 2: Port scan each live host
    print(f"{Colors.BOLD}{Colors.YELLOW}[Phase 2] Port Scanning{Colors.RESET}")
    print("-" * 50)
    
    results = {}
    for ip in live_hosts:
        print(f"\n{Colors.BOLD}[*] Scanning {ip}{Colors.RESET}")
        
        # Reverse DNS
        hostname = dns_reverse_lookup(ip)
        if hostname:
            print(f"    Hostname: {hostname}")
        
        print(f"    Scanning {len(ports)} ports...")
        open_ports = scan_host(ip, ports, timeout)
        
        # Banner grabbing on open ports
        banners = {}
        if open_ports:
            for port, state, service in open_ports:
                if port in [21, 22, 25, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]:
                    banner = get_banner(ip, port)
                    if banner:
                        banners[port] = banner
                        print(f"    {Colors.YELLOW}    Banner: {banner}{Colors.RESET}")
        
        results[ip] = {
            'hostname': hostname,
            'open_ports': open_ports,
            'banners': banners
        }
    
    return results

def generate_report(results, filename="scan_report.txt"):
    """Generate a formatted text report."""
    with open(filename, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("NETWORK SCAN REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        
        for ip, data in results.items():
            f.write(f"Host: {ip}\n")
            if data['hostname']:
                f.write(f"Hostname: {data['hostname']}\n")
            f.write("-" * 40 + "\n")
            
            if data['open_ports']:
                f.write(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}{'BANNER'}\n")
                f.write("-" * 60 + "\n")
                for port, state, service in data['open_ports']:
                    banner = data['banners'].get(port, '')
                    f.write(f"{port:<10}{state:<10}{service:<15}{banner}\n")
            else:
                f.write("No open ports found.\n")
            f.write("\n")
    
    print(f"\n{Colors.GREEN}[+] Report saved to {filename}{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Network & Port Scanner - For Authorized Testing Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 network_scanner.py 192.168.1.0/24
  python3 network_scanner.py 192.168.1.0/24 -p 22,80,443,8080 -t 0.5
  python3 network_scanner.py 192.168.1.0/24 --fast
  python3 network_scanner.py 10.0.0.0/24 -o json
        """
    )
    
    parser.add_argument("target", help="Network CIDR (e.g., 192.168.1.0/24) or single IP")
    parser.add_argument("-p", "--ports", help="Ports to scan (comma-separated, range, or 'top')", default="top")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Max worker threads (default: 100)")
    parser.add_argument("-o", "--output", choices=['text', 'json'], default='text', help="Output format")
    parser.add_argument("--fast", action="store_true", help="Fast mode: only scan top 20 ports")
    
    args = parser.parse_args()
    
    # Determine ports to scan
    if args.fast:
        # Top 20 most common ports
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 8080, 8443]
    elif args.ports == 'top':
        # Extended common ports
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 8080, 8443, 
                 20, 69, 79, 88, 102, 161, 162, 389, 514, 636, 873, 993, 995, 1080, 1194, 1352, 1433, 1521, 1723, 2049, 2375, 2376,
                 3128, 3268, 3269, 3306, 3389, 3478, 4369, 4444, 4789, 5000, 5432, 5555, 5672, 5900, 5985, 5986, 6379, 6443, 6580,
                 7001, 7002, 8000, 8009, 8080, 8081, 8090, 8443, 8888, 9000, 9090, 9100, 9200, 9418, 9999, 10000, 11211, 27017, 27018, 50070]
    else:
        # Custom ports
        ports = []
        for part in args.ports.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
    
    # Check if target is CIDR or single IP
    if '/' in args.target:
        # Network scan
        results = scan_network_ports(args.target, ports, args.timeout)
    else:
        # Single host scan
        ip = resolve_hostname(args.target)
        if not ip:
            print(f"{Colors.RED}[-] Could not resolve {args.target}{Colors.RESET}")
            sys.exit(1)
        
        print(f"{Colors.BOLD}{Colors.CYAN}=== Port Scanner ==={Colors.RESET}")
        print(f"{Colors.CYAN}Target: {args.target} ({ip}){Colors.RESET}")
        print(f"{Colors.CYAN}Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}\n")
        
        hostname = dns_reverse_lookup(ip)
        if hostname:
            print(f"Hostname: {hostname}")
        
        print(f"Scanning {len(ports)} ports...\n")
        print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}{'BANNER'}")
        print("-" * 60)
        
        open_ports = scan_host(ip, ports, args.timeout, args.workers)
        
        results = {}
        banners = {}
        for port, state, service in open_ports:
            if port in [21, 22, 25, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]:
                banner = get_banner(ip, port)
                if banner:
                    banners[port] = banner
                    print(f"{port:<10}{state:<10}{service:<15}{banner}")
        
        results[ip] = {
            'hostname': hostname,
            'open_ports': open_ports,
            'banners': banners
        }
    
    # Output results
    if args.output == 'json':
        json_output = {}
        for ip, data in results.items():
            json_output[ip] = data
        print(json.dumps(json_output, indent=2))
    else:
        generate_report(results)
    
    print(f"\n{Colors.GREEN}[+] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user.{Colors.RESET}")
        sys.exit(0)
    except PermissionError:
        print(f"{Colors.RED}[-] Permission denied. Try running with appropriate privileges.{Colors.RESET}")
        sys.exit(1)
        
python3 network_scanner.py 192.168.1.0/24