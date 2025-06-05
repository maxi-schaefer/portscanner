import os
import sys
import time
import socket
import errno
import datetime
import platform
import argparse
import threading
import subprocess

# Timeout sockets
socket.setdefaulttimeout(1)
startTime = time.time()

# Limit number of threads to prevent system overload
thread_limiter = threading.BoundedSemaphore(value=100)

open_ports = []
lock = threading.Lock()
stop_event = threading.Event()

# Port preset profiles
PORT_PRESETS = {
    "web": (80, 443),
    "mail": (25, 110),
    "ftp": (20, 21),
    "db": (3306, 5432),
    "all": (1, 65535)
}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389]

# =*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*==

def is_host_up(ip):
    common_ports = [22, 80, 443, 53, 135, 139, 445, 3306, 3389, 8080]

    for port in common_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    return True
        except:
            continue

    # Fallback to ICMP ping
    try:
        ping_flag = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(
            ["ping", ping_flag, "1", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        output = result.stdout.lower()
        if "destination host unreachable" in output:
            return False
        elif "request timed out" in output:
            return False
        elif "100% loss" in output:
            return False
        elif "reply from" in output:
            return True
    except:
        pass

    return False


# =*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*==

def scan_report_header(ip_or_host):
    try:
        ip = socket.gethostbyname(ip_or_host)
        try:
            host_name = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            host_name = "Unknown"

        print(f"Scan report for {ip_or_host} ({ip})")
        print(f"Resolved hostname: {host_name}")
        print(f"Host is {'up' if is_host_up(ip) else 'down'} (checked via TCP and ICMP fallback)")
        print(f"-"*50)
        
        return ip
    
    except socket.gaierror:
        print(f"Error: Could not resolve hostname: {ip_or_host}")
        sys.exit(1)

# =*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*==

def banner_grabbing(ip, port, verbose=False, detect_version=False):
    sock = None
    ssl_sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, port))

        if port == 443:
            try:
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                ssl_sock = context.wrap_socket(sock, server_hostname=ip)
                cert = ssl_sock.getpeercert()

                if verbose:
                    if cert:
                        subject = dict(x[0] for x in cert.get('subject', []))
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        return (
                            f"TLS Cert: CN={subject.get('commonName', '')}, "
                            f"Issuer={issuer.get('commonName', '')}, "
                            f"Expires={cert.get('notAfter', '')}"
                        )
                    else:
                        return "TLS handshake succeeded but no certificate details returned"
                else:
                    return "TLS handshake succeeded"

            except Exception as e:
                return f"TLS handshake failed: {e}" if verbose else ""

        # Generic Banner grabbing
        if port in (80, 8080, 8000): # HTTP
            sock.send(b"HEAD HTTP/1.1\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            
            if detect_version:
                for line in banner.splitlines():
                    if line.lower().startswith("server:"):
                        return line.strip()
                return "Unkown HTTP server"
            return banner.split("\n")[0]
        elif port == 21: # FTP
            sock.send(b"HELP\r\n")
        elif port == 22:  # SSH
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if detect_version:
                parts = banner.split("-")
                if len(parts) >= 3:
                    return f"{parts[1]}-{parts[2]}"
                return banner
            return banner

        elif port == 25: # SMTP
            sock.send(b"EHLO test\r\n")
        elif port == 110: # POP3
            sock.send(b"QUIT\r\n")
        elif port == 143: # IMAP
            sock.send(b"CAPABILITY\r\n")
        elif port == 3306: # MySQL
            return sock.recv(1024).decode(errors="ignore").strip()
        elif port == 6379: # Redis
            sock.send(b"INFO\r\n")
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode('utf-8', errors="ignore").strip()

        if detect_version and banner:
            lines = banner.splitlines()
            filtered = [line for line in lines if not line.lower().startswith("date:")]
            return " ".join(filtered).replace("\r", "")[:100]
        elif verbose:
            return banner.split("\n")[0]
        else:
            return ""


    except Exception as e:
        return f"Error: {e}" if verbose else ""

    finally:
        if ssl_sock:
            try:
                ssl_sock.close()
            except:
                pass
        elif sock:
            try:
                sock.close()
            except:
                pass
    
# =*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*==

def scan_range(network, start_port, end_port, verbose, detect_version):
    # Starts a TCP scan on a given IP adress range

    for host in range(1, 255):
        ip = f"{network}.{host}"
        if is_host_up(ip):
            print(f"\n[+] Host {ip} is up. Starting scan at {datetime.datetime.now()}")
            tcp_scan(ip, start_port, end_port, verbose, detect_version)
        else:
            if verbose:
                print(f"\n[-] Host {ip} is down. Skipping.")


    print(f"[+] TCP Scan on network {network} done!")

# =*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*==

def scan_port(ip, port, verbose, detect_version):
    if stop_event.is_set():
        return
    
    with thread_limiter:
        tcp = None

        try:
            if stop_event.is_set():
                return

            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.settimeout(2)
            result = tcp.connect_ex((ip, port))

            if result == 0:
                header = banner_grabbing(ip, port, verbose=verbose, detect_version=detect_version)
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"

                with lock:
                    if detect_version:
                        print(f"{port:<6}  {service:<15} {header}")
                    else:
                        print(f"{port:<6}  {service}")

                    open_ports.append(port)

            elif result == errno.ECONNREFUSED:
                with lock:
                    print(f"{port:<6}  closed           Connection refused")

        except Exception as e:
            if verbose:
                with lock:
                    print(f"Error on port {port}: {e}")

        finally:
            if tcp:
                tcp.close()
# =*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*==

def udp_scan_port(ip, port, verbose=False):
    if stop_event.is_set():
        return

    with thread_limiter:
        sock = None
        
        try:
            if stop_event.is_set():
                return
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)

            # Probes for well-known UDP services
            if port == 53:  # DNS
                probe = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
                        b"\x03www\x06google\x03com\x00\x00\x01\x00\x01"
            elif port == 123:  # NTP
                probe = b'\x1b' + 47 * b'\0'
            elif port == 161:  # SNMP
                probe = b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'
            else:
                probe = b"\x00"

            sock.sendto(probe, (ip, port))
            data, _ = sock.recvfrom(1024)

            try:
                service = socket.getservbyport(port, 'udp')
            except:
                service = "unknown"

            with lock:
                print(f"{port:<6}  {service:<15} {data[:20].hex()}...")

        except socket.timeout:
            if verbose:
                with lock:
                    print(f"{port:<6}  unknown         No response (open|filtered)")
        except Exception as e:
            if verbose:
                with lock:
                    print(f"{port:<6}  unknown         Error: {e}")
        finally:
            sock.close()

# =*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*==

def tcp_scan(ip, start_port, end_port, verbose=False, detect_version=False):
    if detect_version:
        print("\nPORT    SERVICE         VERSION")
    else:
        print("\nPORT    SERVICE")

    threads = []

    try:
        ip = socket.gethostbyname(ip)
    except socket.gaierror:
        print(f"Unable to resolve IP: {ip}")
        return []

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(ip, port, verbose, detect_version))
        threads.append(t)
        t.start()

    for thread in threads:
        thread.join()

    return open_ports


# =*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*==

def udp_scan(ip, start_port, end_port, verbose=False):
    print("\nPORT    SERVICE         RESPONSE")
    threads = []

    try:
        ip = socket.gethostbyname(ip)
    except socket.gaierror:
        print(f"Unable to resolve IP: {ip}")
        return

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=udp_scan_port, args=(ip, port, verbose))
        threads.append(t)
        t.start()

    for thread in threads:
        thread.join()

# =*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*==

def scan_host(ip, start_port, end_port, verbose, detect_version):
    # Starts a TCP scan on a given IP adress
    
    if is_host_up(ip):
        print(f"Starting TCP port scan on ip {ip}  at {datetime.datetime.now()}")
        ports = tcp_scan(ip, start_port, end_port, verbose, detect_version)
        print(f"\nPortscan done: {ip}, {len(ports)} port{'s' if len(ports) != 1 else ''} open. It took: {str(round(time.time() - startTime, 2))}s")
    elif verbose:
        print(f"\n[!] Host {ip} is down exiting gracefully.")
        sys.exit(0)

# =*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*==

def parse_port_range(port_arg):
    if '-' in port_arg:
        parts = port_arg.split('-')
        if len(parts) != 2 or not all(p.isdigit() for p in parts):
            raise argparse.ArgumentTypeError("Invalid port range format. Use <start>-<end>.")
        return int(parts[0]), int(parts[1])
    elif port_arg.isdigit():
        p = int(port_arg)
        return p, p
    else:
        raise argparse.ArgumentTypeError("Port must be a number or range like 80-443.")

# =*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*==

if __name__ == "__main__":
    try:
        
        # Arguments
        parser = argparse.ArgumentParser(
            description="Simple threaded TCP/UDP port scanner with banner grabbing and host detection.",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )

        parser.add_argument("ip", help="IP address or network prefix to scan")
        parser.add_argument("-u", help="Enable UDP scan instead of TCP", action="store_true", )
        parser.add_argument("-p", metavar="PORT", help="Port or port range (e.g. 80 or 80-443)", type=str)
        parser.add_argument("-P", metavar="PROFILE", help="Named port profile (web, mail, ftp, db, all)", type=str)
        parser.add_argument("-v", help="Enable verbose output", action="store_true")
        parser.add_argument("-V", help="Attempt to detect service versions", action="store_true")
        parser.add_argument("-n", help="Scan a /24 network instead of a single host", action="store_true")

        args = parser.parse_args()

        # Parse Port Profile
        if args.P:
            if args.P.lower() in PORT_PRESETS:
                start_port, end_port = PORT_PRESETS[args.P.lower()]
            else:
                print(f"Unkown profile. Use one of: ", ", ".join(PORT_PRESETS.keys()))

        # Parse port range
        if args.p:
            start_port, end_port = parse_port_range(args.p)
        else:
            start_port, end_port = 1, 1023

        if args.n:
            # Must ensure IP is a network prefix
            if len(args.ip.split(".")) != 3:
                print("Error: When using -n, IP must be a 3-octet network prefix like 192.168.0")
                sys.exit(1)
            scan_range(args.ip, start_port, end_port, args.v, args.V)
        else:
            resolved_ip = scan_report_header(args.ip)
            if args.u:
                print(f"Starting UDP port scan on ip {args.ip}  at {datetime.datetime.now()}")
                udp_scan(args.ip, start_port, end_port, verbose=args.v)
                print(f"\nUDP scan done: {args.ip}. It took: {str(round(time.time() - startTime, 2))}s")
            else:
                scan_host(resolved_ip, start_port, end_port, args.v, args.V)
    except KeyboardInterrupt:
        stop_event.set()
        print("\n[!] Scan interrupted by user. Exiting gracefully.")
        sys.exit(0)