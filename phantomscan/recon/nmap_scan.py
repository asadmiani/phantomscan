import subprocess
import socket
import re
import time
from urllib.parse import urlparse


class NmapScanner:

    def __init__(self):

        self.common_ports = [
            21, 22, 23, 25,
            53, 80, 110, 111,
            135, 139, 143,
            443, 445, 993,
            995, 1723, 3306,
            3389, 5900, 8080,
            8443
        ]

    # =====================================
    # CLEAN TARGET
    # =====================================

    def clean_target(self, target):

        if target.startswith("http://") or target.startswith("https://"):

            parsed = urlparse(target)

            return parsed.netloc

        return target

    # =====================================
    # SOCKET FALLBACK
    # =====================================

    def socket_scan(self, host):

        print("[INFO] Starting socket fallback scan...")

        results = []

        for port in self.common_ports:

            try:

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                sock.settimeout(1)

                result = sock.connect_ex((host, port))

                if result == 0:

                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"

                    results.append({
                        "port": port,
                        "protocol": "tcp",
                        "service": service,
                        "version": "Unknown"
                    })

                sock.close()

            except:
                pass

        return results

    # =====================================
    # MAIN SCAN
    # =====================================

    def scan(self, target):

        start = time.time()

        host = self.clean_target(target)

        print(f"[INFO] Nmap scanning host: {host}")

        try:

            ip = socket.gethostbyname(host)

            print(f"[INFO] Resolved IP: {ip}")

        except Exception as e:

            print(f"[ERROR] Cannot resolve hostname: {e}")

            return {"ports": []}

        ports = []

        try:

            cmd = [
                "nmap",
                "-Pn",
                "-sS",
                "-sV",
                "--top-ports", "100",
                "-T4",
                host
            ]

            print("[DEBUG] Running Nmap scan...")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            output = result.stdout

            # =================================
            # PARSE NMAP OUTPUT
            # =================================

            lines = output.splitlines()

            for line in lines:

                if "/tcp" in line and "open" in line:

                    parts = re.split(r"\s+", line)

                    try:

                        port_proto = parts[0]

                        port = int(port_proto.split("/")[0])

                        protocol = port_proto.split("/")[1]

                        state = parts[1]

                        service = parts[2]

                        version = " ".join(parts[3:])

                        ports.append({
                            "port": port,
                            "protocol": protocol,
                            "service": service,
                            "version": version
                        })

                    except:
                        pass

            # =================================
            # FALLBACK
            # =================================

            if not ports:

                print("[WARNING] Nmap found no ports")

                ports = self.socket_scan(host)

        except Exception as e:

            print(f"[ERROR] Nmap scan failed: {e}")

            ports = self.socket_scan(host)

        elapsed = round(time.time() - start, 2)

        print(f"[INFO] Scan completed in {elapsed} seconds")

        return {
            "host": host,
            "ip": ip,
            "ports": ports
        }
