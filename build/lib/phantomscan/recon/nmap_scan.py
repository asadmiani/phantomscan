import subprocess
from urllib.parse import urlparse


class NmapScanner:

    def clean_target(self, target):
        if target.startswith("http"):
            parsed = urlparse(target)
            return parsed.netloc
        return target

    def scan(self, target):

        cleaned_target = self.clean_target(target)

        command = ["nmap", "-sS", "-sV", "-Pn", "-T4", cleaned_target]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True
            )

            output = result.stdout

            structured = {
                "host": cleaned_target,
                "ports": [],
                "raw_output": output
            }

            for line in output.split("\n"):
                if "/tcp" in line and "open" in line:
                    parts = line.split()

                    port_protocol = parts[0]
                    port = port_protocol.split("/")[0]
                    protocol = port_protocol.split("/")[1]

                    service = parts[2] if len(parts) > 2 else ""
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""

                    structured["ports"].append({
                        "port": int(port),
                        "protocol": protocol,
                        "service": service,
                        "version": version
                    })

            return structured

        except Exception as e:
            return {
                "error": str(e),
                "ports": []
            }
