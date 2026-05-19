# phantomscan/main.py

"""
PhantomScan
Ultra Advanced Autonomous AI Security Framework
Author: Asad Ullah
"""

# =========================================
# IMPORTS
# =========================================

import os
import socket
import warnings
import datetime

from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

warnings.filterwarnings("ignore")

# =========================================
# BANNER
# =========================================

from phantomscan.banner import print_banner
from phantomscan.loader import boot_sequence

# =========================================
# CORE
# =========================================

from phantomscan.core.scope import ScopeValidator

# =========================================
# RECON
# =========================================

from phantomscan.recon.http_detect import HTTPDetector
from phantomscan.recon.nmap_scan import NmapScanner
from phantomscan.recon.fingerprint import FingerprintEngine

# =========================================
# SCANNERS
# =========================================

from phantomscan.scanner.crawler import WebCrawler
from phantomscan.scanner.param_extractor import ParamExtractor

from phantomscan.scanner.header_analyzer import HeaderAnalyzer
from phantomscan.scanner.advanced_sqli import AdvancedSQLiScanner
from phantomscan.scanner.advanced_xss import AdvancedXSSScanner
from phantomscan.scanner.idor_scanner import IDORScanner
from phantomscan.scanner.ssrf_scanner import SSRFScanner
from phantomscan.scanner.rce_scanner import RCEScanner
from phantomscan.scanner.lfi_scanner import LFIScanner

from phantomscan.scanner.api_scanner import APIScanner

# =========================================
# AI ENGINE
# =========================================

from phantomscan.ai_engine.risk_model import AdvancedRiskModel
from phantomscan.ai_engine.false_positive_filter import FalsePositiveFilter
from phantomscan.ai_engine.vuln_classifier import VulnerabilityClassifier
from phantomscan.ai_engine.cvss_v3 import CVSSv3Calculator

# =========================================
# STORAGE
# =========================================

from phantomscan.storage.db import Database
from phantomscan.storage.dataset import DatasetManager

# =========================================
# REPORTS
# =========================================

from phantomscan.reports.advanced_report import AdvancedReportGenerator


# =========================================
# COLORS
# =========================================

class Colors:

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"


# =========================================
# LOGGING
# =========================================

def info(message):
    print(f"{Colors.CYAN}[INFO]{Colors.RESET} {message}")


def success(message):
    print(f"{Colors.GREEN}[+]{Colors.RESET} {message}")


def warning(message):
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {message}")


def error(message):
    print(f"{Colors.RED}[-]{Colors.RESET} {message}")


# =========================================
# HELPERS
# =========================================

def extract_host(target):

    parsed = urlparse(target)

    if parsed.netloc:
        return parsed.netloc

    return parsed.path


def deduplicate_findings(findings):

    seen = set()
    unique = []

    for finding in findings:

        identifier = (
            finding.get("type"),
            finding.get("url"),
            finding.get("payload")
        )

        if identifier not in seen:

            seen.add(identifier)

            unique.append(finding)

    return unique


# =========================================
# CVSS METRICS
# =========================================

def get_cvss_metrics(vuln_type):

    vuln = vuln_type.lower()

    if "sql" in vuln:

        return {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "C": "H",
            "I": "H",
            "A": "H"
        }

    elif "xss" in vuln:

        return {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "R",
            "C": "L",
            "I": "L",
            "A": "N"
        }

    elif "idor" in vuln:

        return {
            "AV": "N",
            "AC": "L",
            "PR": "L",
            "UI": "N",
            "C": "H",
            "I": "L",
            "A": "N"
        }

    elif "ssrf" in vuln:

        return {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "C": "H",
            "I": "L",
            "A": "L"
        }

    elif "rce" in vuln:

        return {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "C": "H",
            "I": "H",
            "A": "H"
        }

    elif "lfi" in vuln:

        return {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "C": "H",
            "I": "L",
            "A": "L"
        }

    return {
        "AV": "N",
        "AC": "L",
        "PR": "N",
        "UI": "N",
        "C": "L",
        "I": "L",
        "A": "N"
    }


# =========================================
# URL SCANNER
# =========================================

def scan_single_url(
    url,
    scanners,
    risk_model,
    classifier,
    cvss,
    db,
    dataset,
    scan_id
):

    findings = []

    try:

        info(f"Scanning URL: {url}")

        params = scanners["params"].extract(url)

        findings.extend(scanners["headers"].analyze(url))
        findings.extend(scanners["sqli"].scan(url, params))
        findings.extend(scanners["xss"].scan(url, params))
        findings.extend(scanners["idor"].scan(url))
        findings.extend(scanners["ssrf"].scan(url))
        findings.extend(scanners["rce"].scan(url))
        findings.extend(scanners["lfi"].scan(url, params))

        for finding in findings:

            vuln_type = finding.get("type", "Unknown")

            risk_result = risk_model.compute_final_risk(finding)

            finding["risk_score"] = risk_result.get(
                "final_risk_score",
                5.0
            )

            finding["severity"] = risk_result.get(
                "final_severity",
                "Medium"
            )

            metrics = get_cvss_metrics(vuln_type)

            score, severity, vector = cvss.calculate(metrics)

            finding["cvss_score"] = score
            finding["cvss_severity"] = severity
            finding["cvss_vector"] = vector

            classification = classifier.classify(vuln_type)

            finding["category"] = classification.get(
                "category",
                "General"
            )

            finding["owasp"] = classification.get(
                "owasp",
                "N/A"
            )

            finding["cwe"] = classification.get(
                "cwe",
                "N/A"
            )

            db.insert_finding(scan_id, finding)

            dataset.add_entry(finding)

            warning(
                f"{vuln_type} detected at "
                f"{finding.get('url')}"
            )

    except Exception as e:

        error(f"Scanner error on {url}: {e}")

    return findings


# =========================================
# MAIN
# =========================================

def main():

    os.system("clear")

    print_banner()

    boot_sequence()

    print(
        f"\n{Colors.MAGENTA}"
        "=== ULTRA PHANTOMSCAN FRAMEWORK ==="
        f"{Colors.RESET}\n"
    )

    # =====================================
    # TARGET INPUT
    # =====================================

    target = input(
        "Enter target URL/domain: "
    ).strip()

    target = target.replace(" ", "")

    # FORCE HTTP
    if not target.startswith("http://") and not target.startswith("https://"):

        target = "http://" + target

    parsed = urlparse(target)

    host = parsed.netloc

    if not host:

        error("Invalid target")
        return

    # =====================================
    # DNS VALIDATION
    # =====================================

    try:

        resolved_ip = socket.gethostbyname(host)

        success(f"Resolved IP: {resolved_ip}")

    except Exception:

        error("Target does not exist or DNS failed")
        return

    # =====================================
    # SCOPE VALIDATION
    # =====================================

    scope = ScopeValidator()

    if not scope.validate(target):

        error("Target out of scope")
        return

    success("Target validated")

    # =====================================
    # INITIALIZE
    # =====================================

    info("Initializing modules...")

    http_detector = HTTPDetector()
    nmap_scanner = NmapScanner()
    fingerprint = FingerprintEngine()

    crawler = WebCrawler()

    api_scanner = APIScanner()

    risk_model = AdvancedRiskModel()
    classifier = VulnerabilityClassifier()
    cvss = CVSSv3Calculator()

    fp_filter = FalsePositiveFilter()

    db = Database()
    dataset = DatasetManager()

    reporter = AdvancedReportGenerator()

    scanners = {

        "params": ParamExtractor(),

        "headers": HeaderAnalyzer(),

        "sqli": AdvancedSQLiScanner(),

        "xss": AdvancedXSSScanner(),

        "idor": IDORScanner(),

        "ssrf": SSRFScanner(),

        "rce": RCEScanner(),

        "lfi": LFIScanner()
    }

    scan_id = db.insert_scan(
        target,
        str(datetime.datetime.now())
    )

    all_findings = []

    # =====================================
    # HTTP DETECTION
    # =====================================

    info("Running HTTP detection...")

    try:

        http_detector.detect(target)

    except Exception as e:

        error(f"HTTP detection error: {e}")

    # =====================================
    # NMAP
    # =====================================

    info("Running Recon Scan...")

    try:

        nmap_results = nmap_scanner.scan(target)

        ports = nmap_results.get("ports", [])

        if ports:

            success(
                f"{len(ports)} Open Ports Discovered"
            )

            print()

            for port in ports:

                print(
                    f"[OPEN] "
                    f"{port['port']}/{port['protocol']} "
                    f"- {port['service']}"
                )

            print()

        else:

            warning("No open ports discovered")

    except Exception as e:

        error(f"Recon failed: {e}")

    # =====================================
    # FINGERPRINTING
    # =====================================

    info("Running fingerprinting...")

    try:

        fingerprint.analyze(target)

        success("Fingerprinting completed")

    except Exception as e:

        error(f"Fingerprinting error: {e}")

    # =====================================
    # CRAWLING
    # =====================================

    info("Crawling target...")

    try:

        urls = crawler.crawl(target)

        if not urls:

            urls = [target]

    except Exception as e:

        error(f"Crawler error: {e}")

        urls = [target]

    success(f"{len(urls)} URLs discovered")

    # =====================================
    # SCANNING
    # =====================================

    info("Starting multi-threaded scan engine...")

    with ThreadPoolExecutor(max_workers=5) as executor:

        futures = [

            executor.submit(
                scan_single_url,
                url,
                scanners,
                risk_model,
                classifier,
                cvss,
                db,
                dataset,
                scan_id
            )

            for url in urls
        ]

        for future in as_completed(futures):

            try:

                findings = future.result()

                all_findings.extend(findings)

            except Exception as e:

                error(f"Thread error: {e}")

    # =====================================
    # API SCAN
    # =====================================

    info("Scanning APIs...")

    try:

        api_findings = api_scanner.scan(target)

        all_findings.extend(api_findings)

    except Exception as e:

        error(f"API scan error: {e}")

    # =====================================
    # FILTER FINDINGS
    # =====================================

    info("Filtering false positives...")

    all_findings = deduplicate_findings(all_findings)

    try:

        all_findings = fp_filter.filter(all_findings)

    except Exception as e:

        error(f"Filter error: {e}")

    # =====================================
    # REPORTS
    # =====================================

    info("Generating reports...")

    structured_findings = []

    for finding in all_findings:

        structured_findings.append({

            "title":
                finding.get("type", "Unknown"),

            "score":
                finding.get("risk_score", 5.0),

            "risk":
                finding.get("severity", "Medium"),

            "url":
                finding.get("url", "N/A"),

            "parameter":
                finding.get("parameter", "N/A"),

            "description":
                finding.get(
                    "description",
                    "No description."
                ),

            "impact":
                finding.get(
                    "impact",
                    "Unknown impact."
                ),

            "remediation":
                finding.get(
                    "remediation",
                    "Apply security fixes."
                ),

            "payload":
                finding.get(
                    "payload",
                    "N/A"
                ),

            "cvss_score":
                finding.get(
                    "cvss_score",
                    "N/A"
                ),

            "cvss_vector":
                finding.get(
                    "cvss_vector",
                    "N/A"
                ),

            "owasp":
                finding.get(
                    "owasp",
                    "N/A"
                ),

            "cwe":
                finding.get(
                    "cwe",
                    "N/A"
                )
        })

    try:

        html_report, pdf_report = reporter.generate_report(
            target,
            structured_findings
        )

        success(f"HTML report: {html_report}")

        success(f"PDF report: {pdf_report}")

    except Exception as e:

        error(f"Report generation failed: {e}")

    # =====================================
    # SUMMARY
    # =====================================

    print(
        f"\n{Colors.GREEN}"
        "========== SCAN SUMMARY =========="
        f"{Colors.RESET}"
    )

    print(f"Target        : {target}")
    print(f"URLs Crawled  : {len(urls)}")
    print(f"Findings      : {len(all_findings)}")

    print()

    success("PhantomScan completed successfully")


# =========================================
# ENTRY
# =========================================

def run():
    main()


if __name__ == "__main__":
    main()
