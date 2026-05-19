"""
Autonomous AI Security Platform
Final Integrated Main Controller
Author: Asad Ullah
"""
from phantomscan.banner import print_banner
from phantomscan.loader import boot_sequence
from phantomscan.ai_engine.false_positive_filter import FalsePositiveFilter
#from modules.idor_engine import IDOREngine
#import requests

from phantomscan.ai_engine.vuln_classifier import VulnerabilityClassifier
from phantomscan.ai_engine.cvss_v3 import CVSSv3Calculator
import datetime

# Core
from phantomscan.core.scope import ScopeValidator
from phantomscan.core.classifier import ServiceClassifier
from phantomscan.core.decision_engine import DecisionEngine

# Recon
from phantomscan.recon.http_detect import HTTPDetector
from phantomscan.recon.nmap_scan import NmapScanner
from phantomscan.recon.fingerprint import FingerprintEngine

# Scanner
from phantomscan.scanner.crawler import WebCrawler
from phantomscan.scanner.param_extractor import ParamExtractor
from phantomscan.scanner.header_analyzer import HeaderAnalyzer
#from scanner.sqli_scanner import SQLiScanner
from phantomscan.scanner.advanced_sqli import AdvancedSQLiScanner
#from scanner.xss_scanner import XSSScanner
from phantomscan.scanner.advanced_xss import AdvancedXSSScanner
from phantomscan.scanner.api_scanner import APIScanner

# AI
from phantomscan.ai_engine.risk_model import AdvancedRiskModel

# Storage
from phantomscan.storage.db import Database
from phantomscan.storage.dataset import DatasetManager

# Reports
from phantomscan.reports.report_generator import ReportGenerator

def deduplicate_findings(findings):
    seen = set()
    unique = []

    for f in findings:
        identifier = (
            f.get("type"),
            f.get("url"),
            f.get("payload")
        )

        if identifier not in seen:
            seen.add(identifier)
            unique.append(f)

    return unique


def main():
    if __name__ == "__main__":
        print_banner()
        boot_sequence()
        print("[+] Initializing PhantomScan Engine...\n")

    # your existing code continues here
  #  print("=== Autonomous AI Security Platform ===\n")

    target = input("Enter target domain or URL: ").strip()
    # Normalize URL
    if not target.startswith("http"):
        target = "http://" + target

    # -------------------------------
    # Scope Validation
    # -------------------------------

    scope = ScopeValidator()

    if not scope.validate(target):
        print("[-] Target out of scope")
        return

    print("[+] Target validated")

    # -------------------------------
    # Initialize Components
    # -------------------------------

    http_detector = HTTPDetector()
    nmap_scanner = NmapScanner()
    fingerprint = FingerprintEngine()

    crawler = WebCrawler()
    param_extractor = ParamExtractor()
    header_analyzer = HeaderAnalyzer()
   # sqli_scanner = SQLiScanner()
    sqli_scanner = AdvancedSQLiScanner()
#    xss_scanner = XSSScanner()
    xss_scanner = AdvancedXSSScanner()
    api_scanner = APIScanner()

    risk_model = AdvancedRiskModel()
    decision_engine = DecisionEngine()
    fp_filter = FalsePositiveFilter()

    db = Database()
    dataset = DatasetManager()
    report = ReportGenerator()
    classifier = VulnerabilityClassifier()

    cvss = CVSSv3Calculator()

    # -------------------------------
    # Database: Insert Scan Record
    # -------------------------------

    scan_id = db.insert_scan(target, str(datetime.datetime.now()))

    all_findings = []

    # -------------------------------
    # HTTP Detection
    # -------------------------------

    print("[+] Detecting HTTP service...")
    http_info = http_detector.detect(target)
    print(http_info)

    # -------------------------------
    # Nmap Scan
    # -------------------------------
#   print("\n[+] Running Nmap scan...")
    print("[+] Running Nmap scan...")
    nmap_result = nmap_scanner.scan(target)

    print("\n[+] Open Ports Discovered:")

    if nmap_result.get("ports"):
        for port in nmap_result["ports"]:
            print(f"  - Port: {port['port']}/{port['protocol']}")
            print(f"    Service: {port['service']}")
            print(f"    Version: {port['version']}")
    else:
        print("  No open ports found.")

#    print("[+] Running Nmap scan...")
#    nmap_info = nmap_scanner.scan(target)
 #   print(nmap_info)

    # -------------------------------
    # Fingerprint
    # -------------------------------

    print("[+] Fingerprinting service...")
    formatted_target = target if target.startswith("http") else "http://" + target
    fingerprint_info = fingerprint.analyze(formatted_target)
    print(fingerprint_info)

    # -------------------------------
    # Crawl Website
    # -------------------------------

    print("[+] Crawling target...")
    urls = crawler.crawl(target)

    if not urls:
        urls = [target]

    print(f"[+] {len(urls)} URLs discovered")

    # -------------------------------
    # Scan Each URL
    # -------------------------------

    for url in urls:

        print(f"[+] Scanning: {url}")

        params = param_extractor.extract(url)

        header_findings = header_analyzer.analyze(url)
        sqli_findings = sqli_scanner.scan(url, params)
        xss_findings = xss_scanner.scan(url, params)

        findings = header_findings + sqli_findings + xss_findings

        for finding in findings:

            # ---------------- AI Risk ----------------
            risk_result = risk_model.compute_final_risk(finding)
            finding["risk_score"] = risk_result["final_risk_score"]
            finding["severity"] = risk_result["final_severity"]
            finding["computed_at"] = risk_result["computed_at"]

            # ---------------- CVSS ----------------
            if "SQL Injection" in finding.get("type", ""):
                metrics = {"AV":"N","AC":"L","PR":"N","UI":"N","C":"H","I":"H","A":"H"}

            elif "XSS" in finding.get("type", ""):
                metrics = {"AV":"N","AC":"L","PR":"N","UI":"R","C":"L","I":"L","A":"N"}

            else:
                metrics = {"AV":"N","AC":"L","PR":"N","UI":"N","C":"L","I":"L","A":"N"}

            cvss_score, cvss_severity, cvss_vector = cvss.calculate(metrics)

            finding["cvss_score"] = cvss_score
            finding["cvss_severity"] = cvss_severity
            finding["cvss_vector"] = cvss_vector

            # ---------------- Classification ----------------
            classification = classifier.classify(finding.get("type", ""))

            finding["category"] = classification["category"]
            finding["owasp"] = classification["owasp"]
            finding["cwe"] = classification["cwe"]

            # ---------------- Save ----------------
            db.insert_finding(scan_id, finding)
            dataset.add_entry(finding)

        all_findings.extend(findings)


    # -------------------------------
    # API Scan
    # -------------------------------

    print("[+] Scanning API endpoints...")
    api_findings = api_scanner.scan(target)

    for finding in api_findings:
        score = risk_model.score(finding)
        finding["risk_score"] = score

        db.insert_finding(scan_id, finding)
        dataset.add_entry(finding)

    all_findings.extend(api_findings)
    all_findings = deduplicate_findings(all_findings)
    # ----------------------------------
    # False Positive Reduction
    # ----------------------------------

    all_findings = fp_filter.filter(all_findings)

    # -------------------------------
    # Format Findings for Report
    # -------------------------------

    structured_findings = []

    for f in all_findings:


        structured = {
            "title": f.get("type") or "Unknown Vulnerability",

            "score": f.get("risk_score") or 5.0,

            "risk": f.get("severity") or "Medium",

            "url": f.get("url") or "N/A",

            "parameter": f.get("parameter") or "N/A",

            "description": f.get("description") 
                or f"{f.get('type','Vulnerability')} was detected during automated analysis.",

            "poc": f.get("payload") 
                or "Proof of concept not automatically captured.",

           "impact": f.get("impact") 
               or "This issue may expose the application to security risks.",

           "remediation": f.get("remediation") 
               or "Apply proper security best practices and input validation."
         }

        structured_findings.append(structured)

    # -------------------------------
    # Generate Report
    # -------------------------------

        all_findings = deduplicate_findings(all_findings)


    reporter = ReportGenerator()

    md_file, pdf_file = reporter.generate_full_report(
        target=target,
        findings=structured_findings
    )



    print("\n=== Scan Completed ===")
    print(f"[+] Report generated: {md_file}")
    print(f"[+] Report generated: {pdf_file}")
    print(f"[+] Total findings: {len(all_findings)}")
    print("[+] Results saved to database")

def run():
    main()

if __name__ == "__main__":
    main()
