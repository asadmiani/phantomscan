"""
PhantomScan Advanced Report Generator
Author: Asad Ullah
"""

import os
import datetime

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak
)

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter

# =========================================
# REPORT GENERATOR
# =========================================

class AdvancedReportGenerator:

    def __init__(self):

        self.report_dir = "reports"

        os.makedirs(
            self.report_dir,
            exist_ok=True
        )

    # =====================================
    # GENERATE REPORT
    # =====================================

    def generate_report(
        self,
        target,
        findings
    ):

        timestamp = datetime.datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        html_file = (
            f"{self.report_dir}/"
            f"phantomscan_{timestamp}.html"
        )

        pdf_file = (
            f"{self.report_dir}/"
            f"phantomscan_{timestamp}.pdf"
        )

        # =================================
        # GENERATE HTML
        # =================================

        self.generate_html(
            target,
            findings,
            html_file
        )

        # =================================
        # GENERATE PDF
        # =================================

        self.generate_pdf(
            target,
            findings,
            pdf_file
        )

        return html_file, pdf_file

    # =====================================
    # HTML REPORT
    # =====================================

    def generate_html(
        self,
        target,
        findings,
        output
    ):

        html = f"""
        <html>
        <head>

        <title>PhantomScan Report</title>

        <style>

        body {{
            background: #0f172a;
            color: white;
            font-family: Arial;
            padding: 30px;
        }}

        h1 {{
            color: #38bdf8;
        }}

        .card {{
            background: #1e293b;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 10px;
        }}

        .critical {{
            color: red;
        }}

        .high {{
            color: orange;
        }}

        .medium {{
            color: yellow;
        }}

        .low {{
            color: lightgreen;
        }}

        </style>

        </head>

        <body>

        <h1>PhantomScan Security Report</h1>

        <h3>Target: {target}</h3>

        <h3>Total Findings: {len(findings)}</h3>

        <hr>
        """

        for finding in findings:

            severity = str(
                finding.get(
                    "risk",
                    "Medium"
                )
            ).lower()

            html += f"""

            <div class='card'>

            <h2 class='{severity}'>
            {finding.get('title')}
            </h2>

            <p><b>Severity:</b>
            {finding.get('risk')}</p>

            <p><b>CVSS:</b>
            {finding.get('cvss_score')}</p>

            <p><b>URL:</b>
            {finding.get('url')}</p>

            <p><b>Description:</b>
            {finding.get('description')}</p>

            <p><b>Impact:</b>
            {finding.get('impact')}</p>

            <p><b>Remediation:</b>
            {finding.get('remediation')}</p>

            <p><b>OWASP:</b>
            {finding.get('owasp')}</p>

            <p><b>CWE:</b>
            {finding.get('cwe')}</p>

            </div>
            """

        html += "</body></html>"

        with open(output, "w") as f:

            f.write(html)

    # =====================================
    # PDF REPORT
    # =====================================

    def generate_pdf(
        self,
        target,
        findings,
        output
    ):

        doc = SimpleDocTemplate(
            output,
            pagesize=letter
        )

        styles = getSampleStyleSheet()

        elements = []

        title = Paragraph(
            f"<b>PhantomScan Security Report</b>",
            styles['Title']
        )

        elements.append(title)

        elements.append(
            Spacer(1, 20)
        )

        target_text = Paragraph(
            f"<b>Target:</b> {target}",
            styles['BodyText']
        )

        elements.append(target_text)

        elements.append(
            Spacer(1, 20)
        )

        for finding in findings:

            vuln = Paragraph(
                f"<b>{finding.get('title')}</b>",
                styles['Heading2']
            )

            elements.append(vuln)

            elements.append(
                Paragraph(
                    f"Severity: {finding.get('risk')}",
                    styles['BodyText']
                )
            )

            elements.append(
                Paragraph(
                    f"CVSS: {finding.get('cvss_score')}",
                    styles['BodyText']
                )
            )

            elements.append(
                Paragraph(
                    f"URL: {finding.get('url')}",
                    styles['BodyText']
                )
            )

            elements.append(
                Paragraph(
                    f"Description: "
                    f"{finding.get('description')}",
                    styles['BodyText']
                )
            )

            elements.append(
                Paragraph(
                    f"Impact: "
                    f"{finding.get('impact')}",
                    styles['BodyText']
                )
            )

            elements.append(
                Paragraph(
                    f"Remediation: "
                    f"{finding.get('remediation')}",
                    styles['BodyText']
                )
            )

            elements.append(
                Spacer(1, 25)
            )

        doc.build(elements)
