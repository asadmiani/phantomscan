import os
import re
import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch


class ReportGenerator:

    def __init__(self):
        self.reports_dir = "reports"
        os.makedirs(self.reports_dir, exist_ok=True)

    # -----------------------------
    # Clean filename
    # -----------------------------
    def _sanitize_target(self, target):
        target = target.replace("http://", "").replace("https://", "")
        return re.sub(r"[^a-zA-Z0-9.-]", "_", target)

    # -----------------------------
    # Markdown Style Report
    # -----------------------------
    def generate_markdown(self, target, findings):

        safe_target = self._sanitize_target(target)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        filename = os.path.join(
            self.reports_dir,
            f"{safe_target}_{timestamp}.md"
        )

        now = datetime.datetime.now()

        content = f"# Vulnerability Report\n"
        content += f"Target: {target}\n"
        content += f"Generated on {now}\n\n"
        content += "=" * 60 + "\n\n"

        if not findings:
            content += "No vulnerabilities detected.\n"
        else:
            for finding in findings:

                content += f"Title: {finding.get('title','Unknown')}\n"
                content += f"Severity: {finding.get('score','N/A')}/10\n"
                content += f"Risk Level: {finding.get('risk','N/A')}\n"
                content += f"URL: {finding.get('url','N/A')}\n"
                content += f"Parameter: {finding.get('parameter') or "N/A"}\n\n"

                content += "Description:\n"
                content += f"{finding.get('description') or "N/A"}\n\n"
                content += "Proof of Concept:\n"
                content += f"{finding.get('poc') or "N/A"}\n\n"

                content += "Impact:\n"
                content += f"{finding.get('impact') or "N/A"}\n\n"

                content += "Remediation:\n"
                content += f"{finding.get('remediation') or "N/A"}\n\n"

                content += "-" * 60 + "\n\n"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)

        return filename

    # -----------------------------
    # PDF Version (same structure)
    # -----------------------------
    def generate_pdf(self, target, findings):

        safe_target = self._sanitize_target(target)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        filename = os.path.join(
            self.reports_dir,
            f"{safe_target}_{timestamp}.pdf"
        )

        doc = SimpleDocTemplate(filename)
        elements = []
        styles = getSampleStyleSheet()
        normal = styles["Normal"]

        now = datetime.datetime.now()

        elements.append(Paragraph(f"<b>Vulnerability Report</b>", styles["Heading1"]))
        elements.append(Spacer(1, 0.3 * inch))
        elements.append(Paragraph(f"Target: {target}", normal))
        elements.append(Paragraph(f"Generated on {now}", normal))
        elements.append(Spacer(1, 0.5 * inch))

        if not findings:
            elements.append(Paragraph("No vulnerabilities detected.", normal))
        else:
            for finding in findings:

                elements.append(Paragraph(
                    f"<b>Title:</b> {finding.get('title','Unknown')}", normal))
                elements.append(Paragraph(
                    f"<b>Severity:</b> {finding.get('score','N/A')}/10", normal))
                elements.append(Paragraph(
                    f"<b>Risk Level:</b> {finding.get('risk','N/A')}", normal))
                elements.append(Paragraph(
                    f"<b>URL:</b> {finding.get('url','N/A')}", normal))
                elements.append(Paragraph(
                    f"<b>Parameter:</b> {finding.get('parameter','N/A')}", normal))

                elements.append(Spacer(1, 0.3 * inch))

                elements.append(Paragraph(
                    f"<b>Description:</b> {finding.get('description') or "N/A"}", normal))
                elements.append(Paragraph(
                    f"<b>Proof of Concept:</b> {finding.get('poc') or "N/A"}", normal))
                elements.append(Paragraph(
                    f"<b>Impact:</b> {finding.get('impact') or "N/A"}", normal))
                elements.append(Paragraph(
                    f"<b>Remediation:</b> {finding.get('remediation') or "N/A"}", normal))

                elements.append(Spacer(1, 0.5 * inch))

        doc.build(elements)
        return filename

    # -----------------------------
    # Generate Both
    # -----------------------------
    def generate_full_report(self, target, findings):
        md = self.generate_markdown(target, findings)
        pdf = self.generate_pdf(target, findings)
        return md, pdf
