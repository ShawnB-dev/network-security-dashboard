import time
try:
    from fpdf import FPDF, FPDFException
except ImportError:
    FPDF = None
    FPDFException = Exception

def create_pdf_report(report):
    """Generates a detailed PDF report from a security scan report dictionary."""
    import logging
    
    # Ensure the report contains necessary keys to prevent KeyError during PDF generation
    if not report or 'target' not in report:
        logging.error("Invalid report data provided to PDF generator.")
        return None

    if FPDF is None:
        logging.error("FPDF2 library not found. PDF generation aborted.")
        return None

    class PDF(FPDF):
        def header(self):
            self.set_font("helvetica", "B", 8)
            self.set_text_color(150)
            self.cell(0, 10, f"Target: {report['target']} | Generated: {time.strftime('%Y-%m-%d')}", border=0, align="R")
            self.ln(15)

        def footer(self):
            self.set_y(-15)
            self.set_font("helvetica", "I", 8)
            self.set_text_color(150)
            self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", border=0, align="C")

    pdf = PDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font("helvetica", "B", 18)
    pdf.cell(0, 15, f"Network Security Report: {report['target']}", new_x="LMARGIN", new_y="NEXT", align='C')
    pdf.set_font("helvetica", "I", 10)
    pdf.cell(0, 10, f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT", align='C')
    pdf.ln(10)
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "Scan Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 12)
    pdf.cell(0, 10, f"Overall Health Score: {report['overall_health_score']}/100", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"Status: {report['status']}", new_x="LMARGIN", new_y="NEXT")

    # Calculate Severity Summary for the Table
    severity_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for module_findings in report.get('detailed_findings', {}).values():
        for f in module_findings:
            sev = f.get('severity', 'INFO')
            if sev in severity_summary:
                severity_summary[sev] += 1

    # Mapping severities to RGB colors for PDF table cells
    severity_colors_rgb = {
        "CRITICAL": (238, 130, 238),  # Violet
        "HIGH": (255, 0, 0),          # Red
        "MEDIUM": (255, 165, 0),      # Orange
        "LOW": (0, 0, 255),           # Blue
        "INFO": (0, 128, 0)           # Green
    }

    pdf.ln(5)
    try:
        with pdf.table(text_align="CENTER") as table:
            header = table.row()
            header.cell("Severity Level")
            header.cell("Findings Count")
            for sev, count in severity_summary.items():
                row = table.row()
                row.cell(sev, background_color=severity_colors_rgb.get(sev))
                row.cell(str(count))
    except (FPDFException, AttributeError, Exception):
        pass

    pdf.ln(10)
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "Detailed Findings", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    for module, findings in report['detailed_findings'].items():
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, f"Module: {module}", new_x="LMARGIN", new_y="NEXT")
        if not findings:
            pdf.set_font("helvetica", "I", 10)
            pdf.cell(0, 10, "  No vulnerabilities detected.", new_x="LMARGIN", new_y="NEXT")
        for f in findings:
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(0, 8, f"  [{f['severity']}] {f['title']}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", "", 10)
            pdf.multi_cell(0, 5, f"  Description: {f['description']}")
            pdf.multi_cell(0, 5, f"  Mitigation: {f['mitigation']}")
            pdf.ln(2)
        pdf.ln(5)
    
    try:
        # fpdf2 output() returns a bytearray/bytes object by default when no filename is given.
        # We return it directly to avoid unnecessary buffer conversions that can trigger WinError 5.
        return pdf.output()
    except Exception as e:
        logging.error(f"Critical error during PDF binary output: {e}")
        return None