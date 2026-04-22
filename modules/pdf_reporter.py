"""
pdf_reporter.py
─────────────────────────────────────────────────────────────────────────────
Professional PDF Report Generator for BitLocker Key Finder
Generates forensic-grade reports with case info, results, and statistics
"""

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from datetime import datetime
import os

class PDFReporter:
    """Generate professional forensic reports in PDF format"""
    
    def __init__(self, filename, case_info=None):
        self.filename = filename
        self.case_info = case_info or {}
        self.doc = SimpleDocTemplate(
            filename,
            pagesize=letter,
            rightMargin=0.5*inch,
            leftMargin=0.5*inch,
            topMargin=0.5*inch,
            bottomMargin=0.5*inch,
        )
        self.styles = getSampleStyleSheet()
        self._setup_styles()
        self.story = []
        
    def _setup_styles(self):
        """Setup custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#4fc3f7'),
            spaceAfter=12,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#4fc3f7'),
            spaceAfter=10,
            spaceBefore=10,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['BodyText'],
            fontSize=10,
            spaceAfter=8
        ))
        
    def add_title(self):
        """Add report title and header"""
        self.story.append(Paragraph(
            "🔐 BitLocker Recovery Report",
            self.styles['CustomTitle']
        ))
        self.story.append(Spacer(1, 0.2*inch))
        
    def add_case_information(self):
        """Add case information section"""
        self.story.append(Paragraph(
            "CASE INFORMATION",
            self.styles['CustomHeading']
        ))
        
        case_data = [
            ["Field", "Value"],
            ["Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Case Number", self.case_info.get('case_number', 'N/A')],
            ["Investigator", self.case_info.get('investigator', 'N/A')],
            ["Device Name", self.case_info.get('device_name', 'N/A')],
            ["Evidence ID", self.case_info.get('evidence_id', 'N/A')],
        ]
        
        case_table = Table(case_data, colWidths=[2*inch, 4*inch])
        case_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1c2340')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#4fc3f7')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')])
        ]))
        
        self.story.append(case_table)
        self.story.append(Spacer(1, 0.2*inch))
        
    def add_scan_summary(self, summary_data):
        """Add scan summary section
        
        Args:
            summary_data: Dict with keys like:
                - scan_type: "Live RAM Extraction" or "Partition Scan"
                - scan_location: Path scanned
                - start_time: Scan start time
                - end_time: Scan end time
                - total_size: Size scanned
                - keys_found: Number of keys found
        """
        self.story.append(Paragraph(
            "SCAN SUMMARY",
            self.styles['CustomHeading']
        ))
        
        summary_rows = [
            ["Metric", "Value"],
            ["Scan Type", summary_data.get('scan_type', 'N/A')],
            ["Location/Source", summary_data.get('scan_location', 'N/A')],
            ["Start Time", summary_data.get('start_time', 'N/A')],
            ["End Time", summary_data.get('end_time', 'N/A')],
            ["Total Scanned", summary_data.get('total_size', 'N/A')],
            ["Keys Found", str(summary_data.get('keys_found', 0))],
            ["Success Rate", summary_data.get('success_rate', 'N/A')],
        ]
        
        summary_table = Table(summary_rows, colWidths=[2*inch, 4*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1c2340')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#4fc3f7')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')])
        ]))
        
        self.story.append(summary_table)
        self.story.append(Spacer(1, 0.2*inch))
        
    def add_findings(self, findings):
        """Add findings/results section
        
        Args:
            findings: List of dicts with keys:
                - key: Recovery key
                - validity: "Valid (mod-11)" or "Pattern-only"
                - encoding: UTF-8, UTF-16-LE, etc.
                - location: Memory offset or file path
                - status: Found, Verified, etc.
        """
        self.story.append(Paragraph(
            "FINDINGS - BitLocker RECOVERY KEYS",
            self.styles['CustomHeading']
        ))
        
        if not findings:
            self.story.append(Paragraph(
                "No BitLocker recovery keys found.",
                self.styles['CustomBody']
            ))
            self.story.append(Spacer(1, 0.2*inch))
            return
        
        # Create findings table
        findings_data = [["#", "Recovery Key", "Validity", "Encoding", "Location"]]
        
        for i, finding in enumerate(findings, 1):
            findings_data.append([
                str(i),
                finding.get('key', 'N/A')[:30] + "...",  # Truncate for display
                finding.get('validity', 'N/A'),
                finding.get('encoding', 'N/A'),
                finding.get('location', 'N/A')[:20] + "..."  # Truncate
            ])
        
        findings_table = Table(findings_data, colWidths=[0.4*inch, 2*inch, 1.2*inch, 0.8*inch, 1.6*inch])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1c2340')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#4fc3f7')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')])
        ]))
        
        self.story.append(findings_table)
        self.story.append(Spacer(1, 0.2*inch))
        
    def add_statistics(self, stats):
        """Add statistics section
        
        Args:
            stats: Dict with keys like:
                - total_valid: Number of valid keys
                - total_pattern_only: Number of pattern-only keys
                - encoding_breakdown: Dict of encoding counts
                - scan_speed: MB/s
                - false_positive_rate: Percentage
        """
        self.story.append(Paragraph(
            "STATISTICS",
            self.styles['CustomHeading']
        ))
        
        stats_data = [
            ["Metric", "Value"],
            ["Valid Keys (mod-11)", str(stats.get('total_valid', 0))],
            ["Pattern-Only Keys", str(stats.get('total_pattern_only', 0))],
            ["Total Keys Found", str(stats.get('total_valid', 0) + stats.get('total_pattern_only', 0))],
            ["False Positive Rate", stats.get('false_positive_rate', 'N/A')],
            ["Scan Speed", stats.get('scan_speed', 'N/A')],
        ]
        
        stats_table = Table(stats_data, colWidths=[2*inch, 4*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1c2340')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#4fc3f7')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')])
        ]))
        
        self.story.append(stats_table)
        self.story.append(Spacer(1, 0.2*inch))
        
    def add_forensic_notes(self):
        """Add forensic methodology and notes"""
        self.story.append(Paragraph(
            "FORENSIC METHODOLOGY",
            self.styles['CustomHeading']
        ))
        
        notes = """
        <b>Scan Method:</b> Pattern carving with mod-11 checksum validation<br/>
        <b>Encodings Tested:</b> UTF-8, UTF-16-LE, UTF-16-BE<br/>
        <b>Validation:</b> Microsoft mod-11 checksum algorithm (block % 11 == 0)<br/>
        <b>False Positive Filtering:</b> ~90% reduction through mod-11 validation<br/>
        <b>Tool:</b> BitLocker Key Finder v1.0 | FAST-NUCES Digital Forensics<br/>
        <b>Chain of Custody:</b> This report documents findings from authorized forensic investigation.
        """
        
        self.story.append(Paragraph(notes, self.styles['CustomBody']))
        self.story.append(Spacer(1, 0.2*inch))
        
    def add_disclaimer(self):
        """Add legal disclaimer"""
        self.story.append(Paragraph(
            "DISCLAIMER & LIMITATIONS",
            self.styles['CustomHeading']
        ))
        
        disclaimer = """
        <b>Authorized Use Only:</b> This tool is for authorized forensic investigations only.<br/>
        <b>Legal Compliance:</b> User is responsible for complying with all applicable laws and regulations.<br/>
        <b>Accuracy:</b> While mod-11 validation removes ~90% false positives, no guarantee of 100% accuracy.<br/>
        <b>Verification:</b> All found keys should be verified against saved recovery keys when possible.<br/>
        <b>Chain of Custody:</b> This report should be maintained as part of the evidence chain of custody.
        """
        
        self.story.append(Paragraph(disclaimer, self.styles['CustomBody']))
        
    def generate(self):
        """Generate the PDF report"""
        self.doc.build(self.story)
        return os.path.exists(self.filename)


def generate_ram_report(filename, case_info, findings, summary, stats):
    """Convenience function to generate RAM extraction report"""
    reporter = PDFReporter(filename, case_info)
    reporter.add_title()
    reporter.add_case_information()
    reporter.add_scan_summary(summary)
    reporter.add_findings(findings)
    reporter.add_statistics(stats)
    reporter.add_forensic_notes()
    reporter.add_disclaimer()
    return reporter.generate()


def generate_partition_report(filename, case_info, findings, summary, stats):
    """Convenience function to generate partition scan report"""
    reporter = PDFReporter(filename, case_info)
    reporter.add_title()
    reporter.add_case_information()
    reporter.add_scan_summary(summary)
    reporter.add_findings(findings)
    reporter.add_statistics(stats)
    reporter.add_forensic_notes()
    reporter.add_disclaimer()
    return reporter.generate()