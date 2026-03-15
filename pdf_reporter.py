from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import os
from config import REMEDIATION_MAP

def export_full_pdf_report(all_paths, graph_ref, filename="Full_Security_Audit.pdf"):

    report_dir = os.getenv('REPORT_PATH', '.') 
    full_path = os.path.join(report_dir, filename)

    doc = SimpleDocTemplate(full_path, pagesize=letter)

    """Generates a multi-page PDF audit for all detected attack paths."""
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Custom Styles / Safety check for SubTitle
    title_style = styles['Title']
    title_style.textColor = colors.darkblue
    subtitle_style = styles.get('Subtitle', styles.get('Heading2', styles['Normal']))
    h2_style = styles['Heading2']
    h3_style = styles['Heading3']
    normal_style = styles['Normal']
    
    # 1. Title Page
    story.append(Paragraph("Kubernetes Cluster Security Audit", title_style))
    story.append(Paragraph("Automated Attack Path & Risk Analysis Report", subtitle_style))
    story.append(Spacer(1, 30))

    # 2. Executive Summary
    story.append(Paragraph("1. Executive Summary", h2_style))
    total_paths = len(all_paths)
    
    # FIX: Use total_risk_score and .get() for safety
    critical_paths = len([p for p in all_paths if p.get('total_risk_score', 0) >= 15])
    highest_risk = all_paths[0].get('total_risk_score', 0) if all_paths else 0

    summary_data = [
        ["Metric", "Value"],
        ["Total Exploitable Paths Found", str(total_paths)],
        ["Critical Severity Paths", str(critical_paths)],
        ["Highest Path Risk Score", f"{highest_risk}/20"],
        ["Cluster Status", "VULNERABLE" if total_paths > 0 else "SECURE"]
    ]
    
    summary_table = Table(summary_data, colWidths=[200, 100])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), colors.darkblue),
        ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    # 3. Detailed Path Analysis
    story.append(Paragraph("2. Detailed Kill Chain Analysis", h2_style))
    for idx, p_data in enumerate(all_paths[:10]):
        score = p_data.get('total_risk_score', 0)
        severity = "CRITICAL" if score >= 15 else "HIGH" if score >= 8 else "MEDIUM"
        story.append(Paragraph(f"Path #{idx+1}: {severity} (Score: {score})", h3_style))
        
        path_text = ""
        path = p_data['path']
        for i in range(len(path) - 1):
            u, v = path[i], path[i+1]
            rel = graph_ref.G[u][v].get('relation', 'access')
            path_text += f"<b>{u}</b><br/>&nbsp;&nbsp;↓ <i>[{rel}]</i><br/>"
        path_text += f"<b>{path[-1]}</b>"
        
        story.append(Paragraph(path_text, normal_style))
        story.append(Spacer(1, 15))

    story.append(PageBreak())

    # 4. Remediation Roadmap
    story.append(Paragraph("3. Remediation Roadmap", h2_style))
    detected_vulnerabilities = set()
    for p_data in all_paths:
        path = p_data['path']
        for u, v in zip(path[:-1], path[1:]):
            rel = graph_ref.G[u][v].get('relation')
            if rel in REMEDIATION_MAP:
                detected_vulnerabilities.add(rel)

    for vuln_type in detected_vulnerabilities:
        advice = REMEDIATION_MAP[vuln_type]
        story.append(Paragraph(f"• <b>{vuln_type.replace('-', ' ').title()}:</b> {advice}", normal_style))
        story.append(Spacer(1, 8))

    doc.build(story)
    print(f"[+] Multi-page Security Audit exported to: {full_path}")