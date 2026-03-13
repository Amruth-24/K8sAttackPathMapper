# pdf_reporter.py

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.colors import red, darkblue, black

def export_pdf_report(worst_path, blast, cycles, critical_res, filename="Kill_Chain_Report.pdf"):
    """Generates a professional PDF report from the graph analysis."""
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Custom Styles
    title_style = styles['Title']
    title_style.textColor = darkblue
    heading_style = styles['Heading2']
    normal_style = styles['Normal']
    alert_style = styles['Normal']
    alert_style.textColor = red

    # Title
    story.append(Paragraph("Kubernetes Attack Path: Kill Chain Report", title_style))
    story.append(Spacer(1, 12))

    # 1. Attack Path Section
    story.append(Paragraph("1. Critical Attack Path", heading_style))
    if worst_path:
        severity = "CRITICAL" if worst_path['total_risk_score'] >= 15 else "HIGH" if worst_path['total_risk_score'] >= 8 else "MEDIUM"
        story.append(Paragraph(f"<b>Status:</b> <font color='red'>VULNERABLE ({severity})</font>", normal_style))
        story.append(Paragraph(f"<b>Entry Point:</b> {worst_path['source']}", normal_style))
        story.append(Paragraph(f"<b>Target:</b> {worst_path['target']}", normal_style))
        story.append(Paragraph(f"<b>Total Hops:</b> {worst_path['total_hops']} | <b>Path Risk Score:</b> {worst_path['total_risk_score']}", normal_style))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("<b>Kill Chain Steps:</b>", normal_style))
        path = worst_path["path"]
        story.append(Paragraph(f"Start: {path[0]}", normal_style))
        
        # We extract edge data using the graph reference passed from the builder
        graph_ref = worst_path.get('graph_ref')
        for u, v in zip(path[:-1], path[1:]):
            edge_data = graph_ref.G[u][v] 
            cve_info = f" (CVE: {graph_ref.G.nodes[u].get('cve')})" if graph_ref.G.nodes[u].get('cve') else ""
            story.append(Paragraph(f"&nbsp;&nbsp;→ <i>[{edge_data.get('relation')}]</i> {v}{cve_info}", normal_style))
    else:
        story.append(Paragraph("<b>Status:</b> SECURE. No attack paths detected.", normal_style))

    story.append(Spacer(1, 20))

    # 2. Blast Radius Section
    story.append(Paragraph("2. Blast Radius Analysis", heading_style))
    blast_source = worst_path["source"] if worst_path else "Entry Point"
    if "error" not in blast:
        story.append(Paragraph(f"If <b>{blast_source}</b> is compromised, the attacker can reach <b>{blast['total_reachable']}</b> other resources within {blast['max_hops_checked']} hops.", normal_style))

    story.append(Spacer(1, 20))

    # 3. Cycles Section
    story.append(Paragraph("3. Circular Dependencies", heading_style))
    if cycles:
        story.append(Paragraph(f"Detected {len(cycles)} privilege loops:", alert_style))
        for c in cycles:
            story.append(Paragraph(f"&nbsp;&nbsp;• {' <-> '.join(c)}", normal_style))
    else:
        story.append(Paragraph("No circular privilege loops detected.", normal_style))

    story.append(Spacer(1, 20))

    # 4. Remediation Section
    story.append(Paragraph("4. Critical Node Remediation", heading_style))
    recommendation = critical_res.get('recommendation', critical_res.get('message'))
    story.append(Paragraph(f"<b>Recommendation:</b> {recommendation}", normal_style))

    # Build the PDF
    doc.build(story)
    print(f"[+] PDF Report successfully exported to: {filename}")