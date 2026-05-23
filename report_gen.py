import os
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 Table, TableStyle, HRFlowable)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

W, H = A4
BG=colors.HexColor("#0A0E1A"); GREEN=colors.HexColor("#00FF88")
BLUE=colors.HexColor("#00BFFF"); RED=colors.HexColor("#FF4444")
GOLD=colors.HexColor("#FFD700"); CARD=colors.HexColor("#0F1A2E")
WHITE=colors.white; GRAY=colors.HexColor("#8899AA")

def draw_bg(c, doc):
    c.saveState()
    c.setFillColor(BG); c.rect(0,0,W,H,fill=1,stroke=0)
    c.setFillColor(GREEN); c.rect(0,H-4,W,4,fill=1,stroke=0)
    c.setFillColor(RED); c.rect(0,0,W,4,fill=1,stroke=0)
    c.restoreState()

def mk(txt, bold=False, color=WHITE, size=9, align=TA_LEFT):
    return Paragraph(str(txt), ParagraphStyle("x",
        fontName="Helvetica-Bold" if bold else "Helvetica",
        fontSize=size, textColor=color, alignment=align))

def card_table(rows, widths, bg=CARD, border=BLUE):
    t = Table(rows, colWidths=widths)
    t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),bg),
        ("BOX",(0,0),(-1,-1),1,border),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[bg,colors.HexColor("#0A1628")]),
        ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("LEFTPADDING",(0,0),(-1,-1),7),("RIGHTPADDING",(0,0),(-1,-1),7),
    ]))
    return t

def generate_report(results):
    os.makedirs("reports", exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/vuln_report_{ts}.pdf"
    doc = SimpleDocTemplate(filename, pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm, topMargin=14*mm, bottomMargin=14*mm)
    story = []
    story.append(Paragraph("VULNERABILITY ASSESSMENT REPORT", ParagraphStyle("h",
        fontName="Helvetica-Bold", fontSize=20, textColor=GREEN, alignment=TA_CENTER)))
    story.append(Paragraph("Automated Scan  |  Confidential", ParagraphStyle("s",
        fontName="Helvetica", fontSize=9, textColor=GRAY, alignment=TA_CENTER, spaceAfter=4)))
    story.append(HRFlowable(width="100%", thickness=1.5, color=GREEN, spaceAfter=8))
    total_ports = sum(len(h["ports"]) for h in results["hosts"])
    total_vulns = sum(sum(len(p["vulns"]) for p in h["ports"]) for h in results["hosts"])
    risk = "CRITICAL" if total_vulns>5 else "HIGH" if total_vulns>2 else "MEDIUM" if total_vulns>0 else "LOW"
    risk_color = RED if risk in ("CRITICAL","HIGH") else GOLD if risk=="MEDIUM" else GREEN
    meta = [["Target",results["target"]],["Scan Time",results["scan_time"]],
            ["Hosts Found",str(len(results["hosts"]))],["Open Ports",str(total_ports)],
            ["Vulns Found",str(total_vulns)],["Risk Level",risk]]
    story.append(card_table([[mk(r[0],True,GOLD),mk(r[1],color=risk_color if r[0]=="Risk Level" else WHITE)] for r in meta],[45*mm,130*mm]))
    story.append(Spacer(1,10))
    for host in results["hosts"]:
        story.append(HRFlowable(width="100%", thickness=0.5, color=BLUE, spaceAfter=4))
        story.append(Paragraph(f"HOST: {host['ip']}  ({host['hostname']})",
            ParagraphStyle("hh",fontName="Helvetica-Bold",fontSize=12,textColor=BLUE,spaceAfter=4)))
        info=[["IP Address",host["ip"]],["Hostname",host["hostname"]],
              ["State",host["state"]],["OS Guess",host["os_guess"]]]
        story.append(card_table([[mk(r[0],True,GOLD),mk(r[1])] for r in info],[45*mm,130*mm]))
        story.append(Spacer(1,6))
        if host["ports"]:
            story.append(mk("Open Ports and Services",True,GREEN,size=10))
            story.append(Spacer(1,3))
            hdr=[mk("Port",True,BLUE),mk("Protocol",True,BLUE),mk("Service",True,BLUE),mk("Version",True,BLUE),mk("Vulns",True,BLUE)]
            port_rows=[hdr]
            for p in host["ports"]:
                vc=len(p["vulns"]); col=RED if vc>0 else GREEN
                port_rows.append([mk(str(p["port"]),True,GOLD),mk(p["proto"]),mk(p["service"]),mk(p["version"],size=8),mk(str(vc) if vc else "-",bold=(vc>0),color=col)])
            story.append(card_table(port_rows,[18*mm,22*mm,25*mm,80*mm,18*mm],border=GREEN))
            story.append(Spacer(1,6))
            for p in host["ports"]:
                for v in p["vulns"]:
                    story.append(Paragraph(f"WARNING Port {p['port']} - {v['script']}",
                        ParagraphStyle("vt",fontName="Helvetica-Bold",fontSize=9,textColor=RED,spaceBefore=4)))
                    story.append(Paragraph(v["output"].replace("\n"," "),
                        ParagraphStyle("vb",fontName="Helvetica",fontSize=7.5,textColor=WHITE,
                        leading=11,backColor=colors.HexColor("#1A0A0A"),leftIndent=8,rightIndent=8,borderPad=5,spaceAfter=3)))
        story.append(Spacer(1,8))
    story.append(HRFlowable(width="100%",thickness=1,color=GOLD,spaceAfter=4))
    story.append(mk("RECOMMENDATIONS",True,GOLD,size=11))
    story.append(Spacer(1,4))
    recs=[("Close unnecessary ports","Disable any service not required."),
          ("Update all services","Patch outdated software versions."),
          ("Firewall rules","Restrict access using iptables or ufw."),
          ("Regular scanning","Run scans weekly to detect new vulns."),
          ("Network segmentation","Isolate critical systems into VLANs.")]
    rec_rows=[[mk("#",True,BLUE),mk("Finding",True,BLUE),mk("Action",True,BLUE)]]
    for i,(f,a) in enumerate(recs,1):
        rec_rows.append([mk(str(i),True,GOLD),mk(f,True),mk(a)])
    story.append(card_table(rec_rows,[10*mm,60*mm,105*mm],border=GOLD))
    story.append(Spacer(1,8))
    story.append(HRFlowable(width="100%",thickness=0.5,color=GRAY))
    story.append(Paragraph("Generated by Vuln-Scanner  |  Author: Syed Mahammedafzal  |  github.com/SYEDMAHAMMEDAFZAL",
        ParagraphStyle("ft",fontName="Helvetica",fontSize=7,textColor=GRAY,alignment=TA_CENTER)))
    doc.build(story, onFirstPage=draw_bg, onLaterPages=draw_bg)
    return filename
