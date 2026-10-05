from fpdf import FPDF
import sqlite3

def generate_report():
    conn = sqlite3.connect("forensic.db")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE anomaly = -1")
    anomalies = cursor.fetchone()[0]

    cursor.execute("SELECT ip_address, risk_score FROM logs ORDER BY risk_score DESC LIMIT 5")
    top_risk = cursor.fetchall()

    conn.close()

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, "AI Digital Forensics Report", ln=True)
    pdf.cell(200, 10, f"Total Logs: {total_logs}", ln=True)
    pdf.cell(200, 10, f"Anomalies Detected: {anomalies}", ln=True)

    pdf.cell(200, 10, "Top 5 Risk Events:", ln=True)

    for ip, score in top_risk:
        pdf.cell(200, 10, f"{ip} - Risk Score: {score}", ln=True)

    pdf.output("forensic_report.pdf")