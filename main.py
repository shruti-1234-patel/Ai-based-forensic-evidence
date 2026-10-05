from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import pandas as pd
import shutil
import os
import sqlite3

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker
from sklearn.ensemble import IsolationForest
from fpdf import FPDF

# -------------------- APP SETUP --------------------

app = FastAPI()
templates = Jinja2Templates(directory="templates")

UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# -------------------- DATABASE SETUP --------------------

DATABASE_URL = "sqlite:///./forensic.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String)
    ip_address = Column(String)
    username = Column(String)
    failed_attempts = Column(Integer)
    login_hour = Column(Integer)
    anomaly = Column(Integer)
    risk_score = Column(Integer)

Base.metadata.create_all(bind=engine)

# -------------------- AI MODEL --------------------

def detect_anomalies(df):
    features = df[['failed_attempts', 'login_hour']]
    model = IsolationForest(contamination=0.2)
    df['anomaly'] = model.fit_predict(features)
    return df

# -------------------- RISK ENGINE --------------------

def calculate_risk(df):
    df['risk_score'] = 0
    df.loc[df['failed_attempts'] > 5, 'risk_score'] += 8
    df.loc[df['login_hour'] < 4, 'risk_score'] += 5
    df.loc[df['anomaly'] == -1, 'risk_score'] += 10
    return df

# -------------------- ROUTES --------------------

@app.get("/")
def home(request: Request):

    # Fetch summary for dashboard
    conn = sqlite3.connect("forensic.db")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE anomaly = -1")
    anomalies = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE risk_score >= 15")
    high_risk = cursor.fetchone()[0]

    conn.close()

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "total_logs": total_logs,
            "anomalies": anomalies,
            "high_risk": high_risk
        }
    )

# -------------------- Upload Logs --------------------

@app.post("/upload")
async def upload_log(file: UploadFile = File(...)):

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    df = pd.read_csv(file_path)
    df.dropna(inplace=True)

    df = detect_anomalies(df)
    df = calculate_risk(df)

    db = SessionLocal()

    for _, row in df.iterrows():
        log = Log(
            timestamp=row['timestamp'],
            ip_address=row['ip_address'],
            username=row['username'],
            failed_attempts=int(row['failed_attempts']),
            login_hour=int(row['login_hour']),
            anomaly=int(row['anomaly']),
            risk_score=int(row['risk_score'])
        )
        db.add(log)

    db.commit()
    db.close()

    # ✅ Redirect after upload
    return RedirectResponse(url="/", status_code=303)

# -------------------- PDF Report --------------------

@app.get("/report")
def get_report():

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

    return FileResponse("forensic_report.pdf")

# -------------------- Graph Data --------------------

@app.get("/summary-data")
def summary_data():

    conn = sqlite3.connect("forensic.db")
    cursor = conn.cursor()

    cursor.execute("SELECT risk_score, COUNT(*) FROM logs GROUP BY risk_score")
    data = cursor.fetchall()

    conn.close()

    labels = [str(row[0]) for row in data]
    values = [row[1] for row in data]

    return {"labels": labels, "values": values}