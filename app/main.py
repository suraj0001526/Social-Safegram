import os
import shutil
import hashlib
import requests
import json
import base64
import joblib
import numpy as np
from typing import List, Optional

# --- FASTAPI IMPORTS ---
from fastapi import FastAPI, File, UploadFile, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# --- MODULE IMPORTS ---
# Ensure these exist in your app/core folder
from app.core.feature_extractor import extract_features
from app.core.steganography import hide_message, reveal_message
from app.core.crypto_logic import generate_key, encrypt_text, decrypt_text
from app.core.report_logic import generate_pdf_report
from app.core.phishing_logic import assess_url

# --- APP SETUP ---
app = FastAPI(title="Social Safegram")

# Allow Frontend to talk to Backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="app/templates")

# --- GLOBAL EXCEPTION HANDLER ---
@app.exception_handler(500)
async def internal_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": f"Internal Server Error: {str(exc)}"},
    )

# --- MODELS ---
class URLRequest(BaseModel):
    url: str

class CryptoInput(BaseModel):
    text: str
    key: str

# --- 1. HOME ROUTE ---
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# --- 2. MALWARE SCANNER (VirusTotal) ---
# REPLACE WITH YOUR REAL KEY
VT_API_KEY = "2406ac5471b313b3ec857d7cd32b2463e8b814559911883ecc323db6b0b5dddf" 

@app.post("/scan-file/")
async def scan_file(file: UploadFile = File(...)):
    sha256_hash = hashlib.sha256()
    while chunk := await file.read(8192):
        sha256_hash.update(chunk)
    await file.seek(0)
    file_hash = sha256_hash.hexdigest()
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            
            if malicious > 0:
                return {"status": "⚠️ MALWARE DETECTED", "risk_score": f"{malicious}/70 Engines", "risk_level": "Critical"}
            else:
                return {"status": "✅ Clean File", "risk_score": "0/70 Engines", "risk_level": "Safe"}
        elif response.status_code == 404:
            return {"status": "❓ Unknown File", "risk_score": "Not in Database", "risk_level": "Unknown"}
        else:
            return {"error": f"VirusTotal Error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# --- 3. PHISHING SCANNER ---
@app.post("/scan-url/")
def scan_url(request: URLRequest):
    return assess_url(request.url, VT_API_KEY)

# --- 4. STEGANOGRAPHY: HIDE (FIXED) ---
@app.post("/stego/hide/")
async def stego_hide(
    file: UploadFile = File(...), 
    message: str = Form(...)    # <--- THIS LINE FIXES YOUR ERROR
):
    clean_filename = os.path.basename(file.filename)
    temp_input = f"temp_in_{clean_filename}"
    temp_output = f"hidden_{clean_filename}"
    
    try:
        with open(temp_input, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        result = hide_message(temp_input, message, temp_output)
        
        if result["status"] == "success":
            return FileResponse(temp_output, media_type="image/png", filename=f"secret_{clean_filename}")
        else:
            return JSONResponse(status_code=400, content={"error": result["message"]})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        if os.path.exists(temp_input):
            try: os.remove(temp_input) 
            except: pass

# --- 5. STEGANOGRAPHY: REVEAL ---
@app.post("/stego/reveal/")
async def stego_reveal(file: UploadFile = File(...)):
    clean_filename = os.path.basename(file.filename)
    temp_input = f"temp_reveal_{clean_filename}"
    try:
        with open(temp_input, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        return reveal_message(temp_input)
    finally:
        if os.path.exists(temp_input):
            try: os.remove(temp_input) 
            except: pass

# --- 6. CRYPTOGRAPHY ---
@app.get("/crypto/get-key/")
def get_new_key():
    return {"key": generate_key()}

@app.post("/crypto/encrypt/")
def encrypt(data: CryptoInput):
    return {"encrypted_text": encrypt_text(data.text, data.key)}

@app.post("/crypto/decrypt/")
def decrypt(data: CryptoInput):
    return {"decrypted_text": decrypt_text(data.text, data.key)}

# --- 7. REPORTING ---
@app.post("/report/generate/")
async def create_report(
    name: str = Form(...),
    contact: str = Form(...),
    type: str = Form(...),
    date: str = Form(...),
    description: str = Form(...),
    files: List[UploadFile] = File(None) 
):
    temp_image_paths = []
    if files:
        for file in files:
            if not file.filename: continue
            temp_path = f"temp_{file.filename}"
            with open(temp_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            temp_image_paths.append(temp_path)

    data = {"name": name, "contact": contact, "type": type, "date": date, "description": description}

    try:
        pdf_bytes = generate_pdf_report(data, temp_image_paths)
        return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=incident_report.pdf"})
    finally:
        for path in temp_image_paths:
            if os.path.exists(path): os.remove(path)

# --- 8. AWARENESS TIPS (SIMPLIFIED) ---
AWARENESS_TIPS = [
    {"icon": "🔐", "title": "Enable 2FA", "desc": "Turn on Two-Factor Authentication for email, banking, and social media."},
    {"icon": "👆", "title": "Hover Before Clicking", "desc": "Hover over links to see the real URL before clicking."},
    {"icon": "🔄", "title": "Update Everything", "desc": "Keep your OS and apps updated to patch security holes."},
    {"icon": "🛑", "title": "Don't Reuse Passwords", "desc": "If one site gets hacked, attackers will try that password everywhere."},
    {"icon": "📶", "title": "Avoid Public WiFi", "desc": "Use mobile data or a VPN instead of free airport/cafe WiFi."},
    {"icon": "📷", "title": "Cover Your Webcam", "desc": "Use a physical cover or tape when not in use."},
    {"icon": "🏦", "title": "Monitor Accounts", "desc": "Check bank statements weekly for unauthorized charges."},
    {"icon": "📧", "title": "Verify Senders", "desc": "Check the actual email address, not just the display name."},
    {"icon": "💾", "title": "Backup Data", "desc": "Keep a copy of important files on an external hard drive."},
    {"icon": "🔒", "title": "Lock Your Devices", "desc": "Set a short screen timeout and use strong PINs."},
    {"icon": "🕶️", "title": "Limit Social Sharing", "desc": "Don't post travel plans or personal details publicly."},
    {"icon": "🔌", "title": "Avoid Unknown USBs", "desc": "Never plug in a USB drive you found on the ground."},
    {"icon": "🛡️", "title": "Use Antivirus", "desc": "Keep Windows Defender or other AV software active."},
    {"icon": "🛒", "title": "Check HTTPS", "desc": "Only enter credit card info on sites with a lock icon."},
    {"icon": "🚮", "title": "Delete Old Accounts", "desc": "Remove unused accounts to reduce your digital footprint."},
    {"icon": "🕵️", "title": "Watch for Urgency", "desc": "Scammers create false urgency. Stop, Look, and Think."},
    {"icon": "📱", "title": "Review App Permissions", "desc": "Don't give a flashlight app access to your contacts."},
    {"icon": "🚪", "title": "Log Out", "desc": "Always log out of shared or public computers immediately."},
    {"icon": "🩸", "title": "Beware 'Free' Stuff", "desc": "Cracked software often contains hidden malware."},
    {"icon": "🧠", "title": "Trust Your Gut", "desc": "If an offer looks too good to be true, it is."}
]

@app.get("/awareness/tips/")
def get_awareness_tips():
    return AWARENESS_TIPS