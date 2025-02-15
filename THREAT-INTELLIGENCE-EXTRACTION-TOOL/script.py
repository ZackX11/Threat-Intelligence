import os
import re
import json
import spacy
import pdfplumber
import logging
from fastapi import FastAPI, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, List
from pathlib import Path
import uvicorn

# Configure logging
logging.basicConfig(filename="error.log", level=logging.ERROR)

# Initialize FastAPI app
app = FastAPI()

# Enable CORS for frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["POST"],
    allow_headers=["*"],
)

# Ensure upload directory exists
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Load spaCy NLP model
nlp = spacy.load("en_core_web_sm")

# Enhanced IoC Extraction Patterns
IOC_PATTERNS = {
    'IPv4 addresses': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'IPv6 addresses': r'\b(?:(?:[a-fA-F0-9]{1,4}:){7,7}[a-fA-F0-9]{1,4}|'  # Full 8-block IPv6
                  r'(?:[a-fA-F0-9]{1,4}:){1,7}:|'  # Abbreviated IPv6 (:: shorthand)
                  r'(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}|'  
                  r'(?:[a-fA-F0-9]{1,4}:){1,5}(?::[a-fA-F0-9]{1,4}){1,2}|'  
                  r'(?:[a-fA-F0-9]{1,4}:){1,4}(?::[a-fA-F0-9]{1,4}){1,3}|'  
                  r'(?:[a-fA-F0-9]{1,4}:){1,3}(?::[a-fA-F0-9]{1,4}){1,4}|'  
                  r'(?:[a-fA-F0-9]{1,4}:){1,2}(?::[a-fA-F0-9]{1,4}){1,5}|'  
                  r'[a-fA-F0-9]{1,4}:(?:(?::[a-fA-F0-9]{1,4}){1,6})|'  
                  r':(?:(?::[a-fA-F0-9]{1,4}){1,7}|:)|'  
                  r'fe80:(?::[a-fA-F0-9]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'  # Link-local
                  r'::(ffff(:0{1,4}){0,1}:){0,1}'  # IPv4-mapped IPv6
                  r'([a-fA-F0-9]{1,4}:){1,4}[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b', 
    'URLs': r'\b(?:https?|ftp)://[^\s/$.?#].[^\s]*\b',
    'Domains': r"\b(?!(?:[a-fA-F0-9]{32,64}))(?:(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|info|biz|ru|cn|io|me|tv|xyz|top|club|online|site|tech|store|pro|vip|best|blog|host|click|review|press|live|space|fun|today|cloud|agency|services|email|solutions|trade|market|network|systems|expert|guru|company|digital|world|center|group|design|media|news|social|support|video|download|software|photo|tips|game|plus|zone|chat|team|tools|website|cool|global|fashion|company|directory|management|engineering|finance|domains|ventures|enterprises|academy|training|institute|school|university|community|foundation|partners|church|charity|gives|credit|loans|insure|health|band|theater|watch|dance|cafe|bar|restaurant|wedding|gallery|photo|events|house|garden|vacations|holiday|boutique|shoes|diamonds|gold|jewelry|jewelers|builders|construction|contractors))\b",
    'MD5 Hashes': r'\b[a-fA-F0-9]{32}\b',
    'SHA1 Hashes': r'\b[a-fA-F0-9]{40}\b',
    'SHA256 Hashes': r'\b[a-fA-F0-9]{64}\b',
    'Emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'Files': r"\b(?!www\.|http[s]?://)[a-zA-Z0-9_\-]+\.(?:exe|dll|txt|pdf|docx|xls|xlsx|zip|rar|7z|tar|gz|py|sh|js|php|html|json|bin|apk|msi|scr|sys|log|db|cfg|bak|cmd|rpm|iso|img|vmdk|jar|war)\b"
}

# Function to extract text from PDFs
def extract_text_from_pdf(pdf_path: Path) -> str:
    """Extract text content from a PDF file."""
    text = ""
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
    except Exception as e:
        logging.error(f"Error extracting text from {pdf_path}: {e}")
        return ""
    return text.strip() if text else ""

# Function to extract IoCs
def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Extract IoCs using regex patterns."""
    extracted_iocs = {}
    for category, pattern in IOC_PATTERNS.items():
        matches = list(set(re.findall(pattern, text, re.IGNORECASE)))
        if matches:
            extracted_iocs[category] = matches
    return extracted_iocs

@app.post("/upload_pdf/")
async def upload_pdf(file: UploadFile):
    """Process PDF, extract IoCs, and return results."""
    file_path = Path(f"{UPLOAD_DIR}/{file.filename}")

    # Save uploaded file
    with file_path.open("wb") as buffer:
        buffer.write(await file.read())

    # Extract text from the PDF
    text = extract_text_from_pdf(file_path)
    if not text:
        return {"error": "No text extracted from the PDF"}

    # Extract IoCs
    iocs = extract_iocs(text)

    # Structure response
    report_data = {"IoCs": iocs}

    # Save results
    output_path = file_path.with_suffix(".json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    return {"message": "Processing complete", "report_path": str(output_path), "results": report_data}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
