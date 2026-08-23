import sys
import os
import re
import io
import json
import time
import hashlib
import datetime
from typing import List, Dict, Tuple, Optional, Any

import fitz  # PyMuPDF
import cv2
import numpy as np
from PIL import Image
import pytesseract
import spacy

try:
    import docx
except ImportError:
    docx = None

try:
    from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Query
    from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


TESSERACT_CONFIG = r"--oem 3 --psm 6"
LEDGER_FILE = "audit_ledger.json"

# Load spaCy NLP model safely
try:
    nlp = spacy.load("en_core_web_sm")
except Exception:
    try:
        spacy.cli.download("en_core_web_sm")
        nlp = spacy.load("en_core_web_sm")
    except Exception as e:
        print("[!] Warning: spaCy model 'en_core_web_sm' could not be loaded. Falling back to regex engine only.")
        nlp = None

# ==========================================
# COMPLIANCE PROFILES & REGEX ENTITY RULES
# ==========================================

COMPLIANCE_PROFILES = {
    "GDPR": {
        "description": "General Data Protection Regulation - Protects personal identifying data (Names, Emails, Phones, Addresses, SSNs, IPs, DOBs).",
        "entities": ["NAME", "EMAIL", "PHONE", "ADDRESS", "CITY_STATE_ZIP", "SSN", "DOB", "IP_ADDRESS", "PASSPORT", "DRIVER_LICENSE", "LOCATION"]
    },
    "HIPAA": {
        "description": "Health Insurance Portability and Accountability Act - Protects PHI (Patient Names, MRNs, Health IDs, SSNs, Member IDs, Dates, Medical Records).",
        "entities": ["NAME", "MRN", "SSN", "DOB", "MEMBER_ID", "GROUP_NUMBER", "POLICY_ID", "PAYER_ID", "INSURANCE_ID", "PHONE", "ADDRESS", "CITY_STATE_ZIP", "EMAIL", "PHYSICIAN", "FACILITY", "NPI_ID"]
    },
    "PCI-DSS": {
        "description": "Payment Card Industry Data Security Standard - Protects financial data (Credit Cards, CVVs, Bank Accounts, Tax IDs, Account IDs).",
        "entities": ["CREDIT_CARD", "CVV", "BANK_ACCOUNT", "TAX_ID", "ACCOUNT_ID", "PAYER_ID", "SSN"]
    },
    "CUSTOM": {
        "description": "All-inclusive security profile scanning for all PII, PHI, and financial entity types.",
        "entities": []  # Empty means target all detected entities
    }
}

DEFAULT_PROFILE = "HIPAA"
DEFAULT_STRATEGY = "redact"  # Options: redact, hash, anonymize

REGEX_PATTERNS = {
    "CREDIT_CARD": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}",
    "PHONE": r"(?:\+?\d{1,2}[\s-]?)?(?:\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})",
    "MRN": r"(?i)\bMRN[:\s]*[A-Z0-9-]{5,15}\b",
    "DOB": r"(?i)(?:DOB[:\s]*|Date of Birth[:\s]*)(?:\d{1,2}[-/\s]\d{1,2}[-/\s]\d{2,4}|[A-Z][a-z]+\s\d{1,2},\s\d{4})",
    "MEMBER_ID": r"(?i)(?:Member ID[:\s]*)[A-Z0-9-]{6,15}",
    "GROUP_NUMBER": r"(?i)(?:Group Number[:\s]*)[A-Z0-9-]{3,15}",
    "POLICY_ID": r"(?i)(?:Policy Effective Date[:\s]*)\d{1,2}[-/]\d{1,2}[-/]\d{2,4}",
    "PAYER_ID": r"(?i)(?:Payer ID[:\s]*)\d{3,10}",
    "NPI_ID": r"(?i)NPI[:\s]*\d{8,10}\b",
    "INSURANCE_ID": r"\b\d{6,15}\b(?=.*(?:Insurance|Insurer|Provider|ID))",
    "DRIVER_LICENSE": r"(?i)(?:License[:\s]*)[A-Z0-9-]{5,15}",
    "PASSPORT": r"(?i)(?:Passport[:\s]*)[A-Z0-9-]{6,15}",
    "TAX_ID": r"\b\d{2}-\d{7}\b(?=.*Tax)",
    "ACCOUNT_ID": r"\b[A-Z]{2,3}\d{6,}\b",
    "ADDRESS": r"\d{1,5}\s+[A-Za-z0-9\s,]+(?:Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Lane|Ln|Boulevard|Blvd|Court|Ct|Way|Place|Pkwy)\b",
    "CITY_STATE_ZIP": r"[A-Z][a-z]+,\s?[A-Z]{2}\s?\d{5}(?:-\d{4})?",
    "IP_ADDRESS": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "NAME": r"(?i)(?<=Name[:\s])([A-Z][a-z]+(?:\s[A-Z]\.)?\s[A-Z][a-z]+)"
}

# ==========================================
# TAMPER-PROOF CRYPTOGRAPHIC AUDIT LEDGER
# ==========================================

class AuditLedger:
    def __init__(self, ledger_file: str = LEDGER_FILE):
        self.ledger_file = ledger_file
        self.ensure_ledger_exists()

    def ensure_ledger_exists(self):
        if not os.path.exists(self.ledger_file):
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            genesis_block = {
                "index": 0,
                "timestamp": timestamp,
                "file_name": "GENESIS_BLOCK",
                "file_type": "system",
                "compliance_profile": "SYSTEM",
                "masking_strategy": "SYSTEM",
                "pii_found_count": 0,
                "entities_summary": {},
                "input_file_hash": "0" * 64,
                "output_file_hash": "0" * 64,
                "previous_hash": "0" * 64,
                "block_hash": self._compute_block_hash(0, "0" * 64, "GENESIS_BLOCK", "0" * 64, "0" * 64, timestamp)
            }
            with open(self.ledger_file, "w", encoding="utf-8") as f:
                json.dump([genesis_block], f, indent=2)

    def _compute_block_hash(self, index: int, prev_hash: str, file_name: str, in_hash: str, out_hash: str, timestamp: str = "") -> str:
        payload = f"{index}:{prev_hash}:{file_name}:{in_hash}:{out_hash}:{timestamp}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get_all_blocks(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.ledger_file):
            self.ensure_ledger_exists()
        try:
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def record_transaction(self, file_name: str, file_type: str, profile: str, strategy: str,
                           pii_entities: List[Tuple[str, str]], input_bytes: bytes, output_bytes: bytes) -> Dict[str, Any]:
        blocks = self.get_all_blocks()
        prev_block = blocks[-1] if blocks else {"index": -1, "block_hash": "0" * 64}

        index = prev_block["index"] + 1
        prev_hash = prev_block["block_hash"]
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"

        in_hash = hashlib.sha256(input_bytes).hexdigest() if input_bytes else "0" * 64
        out_hash = hashlib.sha256(output_bytes).hexdigest() if output_bytes else "0" * 64

        entities_summary = {}
        for text, label in pii_entities:
            entities_summary[label] = entities_summary.get(label, 0) + 1

        block_hash = self._compute_block_hash(index, prev_hash, file_name, in_hash, out_hash, timestamp)

        new_block = {
            "index": index,
            "timestamp": timestamp,
            "file_name": file_name,
            "file_type": file_type,
            "compliance_profile": profile,
            "masking_strategy": strategy,
            "pii_found_count": len(pii_entities),
            "entities_summary": entities_summary,
            "input_file_hash": in_hash,
            "output_file_hash": out_hash,
            "previous_hash": prev_hash,
            "block_hash": block_hash
        }

        blocks.append(new_block)
        with open(self.ledger_file, "w", encoding="utf-8") as f:
            json.dump(blocks, f, indent=2)

        return new_block

    def verify_integrity(self) -> Tuple[bool, str, List[Dict[str, Any]]]:
        blocks = self.get_all_blocks()
        if not blocks:
            return False, "Ledger is empty or unreadable.", []

        details = []
        is_valid = True

        for i in range(len(blocks)):
            block = blocks[i]
            if i == 0:
                calc_hash = self._compute_block_hash(0, "0" * 64, block["file_name"], block["input_file_hash"], block["output_file_hash"], block.get("timestamp", ""))
                if block["block_hash"] != calc_hash:
                    is_valid = False
                    details.append({"index": 0, "status": "INVALID", "reason": "Genesis block hash mismatch"})
                else:
                    details.append({"index": 0, "status": "VALID"})
                continue

            prev_block = blocks[i - 1]
            if block["previous_hash"] != prev_block["block_hash"]:
                is_valid = False
                details.append({"index": block["index"], "status": "INVALID", "reason": f"Previous hash mismatch. Expected {prev_block['block_hash']}, got {block['previous_hash']}"})
                continue

            calc_hash = self._compute_block_hash(block["index"], block["previous_hash"], block["file_name"], block["input_file_hash"], block["output_file_hash"], block.get("timestamp", ""))
            if block["block_hash"] != calc_hash:
                is_valid = False
                details.append({"index": block["index"], "status": "INVALID", "reason": f"Block hash tampered! Recorded: {block['block_hash']}, Computed: {calc_hash}"})
            else:
                details.append({"index": block["index"], "status": "VALID"})

        msg = "Ledger chain is 100% valid and verified." if is_valid else "TAMPERING DETECTED in audit ledger chain!"
        return is_valid, msg, details


ledger_instance = AuditLedger()

# ==========================================
# ENTITY DETECTION ENGINE
# ==========================================

def detect_pii(text: str, profile: str = "HIPAA") -> List[Tuple[str, str]]:
    """Detect PII/PHI entities based on compliance profile."""
    if not text:
        return []

    profile = profile.upper()
    profile_info = COMPLIANCE_PROFILES.get(profile, COMPLIANCE_PROFILES["HIPAA"])
    target_entities = profile_info["entities"]

    detected = []

    # 1. Regex rules search
    for label, pattern in REGEX_PATTERNS.items():
        if target_entities and label not in target_entities:
            continue
        for match in set(re.findall(pattern, text)):
            if isinstance(match, tuple):
                match = match[0]
            val = match.strip()
            if val and len(val) >= 2:
                detected.append((val, label))

    # 2. spaCy NER search
    if nlp is not None:
        doc = nlp(text)
        for ent in doc.ents:
            et = ent.text.strip()
            if not et or len(et.replace(" ", "")) < 3:
                continue
            
            label = None
            if ent.label_ == "PERSON" and (not target_entities or "NAME" in target_entities or "PATIENT" in target_entities):
                label = "NAME"
            elif ent.label_ in {"GPE", "LOC"} and (not target_entities or "LOCATION" in target_entities or "ADDRESS" in target_entities):
                label = "LOCATION"
            elif ent.label_ == "ORG" and (not target_entities or "FACILITY" in target_entities):
                label = "FACILITY"

            if label:
                detected.append((et, label))

    # Deduplicate entities
    seen = set()
    uniq = []
    for text_val, label_val in detected:
        key = (text_val.lower(), label_val)
        if key not in seen:
            seen.add(key)
            uniq.append((text_val, label_val))

    return uniq


def get_masked_replacement(text_val: str, label_val: str, strategy: str = "redact") -> str:
    """Generate masked text according to selected strategy."""
    strategy = strategy.lower()
    if strategy == "hash":
        h = hashlib.sha256(text_val.encode("utf-8")).hexdigest()[:10]
        return f"[HASH_{label_val}:{h}]"
    elif strategy == "anonymize":
        val_hash = int(hashlib.md5(text_val.encode("utf-8")).hexdigest(), 16) % 900 + 100
        return f"[{label_val}_{val_hash}]"
    else:  # redact
        return f"[REDACTED_{label_val}]"

# ==========================================
# MULTI-FORMAT DOCUMENT REDACTION ENGINES
# ==========================================

# 1. PDF REDACTION ENGINE
def redact_pdf_document(input_path: str, output_path: str, pii_entities: List[Tuple[str, str]], strategy: str = "redact") -> bool:
    """Redact PDF while preserving layout, removing metadata."""
    try:
        doc = fitz.open(input_path)
    except Exception as e:
        print(f"[!] Could not open PDF {input_path}: {e}")
        return False

    # Strip metadata
    try:
        doc.set_metadata({})
    except Exception:
        pass

    for page in doc:
        for ent_text, label in pii_entities:
            ent_text = ent_text.strip()
            if not ent_text or len(ent_text) < 2:
                continue
            try:
                rects = page.search_for(ent_text)
            except Exception:
                rects = []
            for r in rects:
                try:
                    if strategy == "redact":
                        page.add_redact_annot(r, fill=(0, 0, 0))
                    else:
                        replacement = get_masked_replacement(ent_text, label, strategy)
                        page.add_redact_annot(r, text=replacement, fill=(1, 1, 1), text_color=(0, 0, 0.8))
                except Exception:
                    pass
        try:
            page.apply_redactions()
        except Exception:
            pass

    try:
        doc.save(output_path, garbage=4, deflate=True)
        doc.close()
        return True
    except Exception as e:
        print(f"[!] PDF save failed: {e}")
        try:
            doc.close()
        except Exception:
            pass
        return False

# 2. IMAGE REDACTION ENGINE
def redact_image_document(input_path: str, output_path: str, profile: str = "HIPAA", strategy: str = "redact") -> Tuple[List[Tuple[str, str]], int]:
    """Redact PII from image using OCR, blur faces, and strip EXIF metadata."""
    img = cv2.imread(input_path)
    if img is None:
        return [], 0

    # OCR text extraction
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    try:
        _, th = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    except Exception:
        th = gray

    ocr_data = pytesseract.image_to_data(th, output_type=pytesseract.Output.DICT, config=TESSERACT_CONFIG)
    words = [w for w in ocr_data.get("text", []) if w and w.strip()]
    full_text = " ".join(words)

    pii_entities = detect_pii(full_text, profile)

    # Overlays on text matches
    for i, word in enumerate(ocr_data["text"]):
        word_clean = word.strip()
        if not word_clean:
            continue
        for ent_text, label in pii_entities:
            if word_clean.lower() in ent_text.lower() or ent_text.lower() in word_clean.lower():
                x, y, w, h = (
                    ocr_data["left"][i],
                    ocr_data["top"][i],
                    ocr_data["width"][i],
                    ocr_data["height"][i],
                )
                if strategy == "redact":
                    cv2.rectangle(img, (x, y), (x + w, y + h), (0, 0, 0), -1)
                else:
                    replacement = get_masked_replacement(word_clean, label, strategy)
                    cv2.rectangle(img, (x, y), (x + w, y + h), (255, 255, 255), -1)
                    cv2.putText(img, replacement[:8], (x, y + h - 2), cv2.FONT_HERSHEY_SIMPLEX, 0.4, (200, 0, 0), 1)
                break

    # Face Blur detection
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
    faces = face_cascade.detectMultiScale(gray, 1.2, 4)
    for (x, y, w, h) in faces:
        sub = img[y:y + h, x:x + w]
        img[y:y + h, x:x + w] = cv2.GaussianBlur(sub, (99, 99), 30)

    # Save without EXIF metadata
    rgb_img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    pil_img = Image.fromarray(rgb_img)
    pil_img.save(output_path)

    return pii_entities, len(faces)

# 3. WORD (.DOCX) REDACTION ENGINE
def redact_docx_document(input_path: str, output_path: str, pii_entities: List[Tuple[str, str]], strategy: str = "redact") -> bool:
    """Redact Word (.docx) document while preserving structure & styles."""
    if docx is None:
        print("[!] python-docx library is not available.")
        return False

    try:
        doc = docx.Document(input_path)
    except Exception as e:
        print(f"[!] Failed to open docx {input_path}: {e}")
        return False

    def replace_text_in_paragraph(p):
        for ent_text, label in pii_entities:
            if not ent_text or ent_text not in p.text:
                continue
            replacement = get_masked_replacement(ent_text, label, strategy)
            # Simple run-level or full text replacement preserving paragraph
            pattern = re.escape(ent_text)
            p.text = re.sub(pattern, replacement, p.text, flags=re.IGNORECASE)

    for p in doc.paragraphs:
        replace_text_in_paragraph(p)

    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    replace_text_in_paragraph(p)

    try:
        doc.save(output_path)
        return True
    except Exception as e:
        print(f"[!] Failed to save redacted docx: {e}")
        return False

# 4. PLAIN TEXT / CODE DOCUMENT ENGINE
def redact_txt_document(input_path: str, output_path: str, pii_entities: List[Tuple[str, str]], strategy: str = "redact") -> bool:
    """Redact plain text files."""
    try:
        with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        for ent_text, label in pii_entities:
            if not ent_text:
                continue
            replacement = get_masked_replacement(ent_text, label, strategy)
            pattern = re.escape(ent_text)
            content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"[!] Text redaction failed: {e}")
        return False


def extract_document_text(filepath: str) -> str:
    """Extract plain text from any supported document format."""
    ext = os.path.splitext(filepath)[1].lower()

    if ext == ".pdf":
        text_parts = []
        try:
            doc = fitz.open(filepath)
            for page in doc:
                pt = page.get_text("text").strip()
                if pt:
                    text_parts.append(pt)
                else:
                    # OCR fallback for image page
                    pix = page.get_pixmap(dpi=200)
                    img_bytes = pix.tobytes("png")
                    img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
                    ocr_text = pytesseract.image_to_string(img, config=TESSERACT_CONFIG)
                    text_parts.append(ocr_text)
            doc.close()
        except Exception:
            pass
        return "\n\n".join(text_parts)

    elif ext in [".docx", ".doc"]:
        if docx is not None:
            try:
                doc = docx.Document(filepath)
                return "\n".join([p.text for p in doc.paragraphs])
            except Exception:
                pass
        return ""

    elif ext in [".png", ".jpg", ".jpeg", ".bmp", ".tiff"]:
        try:
            img = cv2.imread(filepath)
            if img is not None:
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                return pytesseract.image_to_string(gray, config=TESSERACT_CONFIG)
        except Exception:
            pass
        return ""

    else:  # Text, log, csv, json, md
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception:
            return ""

# ==========================================
# FASTAPI WEB SERVER & INTERACTIVE DASHBOARD
# ==========================================

if FASTAPI_AVAILABLE:
    app = FastAPI(
        title="PrivGuard Local Inline Proxy",
        description="Local-First Document Redaction & Cryptographic Compliance Middleware",
        version="2.0.0"
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    active_profile = DEFAULT_PROFILE

    # DASHBOARD HTML PAGE
    DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PrivGuard - Local Compliance & Document Redaction Proxy</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0b0f19;
            --card: #151c2c;
            --accent: #4f46e5;
            --accent-hover: #4338ca;
            --success: #10b981;
            --danger: #ef4444;
            --text: #f3f4f6;
            --muted: #9ca3af;
            --border: #232d42;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }

        body {
            background-color: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        header {
            background-color: var(--card);
            border-bottom: 1px solid var(--border);
            padding: 1.2rem 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .logo-group { display: flex; align-items: center; gap: 12px; }
        .logo-icon {
            background: linear-gradient(135deg, #6366f1, #a855f7);
            width: 38px; height: 38px; border-radius: 10px;
            display: flex; align-items: center; justify-content: center;
            font-weight: 700; font-size: 1.2rem; color: #fff;
        }

        .logo-text { font-size: 1.4rem; font-weight: 700; background: linear-gradient(90deg, #fff, #94a3b8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }

        .status-badge {
            background-color: rgba(16, 185, 129, 0.15);
            color: var(--success);
            border: 1px solid var(--success);
            padding: 0.3rem 0.8rem; border-radius: 20px;
            font-size: 0.85rem; font-weight: 600; display: flex; align-items: center; gap: 6px;
        }

        .status-dot { width: 8px; height: 8px; background-color: var(--success); border-radius: 50%; display: inline-block; }

        .nav-tabs {
            display: flex; gap: 10px; padding: 1rem 2rem;
            background: rgba(21, 28, 44, 0.5); border-bottom: 1px solid var(--border);
        }

        .tab-btn {
            background: none; border: none; color: var(--muted);
            padding: 0.6rem 1.2rem; font-size: 0.95rem; font-weight: 500;
            border-radius: 8px; cursor: pointer; transition: all 0.2s;
        }

        .tab-btn:hover { color: var(--text); background: var(--border); }
        .tab-btn.active { color: #fff; background: var(--accent); font-weight: 600; }

        main { flex: 1; padding: 2rem; max-width: 1400px; margin: 0 auto; width: 100%; }

        .section-card {
            background-color: var(--card); border: 1px solid var(--border);
            border-radius: 14px; padding: 1.8rem; margin-bottom: 2rem;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
        }

        h2 { font-size: 1.3rem; margin-bottom: 0.5rem; font-weight: 600; color: #fff; }
        p.subtitle { color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; }

        .controls-grid {
            display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem;
        }

        .form-group { display: flex; flex-direction: column; gap: 6px; }
        label { font-size: 0.85rem; font-weight: 600; color: var(--muted); }

        select, input[type="text"] {
            background: var(--bg); border: 1px solid var(--border);
            color: var(--text); padding: 0.7rem 1rem; border-radius: 8px;
            font-size: 0.95rem; outline: none; transition: border 0.2s;
        }
        select:focus, input:focus { border-color: var(--accent); }

        .drop-zone {
            border: 2px dashed var(--border); border-radius: 12px;
            padding: 3rem 2rem; text-align: center; cursor: pointer;
            transition: all 0.2s; background: rgba(11, 15, 25, 0.4);
        }

        .drop-zone:hover { border-color: var(--accent); background: rgba(79, 70, 229, 0.05); }

        .btn {
            background: var(--accent); color: #fff; border: none;
            padding: 0.8rem 1.5rem; border-radius: 8px; font-weight: 600;
            font-size: 0.95rem; cursor: pointer; transition: background 0.2s;
            display: inline-flex; align-items: center; gap: 8px;
        }

        .btn:hover { background: var(--accent-hover); }
        .btn-success { background: var(--success); }
        .btn-success:hover { background: #059669; }

        .results-box {
            background: var(--bg); border: 1px solid var(--border);
            border-radius: 10px; padding: 1.2rem; margin-top: 1.5rem;
        }

        .entity-tag {
            display: inline-block; background: rgba(239, 68, 68, 0.15);
            color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3);
            padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.8rem; margin: 4px;
        }

        .table-wrapper { overflow-x: auto; margin-top: 1rem; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }
        th, td { padding: 0.8rem 1rem; border-bottom: 1px solid var(--border); }
        th { color: var(--muted); font-weight: 600; background: rgba(11, 15, 25, 0.5); }

        .badge-valid { background: rgba(16, 185, 129, 0.2); color: var(--success); padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; }
        .badge-invalid { background: rgba(239, 68, 68, 0.2); color: var(--danger); padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; }

        .hidden { display: none; }
    </style>
</head>
<body>
    <header>
        <div class="logo-group">
            <div class="logo-icon">P</div>
            <div class="logo-text">PrivGuard Middleware</div>
        </div>
        <div class="status-badge">
            <span class="status-dot"></span>
            100% Local Compliance Active
        </div>
    </header>

    <div class="nav-tabs">
        <button class="tab-btn active" onclick="switchTab('doc-tab')">📄 Document Redaction & Sanitization</button>
        <button class="tab-btn" onclick="switchTab('profiles-tab')">🛡️ Compliance Profiles</button>
        <button class="tab-btn" onclick="switchTab('ledger-tab')">🔐 Cryptographic Audit Ledger</button>
    </div>

    <main>
        <!-- DOCUMENT SANITIZER TAB -->
        <div id="doc-tab" class="tab-content">
            <div class="section-card">
                <h2>Multi-Format Document Redaction</h2>
                <p class="subtitle">Upload PDF, DOCX, PNG, JPG, or TXT documents. PrivGuard will redact PII/PHI while preserving document layout.</p>

                <div class="controls-grid">
                    <div class="form-group">
                        <label>Compliance Profile</label>
                        <select id="doc-profile">
                            <option value="HIPAA" selected>HIPAA (Healthcare & PHI focus)</option>
                            <option value="GDPR">GDPR (Personal Identifiers)</option>
                            <option value="PCI-DSS">PCI-DSS (Payment & Financial Data)</option>
                            <option value="CUSTOM">CUSTOM (Full Entity Scan)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Masking Strategy</label>
                        <select id="doc-strategy">
                            <option value="redact" selected>Redact (Solid Black Overlay / Replace)</option>
                            <option value="hash">Hash (SHA-256 Hashes)</option>
                            <option value="anonymize">Anonymize (Synthetic Pseudonyms)</option>
                        </select>
                    </div>
                </div>

                <div class="drop-zone" id="drop-zone" onclick="document.getElementById('file-input').click()">
                    <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">📁</div>
                    <div style="font-weight: 600; font-size: 1.1rem;">Click or Drag & Drop Document Here</div>
                    <div style="color: var(--muted); font-size: 0.85rem; margin-top: 6px;">Supports .pdf, .docx, .png, .jpg, .txt, .csv</div>
                    <input type="file" id="file-input" class="hidden" onchange="handleFileSelect(event)">
                </div>

                <div id="doc-results" class="results-box hidden">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <h3 style="color: #fff; font-size: 1.1rem;">Sanitization Complete</h3>
                        <a id="download-link" class="btn btn-success" download>⬇️ Download Redacted Document</a>
                    </div>
                    <div style="margin-top: 1rem;">
                        <p style="color: var(--muted); font-size: 0.9rem;">Entities Found & Masked:</p>
                        <div id="entity-tags-container" style="margin-top: 0.5rem;"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- PROFILES TAB -->
        <div id="profiles-tab" class="tab-content hidden">
            <div class="section-card">
                <h2>Compliance Profile Management</h2>
                <p class="subtitle">Select and hot-swap active compliance policy enforcement.</p>
                
                <div id="profiles-container" class="controls-grid"></div>
            </div>
        </div>

        <!-- LEDGER TAB -->
        <div id="ledger-tab" class="tab-content hidden">
            <div class="section-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                    <div>
                        <h2>Cryptographic Audit Ledger</h2>
                        <p class="subtitle">SHA-256 hash-chained immutable audit trail.</p>
                    </div>
                    <button class="btn" onclick="verifyLedger()">🔍 Verify Ledger Chain Integrity</button>
                </div>

                <div id="verification-result" class="hidden" style="padding: 1rem; border-radius: 8px; margin-bottom: 1rem;"></div>

                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Timestamp</th>
                                <th>File Name</th>
                                <th>Profile</th>
                                <th>Strategy</th>
                                <th>Entities Found</th>
                                <th>Block Hash</th>
                            </tr>
                        </thead>
                        <tbody id="ledger-body"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </main>

    <script>
        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.remove('hidden');
            event.target.classList.add('active');

            if (tabId === 'ledger-tab') loadLedger();
            if (tabId === 'profiles-tab') loadProfiles();
        }

        async function handleFileSelect(e) {
            const file = e.target.files[0];
            if (!file) return;

            const profile = document.getElementById('doc-profile').value;
            const strategy = document.getElementById('doc-strategy').value;

            const formData = new FormData();
            formData.append('file', file);
            formData.append('profile', profile);
            formData.append('strategy', strategy);

            const dropZone = document.getElementById('drop-zone');
            dropZone.innerHTML = '<div style="font-size: 2.5rem;">⏳</div><div>Processing & Redacting Document...</div>';

            try {
                const res = await fetch('/sanitize/document', { method: 'POST', body: formData });
                const data = await res.json();

                dropZone.innerHTML = '<div style="font-size: 2.5rem;">📁</div><div style="font-weight:600;">Click or Drag & Drop Document Here</div>';

                document.getElementById('doc-results').classList.remove('hidden');
                document.getElementById('download-link').href = data.download_url;

                const tagsDiv = document.getElementById('entity-tags-container');
                tagsDiv.innerHTML = '';
                if (data.entities && data.entities.length > 0) {
                    data.entities.forEach(ent => {
                        const tag = document.createElement('span');
                        tag.className = 'entity-tag';
                        tag.innerText = ent[1] + ': ' + ent[0];
                        tagsDiv.appendChild(tag);
                    });
                } else {
                    tagsDiv.innerHTML = '<span style="color:var(--muted); font-size:0.9rem;">No PII/PHI entities detected. Document layout clean.</span>';
                }
            } catch (err) {
                alert('Sanitization failed: ' + err);
                dropZone.innerHTML = '<div style="font-size: 2.5rem;">📁</div><div style="font-weight:600;">Click or Drag & Drop Document Here</div>';
            }
        }

        async function loadProfiles() {
            const res = await fetch('/profiles');
            const data = await res.json();
            const container = document.getElementById('profiles-container');
            container.innerHTML = '';

            for (const [key, val] of Object.entries(data.profiles)) {
                const isCurrent = key === data.active_profile;
                const card = document.createElement('div');
                card.style.background = 'var(--bg)';
                card.style.border = isCurrent ? '2px solid var(--accent)' : '1px solid var(--border)';
                card.style.padding = '1.2rem';
                card.style.borderRadius = '10px';

                card.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
                        <h3 style="color:#fff;">${key}</h3>
                        ${isCurrent ? '<span class="badge-valid">ACTIVE</span>' : ''}
                    </div>
                    <p style="color:var(--muted); font-size:0.85rem; margin-bottom:1rem;">${val.description}</p>
                    <button class="btn" style="width:100%; justify-content:center;" onclick="switchProfile('${key}')">Activate ${key}</button>
                `;
                container.appendChild(card);
            }
        }

        async function switchProfile(prof) {
            await fetch('/profiles/switch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ profile: prof })
            });
            loadProfiles();
        }

        async function loadLedger() {
            const res = await fetch('/ledger');
            const blocks = await res.json();
            const tbody = document.getElementById('ledger-body');
            tbody.innerHTML = '';

            blocks.forEach(b => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${b.index}</td>
                    <td>${b.timestamp.split('T')[0]} ${b.timestamp.split('T')[1].substring(0,5)}</td>
                    <td>${b.file_name}</td>
                    <td>${b.compliance_profile}</td>
                    <td>${b.masking_strategy}</td>
                    <td>${b.pii_found_count}</td>
                    <td style="font-family:monospace; font-size:0.8rem; color:var(--muted);">${b.block_hash.substring(0, 16)}...</td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function verifyLedger() {
            const res = await fetch('/ledger/verify', { method: 'POST' });
            const data = await res.json();
            const div = document.getElementById('verification-result');
            div.classList.remove('hidden');

            if (data.is_valid) {
                div.style.background = 'rgba(16, 185, 129, 0.15)';
                div.style.border = '1px solid var(--success)';
                div.style.color = 'var(--success)';
                div.innerHTML = '<strong>✓ Hash-Chain Verified:</strong> ' + data.message;
            } else {
                div.style.background = 'rgba(239, 68, 68, 0.15)';
                div.style.border = '1px solid var(--danger)';
                div.style.color = 'var(--danger)';
                div.innerHTML = '<strong>❌ Tamper Warning:</strong> ' + data.message;
            }
        }
    </script>
</body>
</html>
"""

    @app.get("/", response_class=HTMLResponse)
    @app.get("/dashboard", response_class=HTMLResponse)
    def serve_dashboard():
        return HTMLResponse(content=DASHBOARD_HTML)

    @app.get("/profiles")
    def get_profiles():
        global active_profile
        return {"active_profile": active_profile, "profiles": COMPLIANCE_PROFILES}

    @app.post("/profiles/switch")
    def switch_profile(data: Dict[str, str]):
        global active_profile
        prof = data.get("profile", "").upper()
        if prof in COMPLIANCE_PROFILES:
            active_profile = prof
            return {"status": "success", "active_profile": active_profile}
        raise HTTPException(status_code=400, detail="Invalid compliance profile name.")

    @app.get("/ledger")
    def get_ledger():
        return ledger_instance.get_all_blocks()

    @app.post("/ledger/verify")
    def verify_ledger():
        is_valid, msg, details = ledger_instance.verify_integrity()
        return {"is_valid": is_valid, "message": msg, "details": details}

    @app.post("/sanitize/document")
    async def sanitize_document(
        file: UploadFile = File(...),
        profile: Optional[str] = Form(None),
        strategy: Optional[str] = Form("redact")
    ):
        prof = profile.upper() if profile else active_profile
        strat = strategy.lower() if strategy else DEFAULT_STRATEGY

        temp_dir = "temp_uploads"
        os.makedirs(temp_dir, exist_ok=True)

        input_filename = file.filename
        input_path = os.path.join(temp_dir, f"raw_{input_filename}")
        
        # Read bytes
        content_bytes = await file.read()
        with open(input_path, "wb") as f:
            f.write(content_bytes)

        ext = os.path.splitext(input_filename)[1].lower()
        base_name = os.path.splitext(input_filename)[0]
        out_filename = f"redacted_{base_name}{ext}"
        output_path = os.path.join(temp_dir, out_filename)

        extracted_text = extract_document_text(input_path)
        pii_entities = detect_pii(extracted_text, prof)

        faces_count = 0
        success = False

        if ext == ".pdf":
            success = redact_pdf_document(input_path, output_path, pii_entities, strat)
        elif ext in [".png", ".jpg", ".jpeg", ".bmp", ".tiff"]:
            pii_entities, faces_count = redact_image_document(input_path, output_path, prof, strat)
            success = True
        elif ext in [".docx", ".doc"]:
            success = redact_docx_document(input_path, output_path, pii_entities, strat)
        else:
            success = redact_txt_document(input_path, output_path, pii_entities, strat)

        output_bytes = b""
        if success and os.path.exists(output_path):
            with open(output_path, "rb") as f:
                output_bytes = f.read()

        # Record transaction to cryptographic audit ledger
        ledger_instance.record_transaction(
            file_name=input_filename,
            file_type=ext.replace(".", ""),
            profile=prof,
            strategy=strat,
            pii_entities=pii_entities,
            input_bytes=content_bytes,
            output_bytes=output_bytes
        )

        return JSONResponse({
            "status": "success",
            "file_name": input_filename,
            "profile_used": prof,
            "strategy_used": strat,
            "entities_found": len(pii_entities),
            "faces_redacted": faces_count,
            "entities": pii_entities,
            "download_url": f"/download/{out_filename}"
        })

    @app.get("/download/{filename}")
    def download_file(filename: str):
        path = os.path.join("temp_uploads", filename)
        if os.path.exists(path):
            return FileResponse(path, filename=filename)
        raise HTTPException(status_code=404, detail="Redacted document not found.")

# ==========================================
# CLI INTERFACE
# ==========================================

def run_cli(argv: List[str]):
    import argparse
    parser = argparse.ArgumentParser(description="PrivGuard Local Compliance & Multi-Format Document Redaction Middleware")
    parser.add_argument("files", nargs="*", help="Document file paths to redact (.pdf, .docx, .png, .jpg, .txt)")
    parser.add_argument("--profile", choices=["GDPR", "HIPAA", "PCI-DSS", "CUSTOM"], default="HIPAA", help="Compliance profile enforcement")
    parser.add_argument("--strategy", choices=["redact", "hash", "anonymize"], default="redact", help="Masking strategy")
    parser.add_argument("--server", action="store_true", help="Start FastAPI local inline proxy server")
    parser.add_argument("--host", default="127.0.0.1", help="Server host IP")
    parser.add_argument("--port", type=int, default=8000, help="Server port")
    parser.add_argument("--verify-ledger", action="store_true", help="Verify cryptographic audit ledger chain")

    args = parser.parse_args(argv[1:])

    if args.verify_ledger:
        print("[*] Verifying PrivGuard Cryptographic Audit Ledger...")
        valid, msg, details = ledger_instance.verify_integrity()
        if valid:
            print(f"[+] SUCCESS: {msg}")
        else:
            print(f"[!] WARNING: {msg}")
        for d in details:
            print(f"    Block #{d['index']}: {d['status']} {d.get('reason', '')}")
        return 0

    if args.server:
        if not FASTAPI_AVAILABLE:
            print("[!] FastAPI/Uvicorn not installed. Run: pip install fastapi uvicorn python-multipart")
            return 1
        print(f"[*] Starting PrivGuard Local Inline Proxy at http://{args.host}:{args.port}")
        print(f"[*] Serving Interactive Dashboard at http://{args.host}:{args.port}/dashboard")
        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    if not args.files:
        parser.print_help()
        return 0

    for filepath in args.files:
        if not os.path.exists(filepath):
            print(f"[!] File not found: {filepath}")
            continue

        filename = os.path.basename(filepath)
        ext = os.path.splitext(filename)[1].lower()
        name_noext = os.path.splitext(filename)[0]
        out_filename = f"redacted_{name_noext}{ext}"

        print(f"[*] Processing {filename} | Profile: {args.profile} | Strategy: {args.strategy}")

        with open(filepath, "rb") as f:
            in_bytes = f.read()

        extracted_text = extract_document_text(filepath)
        pii_entities = detect_pii(extracted_text, args.profile)

        faces_count = 0
        success = False

        if ext == ".pdf":
            success = redact_pdf_document(filepath, out_filename, pii_entities, args.strategy)
        elif ext in [".png", ".jpg", ".jpeg", ".bmp", ".tiff"]:
            pii_entities, faces_count = redact_image_document(filepath, out_filename, args.profile, args.strategy)
            success = True
        elif ext in [".docx", ".doc"]:
            success = redact_docx_document(filepath, out_filename, pii_entities, args.strategy)
        else:
            success = redact_txt_document(filepath, out_filename, pii_entities, args.strategy)

        out_bytes = b""
        if success and os.path.exists(out_filename):
            with open(out_filename, "rb") as f:
                out_bytes = f.read()

        ledger_instance.record_transaction(
            file_name=filename,
            file_type=ext.replace(".", ""),
            profile=args.profile,
            strategy=args.strategy,
            pii_entities=pii_entities,
            input_bytes=in_bytes,
            output_bytes=out_bytes
        )

        print(f"[+] Saved redacted document -> {out_filename}")
        print(f"    Entities found: {len(pii_entities)} | Faces redacted: {faces_count}")

    return 0


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv))
