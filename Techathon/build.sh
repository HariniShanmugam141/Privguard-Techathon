#!/usr/bin/env bash
# Render.com build script
# Installs Tesseract OCR system binary + spaCy language model

set -e

echo "==> Installing Tesseract OCR..."
apt-get update -qq && apt-get install -y tesseract-ocr tesseract-ocr-eng libgl1

echo "==> Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "==> Downloading spaCy English model..."
python -m spacy download en_core_web_sm

echo "==> Build complete!"
