# extractors.py
# Pulls raw text out of non-text files (images, PDFs) so it can be
# handed to scanner.py exactly like a plain .txt file would be.

import io
import platform

import pytesseract
from PIL import Image
import pdfplumber

if platform.system() == "Windows":
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"


class ExtractionError(Exception):
    pass


def extract_text_from_image(raw_bytes: bytes) -> str:
    try:
        image = Image.open(io.BytesIO(raw_bytes))
        text = pytesseract.image_to_string(image)
        return text
    except Exception as e:
        raise ExtractionError(f"couldn't read text from image: {e}")


def extract_text_from_pdf(raw_bytes: bytes) -> str:
    try:
        text_parts = []
        with pdfplumber.open(io.BytesIO(raw_bytes)) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)
        return "\n".join(text_parts)
    except Exception as e:
        raise ExtractionError(f"couldn't read text from pdf: {e}")
