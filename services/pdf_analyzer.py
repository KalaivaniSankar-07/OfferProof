"""Bounded text extraction. Image-only PDFs require a separate OCR pipeline."""
from pypdf import PdfReader

MAX_PAGES = 20
MAX_TEXT_CHARS = 100_000


def extract_pdf_text(pdf_file):
    """Return PDF text; raise ValueError for unsupported or oversized documents."""
    reader = PdfReader(pdf_file)
    if reader.is_encrypted:
        raise ValueError("Encrypted PDFs are not supported")
    if len(reader.pages) > MAX_PAGES:
        raise ValueError("PDF exceeds the 20-page limit")
    parts = []
    total = 0
    for page in reader.pages:
        text = page.extract_text() or ""
        total += len(text)
        if total > MAX_TEXT_CHARS:
            raise ValueError("PDF extracted text exceeds the limit")
        parts.append(text)
    return "\n".join(parts).strip()
