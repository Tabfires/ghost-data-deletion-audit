"""Text extraction for business artifacts: PDFs (pypdf) and screenshots (RapidOCR, ONNX, offline).

Results are cached in `<repo>/.cache/media_text.json` keyed by path + size + mtime so a
full run only pays the OCR cost once. If the OCR engine is unavailable the
artifact simply contributes no text (the rest of the pipeline still runs).
"""
from __future__ import annotations

import json
import os
import sys


def _ocr_engine():
    try:
        from rapidocr_onnxruntime import RapidOCR
        return RapidOCR()
    except Exception as exc:  # pragma: no cover - optional dependency
        print(f"[media] OCR unavailable ({exc}); screenshots will be skipped", file=sys.stderr)
        return None


def _ocr_text(engine, path: str) -> str:
    result, _ = engine(path)
    if not result:
        return ""
    # order boxes top-to-bottom, left-to-right so related labels stay adjacent
    boxes = sorted(((round(b[0][1] / 8), b[0][0], t) for b, t, _ in result))
    return "\n".join(t for _, _, t in boxes)


def _pdf_text(path: str) -> str:
    from pypdf import PdfReader
    return "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)


def extract_media_texts(dataset_dir: str, manifest: list[dict], cache_path: str) -> dict[str, str]:
    cache = {}
    if os.path.exists(cache_path):
        try:
            cache = json.load(open(cache_path, encoding="utf-8"))
        except json.JSONDecodeError:
            cache = {}
    engine = None
    out, dirty = {}, False
    for row in manifest:
        rel = row["file_path"]
        ext = os.path.splitext(rel)[1].lower()
        if ext not in {".png", ".jpg", ".jpeg", ".pdf"}:
            continue
        path = os.path.join(dataset_dir, rel)
        st = os.stat(path)
        key = f"{rel}|{st.st_size}|{int(st.st_mtime)}"
        if key in cache:
            out[rel] = cache[key]
            continue
        if ext == ".pdf":
            text = _pdf_text(path)
        else:
            engine = engine or _ocr_engine()
            text = _ocr_text(engine, path) if engine else ""
        cache[key] = out[rel] = text
        dirty = True
    if dirty:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        json.dump(cache, open(cache_path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    return out
