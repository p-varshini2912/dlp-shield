# main.py
# FastAPI gateway - takes a text/image/pdf upload, runs it through scanner.py,
# hands back the redacted version + some stats.
from typing import Dict, Any
from fastapi import FastAPI, UploadFile, File, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from scanner import scanner, ScanError
from extractors import extract_text_from_image, extract_text_from_pdf, ExtractionError
from database import init_db, insert_scan_record, mark_alert_sent, get_all_records
from alerts import send_security_alert, get_severity

app = FastAPI(title="DLP Gateway")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.on_event("startup")
async def on_startup():
    init_db()


@app.get("/")
async def serve_ui():
    return FileResponse("static/index.html")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/incidents")
async def list_incidents(limit: int = 50):
    return {"records": get_all_records(limit)}


@app.post("/upload")
async def upload_file(file: UploadFile = File(...), background_tasks: BackgroundTasks = None):
    name = file.filename or "unnamed_file"
    try:
        raw = await file.read()
    except Exception as e:
        return JSONResponse(status_code=400, content={
            "filename": name,
            "status": "failed",
            "error": f"couldn't read the upload: {e}",
        })
    if not raw:
        return JSONResponse(status_code=400, content={
            "filename": name,
            "status": "failed",
            "error": "file is empty",
        })
    filename_lower = name.lower()
    try:
        if filename_lower.endswith((".png", ".jpg", ".jpeg")):
            text = extract_text_from_image(raw)
        elif filename_lower.endswith(".pdf"):
            text = extract_text_from_pdf(raw)
        else:
            text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        return JSONResponse(status_code=400, content={
            "filename": name,
            "status": "failed",
            "error": f"file isn't valid utf-8, can't scan it: {e}",
        })
    except ExtractionError as e:
        return JSONResponse(status_code=400, content={
            "filename": name,
            "status": "failed",
            "error": str(e),
        })
    try:
        result: Dict[str, Any] = scanner.scan(text)
    except ScanError as e:
        return JSONResponse(status_code=422, content={
            "filename": name,
            "status": "scan_failed",
            "error": str(e),
        })

    # --- NEW: persist the scan record ---
    severity = get_severity(result["entity_types"])
    record_id = insert_scan_record(
        filename=name,
        entity_types=result["entity_types"],
        redacted_text=result["redacted_text"],
        entity_count=result["hits"],
        severity=severity,
    )

    # --- NEW: fire-and-forget alert, only if high severity ---
    if severity == "HIGH" and background_tasks is not None:
        background_tasks.add_task(
            send_security_alert,
            filename=name,
            record_id=record_id,
            entity_types=result["entity_types"],
            entity_count=result["hits"],
        )
        background_tasks.add_task(mark_alert_sent, record_id)

    return {
        "filename": name,
        "status": "scan_complete",
        "record_id": record_id,
        "severity": severity,
        "entities_found": result["hits"],
        "entity_types": result["entity_types"],
        "redacted_text": result["redacted_text"],
    }
