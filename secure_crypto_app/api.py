import json
import io
import struct
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from config import (
    APP_NAME, APP_VERSION, HOST, PORT,
    FRONTEND_DIR, OUTPUTS_DIR, HISTORY_FILE, MAX_FILE_SIZE
)
from crypto_core import hybrid_encrypt, hybrid_decrypt
from key_manager import (
    key_store,
    keys_exist_on_disk,
    generate_and_save_keys,
    load_keys_from_disk,
    import_external_public_key,
    get_public_key_pem,
)
from exceptions import (
    CryptoAppError, InvalidKeyError,
    CorruptedFileError, SignatureVerificationError,
    IntegrityError, UnsupportedFileError,
)
from logger import get_logger

logger = get_logger(__name__)

app = FastAPI(title=APP_NAME, version=APP_VERSION, docs_url="/docs", redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/app", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


def _require_keys_loaded():
    if not key_store.keys_loaded:
        raise HTTPException(
            status_code=423,
            detail="Aucune clé active. Générez ou chargez une paire de clés d'abord."
        )


def _map_crypto_error(e: CryptoAppError) -> HTTPException:
    mapping = {
        InvalidKeyError            : (401, str(e)),
        CorruptedFileError         : (422, str(e)),
        SignatureVerificationError : (422, str(e)),
        IntegrityError             : (422, str(e)),
        UnsupportedFileError       : (413, str(e)),
    }
    for exc_type, (status, detail) in mapping.items():
        if isinstance(e, exc_type):
            return HTTPException(status_code=status, detail=detail)
    return HTTPException(status_code=500, detail=f"Erreur interne : {e}")


def _log_history(action: str, filename: str, status: str, detail: str = ""):
    history = []
    if HISTORY_FILE.exists():
        try:
            history = json.loads(HISTORY_FILE.read_text())
        except json.JSONDecodeError:
            history = []
    history.append({
        "timestamp": datetime.now().isoformat(),
        "action"   : action,
        "filename" : filename,
        "status"   : status,
        "detail"   : detail,
    })
    history = history[-200:]
    HISTORY_FILE.write_text(json.dumps(history, ensure_ascii=False, indent=2))


# ── CLÉS ──────────────────────────────────────────────────────────────────────

@app.get("/api/keys/status")
async def get_keys_status():
    return {
        "keys_on_disk": keys_exist_on_disk(),
        "keys_loaded" : key_store.keys_loaded,
        "fingerprint" : key_store.fingerprint if key_store.keys_loaded else None,
    }


@app.post("/api/keys/generate")
async def generate_keys(password: str = Form(...)):
    already_had_keys = keys_exist_on_disk()
    try:
        fingerprint = generate_and_save_keys(password)
        return {
            "success"    : True,
            "fingerprint": fingerprint,
            "warning"    : (
                "Attention : l'ancienne paire de clés a été écrasée. "
                "Les fichiers chiffrés précédemment ne pourront plus être déchiffrés."
            ) if already_had_keys else None,
        }
    except Exception as e:
        logger.error(f"Erreur génération de clés : {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/keys/load")
async def load_keys(password: str = Form(...)):
    try:
        fingerprint = load_keys_from_disk(password)
        return {"success": True, "fingerprint": fingerprint}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except InvalidKeyError as e:
        raise HTTPException(status_code=401, detail=str(e))


@app.get("/api/keys/export/public")
async def export_public_key():
    _require_keys_loaded()
    try:
        pem = get_public_key_pem()
        return StreamingResponse(
            io.BytesIO(pem),
            media_type="application/x-pem-file",
            headers={"Content-Disposition": "attachment; filename=public_key.pem"},
        )
    except InvalidKeyError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/keys/import/public")
async def import_public_key_route(file: UploadFile = File(...)):
    pem_bytes = await file.read()
    try:
        fingerprint = import_external_public_key(pem_bytes, save=False)
        return {"success": True, "fingerprint": fingerprint}
    except InvalidKeyError as e:
        raise HTTPException(status_code=422, detail=str(e))


# ── CHIFFREMENT ───────────────────────────────────────────────────────────────

@app.post("/api/encrypt/file")
async def encrypt_file(file: UploadFile = File(...), save_to_disk: bool = Form(False)):
    _require_keys_loaded()
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail=f"Fichier trop volumineux (max {MAX_FILE_SIZE // 1024 // 1024} MB).")
    try:
        package = hybrid_encrypt(
            data=content,
            public_key=key_store.public_key,
            private_key=key_store.private_key,
            original_filename=file.filename or "fichier",
        )
        output_filename = package["output_filename"]
        buffer = io.BytesIO()

        def write_field(data: bytes):
            buffer.write(struct.pack(">I", len(data)))
            buffer.write(data)

        write_field(package["encrypted_key"])
        write_field(package["signature"])
        buffer.write(package["file_hash"])
        buffer.write(package["nonce"])
        buffer.write(package["tag"])
        buffer.write(package["ciphertext"])

        if save_to_disk:
            out_path = OUTPUTS_DIR / output_filename
            out_path.write_bytes(buffer.getvalue())

        _log_history("ENCRYPT", file.filename or "?", "success", output_filename)
        buffer.seek(0)
        return StreamingResponse(
            buffer,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={output_filename}"},
        )
    except CryptoAppError as e:
        _log_history("ENCRYPT", file.filename or "?", "error", str(e))
        raise _map_crypto_error(e)


@app.post("/api/encrypt/message")
async def encrypt_message(message: str = Form(...)):
    _require_keys_loaded()
    if not message.strip():
        raise HTTPException(status_code=400, detail="Le message ne peut pas être vide.")
    content = message.encode("utf-8")
    try:
        package = hybrid_encrypt(
            data=content,
            public_key=key_store.public_key,
            private_key=key_store.private_key,
            original_filename="message.txt",
        )
        buffer = io.BytesIO()

        def write_field(data: bytes):
            buffer.write(struct.pack(">I", len(data)))
            buffer.write(data)

        write_field(package["encrypted_key"])
        write_field(package["signature"])
        buffer.write(package["file_hash"])
        buffer.write(package["nonce"])
        buffer.write(package["tag"])
        buffer.write(package["ciphertext"])

        _log_history("ENCRYPT_MSG", "message.txt", "success", package["output_filename"])
        buffer.seek(0)
        return StreamingResponse(
            buffer,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={package['output_filename']}"},
        )
    except CryptoAppError as e:
        _log_history("ENCRYPT_MSG", "message.txt", "error", str(e))
        raise _map_crypto_error(e)


# ── DÉCHIFFREMENT ─────────────────────────────────────────────────────────────

@app.post("/api/decrypt/file")
async def decrypt_file(file: UploadFile = File(...)):
    _require_keys_loaded()
    bin_content = await file.read()
    try:
        buf = io.BytesIO(bin_content)

        def read_field() -> bytes:
            size_bytes = buf.read(4)
            if len(size_bytes) < 4:
                from exceptions import CorruptedFileError
                raise CorruptedFileError("Structure du fichier binaire invalide.")
            size = struct.unpack(">I", size_bytes)[0]
            return buf.read(size)

        package = {
            "encrypted_key": read_field(),
            "signature"    : read_field(),
            "file_hash"    : buf.read(32),
            "nonce"        : buf.read(16),
            "tag"          : buf.read(16),
            "ciphertext"   : buf.read(),
        }
        plaintext = hybrid_decrypt(
            package=package,
            private_key=key_store.private_key,
            public_key=key_store.public_key,
        )
        original_name = (file.filename or "output").replace(".bin", "")
        _log_history("DECRYPT", file.filename or "?", "success")
        return StreamingResponse(
            io.BytesIO(plaintext),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename=D-{original_name}"},
        )
    except CryptoAppError as e:
        _log_history("DECRYPT", file.filename or "?", "error", str(e))
        raise _map_crypto_error(e)


# ── HISTORIQUE ────────────────────────────────────────────────────────────────

@app.get("/api/history")
async def get_history():
    if not HISTORY_FILE.exists():
        return []
    try:
        return json.loads(HISTORY_FILE.read_text())
    except json.JSONDecodeError:
        return []


@app.delete("/api/history")
async def clear_history():
    if HISTORY_FILE.exists():
        HISTORY_FILE.unlink()
    return {"success": True}


# ── POINT D'ENTRÉE ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    import webbrowser
    import threading
    import time

    def open_browser():
        time.sleep(1.2)
        webbrowser.open(f"http://{HOST}:{PORT}/app")

    threading.Thread(target=open_browser, daemon=True).start()
    logger.info(f"Démarrage de {APP_NAME} v{APP_VERSION} sur http://{HOST}:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
