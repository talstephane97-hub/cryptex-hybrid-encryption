from pathlib import Path

APP_NAME      = "Secure Crypto App"
APP_VERSION   = "1.0.0"
HOST          = "127.0.0.1"
PORT          = 8000
FRONTEND_DIR  = Path("frontend")
OUTPUTS_DIR   = Path("outputs")
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
HISTORY_FILE  = Path("logs") / "history.json"

for d in [OUTPUTS_DIR, Path("keys"), Path("logs")]:
    d.mkdir(exist_ok=True)
