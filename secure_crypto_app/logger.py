import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOGS_DIR = Path("logs")
LOG_FILE = LOGS_DIR / "app.log"

def get_logger(name: str) -> logging.Logger:
    """
    Retourne un logger configuré avec :
    - Sortie console (niveau INFO)
    - Fichier rotatif logs/app.log (max 2MB, 3 backups)
    """
    LOGS_DIR.mkdir(exist_ok=True)

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)

    fh = RotatingFileHandler(LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=3)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)

    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger
