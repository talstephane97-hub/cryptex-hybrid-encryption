from pathlib import Path
from dataclasses import dataclass, field
from Crypto.PublicKey import RSA

from crypto_core import (
    generate_rsa_keypair,
    export_private_key,
    export_public_key,
    import_private_key,
    import_public_key,
    get_key_fingerprint,
)
from exceptions import InvalidKeyError
from logger import get_logger

logger = get_logger(__name__)

KEYS_DIR         = Path("keys")
PRIVATE_KEY_PATH = KEYS_DIR / "private_key.pem"
PUBLIC_KEY_PATH  = KEYS_DIR / "public_key.pem"


@dataclass
class KeyStore:
    public_key  : RSA.RsaKey | None = field(default=None, repr=False)
    private_key : RSA.RsaKey | None = field(default=None, repr=False)
    fingerprint : str = ""
    keys_loaded : bool = False

    def clear(self):
        self.public_key  = None
        self.private_key = None
        self.fingerprint = ""
        self.keys_loaded = False
        logger.info("Clés effacées de la mémoire.")


key_store = KeyStore()


def keys_exist_on_disk() -> bool:
    return PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists()


def initialize_keys_dir():
    KEYS_DIR.mkdir(exist_ok=True)


def generate_and_save_keys(password: str) -> str:
    initialize_keys_dir()
    pub, priv = generate_rsa_keypair()
    export_private_key(priv, password, str(PRIVATE_KEY_PATH))
    export_public_key(pub, str(PUBLIC_KEY_PATH))
    key_store.public_key  = pub
    key_store.private_key = priv
    key_store.fingerprint = get_key_fingerprint(pub)
    key_store.keys_loaded = True
    logger.info(f"Nouvelle paire générée. Fingerprint : {key_store.fingerprint[:23]}...")
    return key_store.fingerprint


def load_keys_from_disk(password: str) -> str:
    if not keys_exist_on_disk():
        raise FileNotFoundError("Aucune clé trouvée. Générez d'abord une paire de clés.")
    priv = import_private_key(str(PRIVATE_KEY_PATH), password)
    pub  = import_public_key(str(PUBLIC_KEY_PATH))
    key_store.public_key  = pub
    key_store.private_key = priv
    key_store.fingerprint = get_key_fingerprint(pub)
    key_store.keys_loaded = True
    logger.info("Clés chargées depuis le disque.")
    return key_store.fingerprint


def import_external_public_key(pem_bytes: bytes, save: bool = False) -> str:
    try:
        pub = RSA.import_key(pem_bytes)
    except (ValueError, IndexError) as e:
        raise InvalidKeyError("Le fichier PEM fourni est invalide ou corrompu.") from e
    if save:
        initialize_keys_dir()
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(pub.export_key(format="PEM"))
        key_store.public_key  = pub
        key_store.fingerprint = get_key_fingerprint(pub)
    logger.info("Clé publique externe importée.")
    return get_key_fingerprint(pub)


def get_public_key_pem() -> bytes:
    if not key_store.public_key:
        raise InvalidKeyError("Aucune clé publique chargée en mémoire.")
    return key_store.public_key.export_key(format="PEM")
