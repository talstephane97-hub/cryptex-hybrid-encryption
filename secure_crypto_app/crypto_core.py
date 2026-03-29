# =============================================================================
# crypto_core.py — Module cryptographique central
# Secure Crypto App | Portfolio
# =============================================================================
#
# CHOIX ARCHITECTURAUX JUSTIFIÉS :
#
# 1. AES-256-GCM (vs AES-128-EAX original)
#    → GCM est un mode AEAD (Authenticated Encryption with Associated Data).
#      Il chiffre ET authentifie simultanément le message grâce à un tag de 16B.
#      256 bits de clé = résistance brute-force même face aux ordinateurs quantiques
#      à court terme. EAX était valide mais GCM est le standard industriel (TLS 1.3).
#
# 2. RSA-4096-OAEP (vs RSA-2048 original)
#    → 4096 bits pour les nouvelles générations de clés (2048 est encore sûr mais
#      vieillissant). OAEP avec SHA-256 comme fonction de hachage interne est le
#      padding recommandé — PKCS#1 v1.5 est vulnérable aux attaques de Bleichenbacher.
#
# 3. Argon2id comme KDF (Key Derivation Function)
#    → Argon2id est le gagnant du Password Hashing Competition (2015). Il est
#      résistant aux attaques par GPU et ASIC grâce à sa consommation mémoire
#      configurable. Il remplace PBKDF2 (trop rapide) et bcrypt (limite 72 chars).
#
# 4. Signature RSA-PSS (absent dans la version originale)
#    → PSS (Probabilistic Signature Scheme) est supérieur à PKCS#1 v1.5 pour les
#      signatures. Il prouve que l'expéditeur possède la clé privée AVANT chiffrement,
#      garantissant l'authenticité et la non-répudiation.
#
# 5. SHA-256 pour l'intégrité
#    → Hash du fichier original inclus dans le package chiffré, vérifié après
#      déchiffrement. Détecte toute corruption ou falsification du fichier.
#
# 6. Chiffrement par blocs (chunked)
#    → Traitement en morceaux de 64KB pour éviter de charger de gros fichiers
#      entièrement en RAM.
#
# =============================================================================

import os
import hashlib
import struct
from datetime import datetime
from typing import Generator

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from argon2.low_level import hash_secret_raw, Type

from exceptions import (
    InvalidKeyError,
    CorruptedFileError,
    SignatureVerificationError,
    IntegrityError,
    UnsupportedFileError,
)
from logger import get_logger

logger = get_logger(__name__)

# =============================================================================
# CONSTANTES DE SÉCURITÉ
# =============================================================================

CHUNK_SIZE         = 64 * 1024
AES_KEY_SIZE       = 32
RSA_KEY_SIZE       = 4096
ARGON2_TIME_COST   = 3
ARGON2_MEM_COST    = 65536
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN    = 32
ARGON2_SALT_LEN    = 16
NONCE_SIZE         = 16
TAG_SIZE           = 16
MAX_FILE_SIZE      = 100 * 1024 * 1024


# =============================================================================
# GÉNÉRATION & GESTION DES CLÉS RSA
# =============================================================================

def generate_rsa_keypair() -> tuple[RSA.RsaKey, RSA.RsaKey]:
    logger.info("Génération d'une nouvelle paire de clés RSA-4096...")
    private_key = RSA.generate(RSA_KEY_SIZE)
    public_key  = private_key.publickey()
    logger.info("Paire de clés générée avec succès.")
    return public_key, private_key


def export_private_key(private_key: RSA.RsaKey, password: str, path: str) -> None:
    salt    = get_random_bytes(ARGON2_SALT_LEN)
    derived = _derive_key_argon2(password, salt)
    encrypted_pem = private_key.export_key(
        format="PEM",
        passphrase=derived,
        protection="PBKDF2WithHMAC-SHA512AndAES256-CBC",
    )
    with open(path, "wb") as f:
        f.write(salt)
        f.write(encrypted_pem)
    logger.info(f"Clé privée exportée vers {path}.")


def import_private_key(path: str, password: str) -> RSA.RsaKey:
    try:
        with open(path, "rb") as f:
            salt          = f.read(ARGON2_SALT_LEN)
            encrypted_pem = f.read()
        derived = _derive_key_argon2(password, salt)
        key     = RSA.import_key(encrypted_pem, passphrase=derived)
        logger.info("Clé privée importée avec succès.")
        return key
    except (ValueError, IndexError, TypeError) as e:
        logger.warning("Échec d'import de clé privée.")
        raise InvalidKeyError("Mot de passe incorrect ou fichier de clé corrompu.") from e


def export_public_key(public_key: RSA.RsaKey, path: str) -> None:
    with open(path, "wb") as f:
        f.write(public_key.export_key(format="PEM"))
    logger.info(f"Clé publique exportée vers {path}.")


def import_public_key(path: str) -> RSA.RsaKey:
    try:
        with open(path, "rb") as f:
            return RSA.import_key(f.read())
    except (ValueError, IndexError) as e:
        raise InvalidKeyError("Fichier de clé publique invalide ou corrompu.") from e


def get_key_fingerprint(key: RSA.RsaKey) -> str:
    pub_bytes = key.publickey().export_key(format="DER")
    digest    = hashlib.sha256(pub_bytes).hexdigest().upper()
    return ":".join(digest[i:i+2] for i in range(0, len(digest), 2))


# =============================================================================
# KEY DERIVATION FUNCTION — ARGON2id
# =============================================================================

def _derive_key_argon2(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret      = password.encode("utf-8"),
        salt        = salt,
        time_cost   = ARGON2_TIME_COST,
        memory_cost = ARGON2_MEM_COST,
        parallelism = ARGON2_PARALLELISM,
        hash_len    = ARGON2_HASH_LEN,
        type        = Type.ID,
    )


# =============================================================================
# SIGNATURE RSA-PSS
# =============================================================================

def sign_data(data: bytes, private_key: RSA.RsaKey) -> bytes:
    h         = SHA256.new(data)
    signature = pss.new(private_key).sign(h)
    logger.debug("Signature RSA-PSS générée.")
    return signature


def verify_signature(data: bytes, signature: bytes, public_key: RSA.RsaKey) -> None:
    try:
        h = SHA256.new(data)
        pss.new(public_key).verify(h, signature)
        logger.debug("Signature RSA-PSS vérifiée.")
    except (ValueError, TypeError) as e:
        logger.warning("Vérification de signature échouée.")
        raise SignatureVerificationError(
            "La signature du fichier est invalide."
        ) from e


# =============================================================================
# CHIFFREMENT AES-256-GCM
# =============================================================================

def _read_in_chunks(data: bytes, chunk_size: int = CHUNK_SIZE) -> Generator[bytes, None, None]:
    offset = 0
    while offset < len(data):
        yield data[offset : offset + chunk_size]
        offset += chunk_size


def aes_encrypt(data: bytes) -> dict:
    key    = get_random_bytes(AES_KEY_SIZE)
    nonce  = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext_parts = []
    for chunk in _read_in_chunks(data):
        ciphertext_parts.append(cipher.encrypt(chunk))
    tag        = cipher.digest()
    ciphertext = b"".join(ciphertext_parts)
    logger.debug(f"AES-256-GCM : {len(data)} bytes chiffrés.")
    return {"key": key, "nonce": nonce, "tag": tag, "ciphertext": ciphertext}


def aes_decrypt(key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext_parts = []
        for chunk in _read_in_chunks(ciphertext):
            plaintext_parts.append(cipher.decrypt(chunk))
        cipher.verify(tag)
        logger.debug("AES-256-GCM : déchiffrement et vérification réussis.")
        return b"".join(plaintext_parts)
    except ValueError as e:
        logger.error("Tag GCM invalide.")
        raise CorruptedFileError(
            "Le tag d'authentification est invalide. Le fichier est corrompu."
        ) from e


# =============================================================================
# CHIFFREMENT HYBRIDE COMPLET
# =============================================================================

def hybrid_encrypt(
    data: bytes,
    public_key: RSA.RsaKey,
    private_key: RSA.RsaKey,
    original_filename: str,
) -> dict:
    if len(data) > MAX_FILE_SIZE:
        raise UnsupportedFileError(f"Fichier trop volumineux (max {MAX_FILE_SIZE // 1024 // 1024} MB).")

    # Étape 1 : Hash SHA-256
    file_hash = hashlib.sha256(data).digest()
    logger.info(f"SHA-256 calculé : {file_hash.hex()[:16]}...")

    # Étape 2 : Signature RSA-PSS
    signature = sign_data(file_hash, private_key)
    logger.info("Fichier signé avec RSA-PSS.")

    # Étape 3 : Chiffrement AES-256-GCM
    aes_result = aes_encrypt(data)
    logger.info("Données chiffrées avec AES-256-GCM.")

    # Étape 4 : Chiffrement RSA-OAEP de la clé AES
    rsa_cipher    = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    encrypted_key = rsa_cipher.encrypt(aes_result["key"])
    logger.info("Clé AES chiffrée avec RSA-OAEP.")

    base_name   = os.path.splitext(original_filename)[0]
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_name = f"{base_name}_{timestamp}.bin"

    return {
        "output_filename"  : output_name,
        "original_filename": original_filename,
        "file_hash"        : file_hash,
        "signature"        : signature,
        "encrypted_key"    : encrypted_key,
        "nonce"            : aes_result["nonce"],
        "tag"              : aes_result["tag"],
        "ciphertext"       : aes_result["ciphertext"],
    }


def hybrid_decrypt(package: dict, private_key: RSA.RsaKey, public_key: RSA.RsaKey) -> bytes:
    # Étape 1 : Déchiffrement RSA-OAEP
    try:
        rsa_cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        aes_key    = rsa_cipher.decrypt(package["encrypted_key"])
    except (ValueError, TypeError) as e:
        raise InvalidKeyError("Impossible de déchiffrer la clé AES — clé privée incorrecte.") from e

    # Étape 2 : Déchiffrement AES-256-GCM
    plaintext = aes_decrypt(aes_key, package["nonce"], package["tag"], package["ciphertext"])

    # Étape 3 : Vérification SHA-256
    computed_hash = hashlib.sha256(plaintext).digest()
    if computed_hash != package["file_hash"]:
        logger.error("Hash SHA-256 incohérent.")
        raise IntegrityError("Le hash du fichier déchiffré ne correspond pas à l'original.")

    # Étape 4 : Vérification signature RSA-PSS
    verify_signature(package["file_hash"], package["signature"], public_key)

    logger.info("Déchiffrement complet — intégrité et authenticité confirmées.")
    return plaintext


# =============================================================================
# SÉRIALISATION DU PACKAGE BINAIRE
# =============================================================================

def save_package(path: str, package: dict) -> None:
    with open(path, "wb") as f:
        def write_field(data: bytes):
            f.write(struct.pack(">I", len(data)))
            f.write(data)
        write_field(package["encrypted_key"])
        write_field(package["signature"])
        f.write(package["file_hash"])
        f.write(package["nonce"])
        f.write(package["tag"])
        f.write(package["ciphertext"])
    logger.info(f"Package sauvegardé : {path}")


def load_package(path: str) -> dict:
    try:
        with open(path, "rb") as f:
            def read_field() -> bytes:
                size_bytes = f.read(4)
                if len(size_bytes) < 4:
                    raise CorruptedFileError("Structure du fichier binaire invalide.")
                size = struct.unpack(">I", size_bytes)[0]
                return f.read(size)
            encrypted_key = read_field()
            signature     = read_field()
            file_hash     = f.read(32)
            nonce         = f.read(NONCE_SIZE)
            tag           = f.read(TAG_SIZE)
            ciphertext    = f.read()
        logger.info(f"Package chargé depuis {path}.")
        return {
            "encrypted_key": encrypted_key,
            "signature"    : signature,
            "file_hash"    : file_hash,
            "nonce"        : nonce,
            "tag"          : tag,
            "ciphertext"   : ciphertext,
        }
    except (OSError, struct.error) as e:
        raise CorruptedFileError(f"Impossible de lire le package : {e}") from e
