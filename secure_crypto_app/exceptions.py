class CryptoAppError(Exception):
    """Exception de base de l'application."""

class InvalidKeyError(CryptoAppError):
    """Clé incorrecte ou fichier PEM corrompu."""

class CorruptedFileError(CryptoAppError):
    """Fichier chiffré altéré ou structure binaire invalide."""

class SignatureVerificationError(CryptoAppError):
    """Signature RSA-PSS invalide — authenticité non confirmée."""

class IntegrityError(CryptoAppError):
    """Hash SHA-256 incohérent — intégrité compromise."""

class UnsupportedFileError(CryptoAppError):
    """Fichier trop volumineux ou format non supporté."""
