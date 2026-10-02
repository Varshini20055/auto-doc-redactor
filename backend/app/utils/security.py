"""
Security helpers:
- Fernet symmetric encryption for documents at rest
- SHA-256 checksums for integrity verification
- Simple API-key based access control dependency
"""
import hashlib
from pathlib import Path
from cryptography.fernet import Fernet
from fastapi import Header, HTTPException, status
from app.config import settings


def _get_fernet() -> Fernet:
    key = settings.ENCRYPTION_KEY
    if not key:
        # Dev fallback: derive a stable key from SECRET_KEY so restarts don't
        # invalidate previously encrypted files. In production, set
        # ENCRYPTION_KEY explicitly (generate with Fernet.generate_key()).
        import base64
        digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        key = base64.urlsafe_b64encode(digest)
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key)


def encrypt_file(src_path: Path, dst_path: Path) -> None:
    fernet = _get_fernet()
    data = src_path.read_bytes()
    dst_path.write_bytes(fernet.encrypt(data))


def decrypt_file(src_path: Path) -> bytes:
    fernet = _get_fernet()
    data = src_path.read_bytes()
    return fernet.decrypt(data)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Very light-weight API key auth. Swap for OAuth2/JWT in production; the
# access-control seam is kept here so it's a single place to upgrade.
# ---------------------------------------------------------------------------
def require_api_key(x_api_key: str = Header(default=None)):
    if settings.ENV == "development":
        return True  # auth disabled locally for convenience
    if not x_api_key or x_api_key != settings.SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )
    return True
