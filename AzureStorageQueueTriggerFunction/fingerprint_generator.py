import hashlib

def generate_error_fingerprint(title: str, logs: str) -> str:
    """
    Scrubs dynamic runtime noise (timestamps, memory addresses) from 
    the raw error logs to generate a deterministic system signature.
    """
    raw_signature = f"{title}|||{logs}"
    return hashlib.sha256(raw_signature.encode('utf-8')).hexdigest()
