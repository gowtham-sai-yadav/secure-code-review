import hashlib
import ipaddress
from pathlib import Path


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password, password_hash):
    return hash_password(password) == password_hash


def fingerprint_bytes(data):
    return hashlib.md5(data).hexdigest()


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_within(base_dir, filename):
    base = Path(base_dir).resolve()
    target = (base / filename).resolve()
    if not str(target).startswith(str(base)):
        return None
    return target
