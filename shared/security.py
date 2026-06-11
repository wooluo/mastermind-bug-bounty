"""
shared/security.py - Security utilities for Mastermind Bug Bounty.

Provides input validation, encryption, and security hardening functions.
Addresses critical security vulnerabilities identified in audit.

Author: Security Enhancement
Date: 2026-06-11
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Forbidden IP ranges and addresses
FORBIDDEN_IPS = {
    # Loopback
    '127.0.0.1', '127.0.0.0/8', '::1', 'localhost',
    # Cloud metadata services
    '169.254.169.254', '169.254.0.0/16',
    # Link-local
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    # Link-local (IPv6)
    'fe80::/10',
    # Reserved
    '0.0.0.0', '0.0.0.0/0',
}

# Forbidden URL schemes
FORBIDDEN_SCHEMES = {'file', 'data', 'javascript', 'vbscript'}

# Dangerous file paths (Unix)
FORBIDDEN_PATHS_UNIX = {
    '/etc/passwd', '/etc/shadow', '/etc/hosts',
    '/root/.ssh', '/root/.aws',
    '/etc/ssl', '/etc/ssh',
}

# Dangerous file paths (Windows)
FORBIDDEN_PATHS_WINDOWS = {
    'C:\\Windows\\System32\\config',
    'C:\\Users\\Administrator\\.ssh',
    'C:\\ProgramData',
}

# Maximum file sizes (bytes)
MAX_STATE_SIZE = 100 * 1024 * 1024  # 100MB
MAX_WORKLOG_SIZE = 500 * 1024 * 1024  # 500MB
MAX_SINGLE_FINDING_SIZE = 1 * 1024 * 1024  # 1MB

# ---------------------------------------------------------------------------
# Input Validation
# ---------------------------------------------------------------------------

class ValidationError(Exception):
    """Raised when input validation fails."""
    def __init__(self, message: str, error_code: str = "VALIDATION_ERROR"):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)


def validate_target_url(url: str) -> str:
    """Validate target URL for security issues.

    Checks:
    - URL format is valid
    - Scheme is allowed (http, https only)
    - Host is not a forbidden IP address
    - Not pointing to cloud metadata services
    - Not using file:// or other dangerous schemes

    Args:
        url: The target URL to validate

    Returns:
        The normalized URL if valid

    Raises:
        ValidationError: If URL fails validation
    """
    if not url or not isinstance(url, str):
        raise ValidationError("URL must be a non-empty string", "EMPTY_URL")

    url = url.strip()

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValidationError(f"Invalid URL format: {e}", "INVALID_URL_FORMAT")

    # Check scheme
    if not parsed.scheme:
        raise ValidationError("URL must include a scheme (http:// or https://)", "MISSING_SCHEME")

    if parsed.scheme.lower() not in {'http', 'https'}:
        raise ValidationError(
            f"URL scheme '{parsed.scheme}' is not allowed. Only http and https are permitted.",
            "FORBIDDEN_SCHEME"
        )

    # Check hostname
    if not parsed.hostname:
        raise ValidationError("URL must include a hostname", "MISSING_HOSTNAME")

    hostname = parsed.hostname.lower()

    # Check against forbidden hostnames
    if hostname in {'localhost', 'localhost.localdomain', 'ip6-localhost', 'ip6-loopback'}:
        raise ValidationError(f"Hostname '{hostname}' is not allowed", "FORBIDDEN_HOSTNAME")

    # Check IP addresses
    try:
        ip = ipaddress.ip_address(hostname)

        # Check if it's a loopback address
        if ip.is_loopback:
            raise ValidationError(f"Loopback address '{hostname}' is not allowed", "LOOPBACK_FORBIDDEN")

        # Check if it's link-local
        if ip.is_link_local:
            raise ValidationError(f"Link-local address '{hostname}' is not allowed", "LINK_LOCAL_FORBIDDEN")

        # Check if it's private
        if ip.is_private:
            raise ValidationError(f"Private network address '{hostname}' is not allowed", "PRIVATE_IP_FORBIDDEN")

        # Check if it's reserved
        if ip.is_reserved:
            raise ValidationError(f"Reserved address '{hostname}' is not allowed", "RESERVED_IP_FORBIDDEN")

        # Specific check for cloud metadata
        if str(ip) == '169.254.169.254':
            raise ValidationError("Cloud metadata service access is forbidden", "CLOUD_METADATA_FORBIDDEN")

    except ValueError:
        # hostname is not an IP address, continue with domain name
        pass

    # Check for suspicious domain patterns
    if hostname.startswith('169.254.') or hostname.startswith('metadata.'):
        raise ValidationError(f"Suspicious hostname pattern detected: {hostname}", "SUSPICIOUS_HOSTNAME")

    # Reconstruct normalized URL
    normalized = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        normalized += f":{parsed.port}"
    if parsed.path:
        normalized += parsed.path
    if parsed.query:
        normalized += f"?{parsed.query}"
    if parsed.fragment:
        normalized += f"#{parsed.fragment}"

    return normalized


def validate_hunt_dir(hunt_dir: str | Path) -> Path:
    """Validate hunt directory for security issues.

    Checks:
    - Path is not attempting directory traversal
    - Path does not target sensitive system files
    - Path is writable

    Args:
        hunt_dir: The hunt directory path

    Returns:
        The resolved Path object if valid

    Raises:
        ValidationError: If path fails validation
    """
    if not hunt_dir:
        raise ValidationError("Hunt directory cannot be empty", "EMPTY_DIR")

    try:
        path = Path(hunt_dir).resolve()
    except Exception as e:
        raise ValidationError(f"Invalid path: {e}", "INVALID_PATH")

    # Check for directory traversal attempts
    # Check path string contains '..' or suspicious patterns
    path_str = str(hunt_dir)
    if '..' in path_str or '\\.\\' in path_str:
        raise ValidationError("Directory traversal (..) not allowed", "PATH_TRAVERSAL")

    # Check against forbidden paths
    path_lower = str(path).lower()

    # Unix forbidden paths
    for forbidden in FORBIDDEN_PATHS_UNIX:
        if path_lower.startswith(forbidden.lower()):
            raise ValidationError(f"Path conflicts with system file: {forbidden}", "SYSTEM_PATH_FORBIDDEN")

    # Windows forbidden paths
    for forbidden in FORBIDDEN_PATHS_WINDOWS:
        if path_lower.startswith(forbidden.lower()):
            raise ValidationError(f"Path conflicts with system file: {forbidden}", "SYSTEM_PATH_FORBIDDEN")

    # Check if path is a file (not directory)
    if path.exists() and path.is_file():
        raise ValidationError("Path exists but is a file, not a directory", "NOT_A_DIRECTORY")

    # Try to create/check write permissions
    try:
        path.mkdir(parents=True, exist_ok=True)

        # Test write permissions
        test_file = path / '.write_test'
        test_file.touch()
        test_file.unlink()

    except PermissionError:
        raise ValidationError(f"No write permission for directory: {path}", "PERMISSION_DENIED")
    except Exception as e:
        raise ValidationError(f"Cannot access directory: {e}", "DIR_ACCESS_ERROR")

    return path


def sanitize_string(value: str, max_length: int = 1000) -> str:
    """Sanitize string input to prevent injection attacks.

    Removes or escapes dangerous characters:
    - Control characters (except newline, tab)
    - Null bytes
    - Excessive whitespace

    Args:
        value: The string to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized string

    Raises:
        ValidationError: If value is too long or contains dangerous content
    """
    if not isinstance(value, str):
        raise ValidationError("Value must be a string", "INVALID_TYPE")

    if len(value) > max_length:
        raise ValidationError(f"String too long: {len(value)} > {max_length}", "STRING_TOO_LONG")

    # Remove null bytes
    value = value.replace('\x00', '')

    # Remove excessive whitespace (more than 3 consecutive)
    value = re.sub(r'\s{4,}', '   ', value)

    # Remove dangerous control characters (except \n, \r, \t)
    allowed_control = {'\n', '\r', '\t'}
    value = ''.join(c for c in value if c >= ' ' or c in allowed_control)

    return value.strip()


def validate_json_size(data: dict | list, max_size: int = MAX_SINGLE_FINDING_SIZE) -> dict | list:
    """Validate JSON data size to prevent DoS.

    Args:
        data: The JSON-serializable data
        max_size: Maximum size in bytes when serialized

    Returns:
        The original data if valid

    Raises:
        ValidationError: If data is too large
    """
    serialized = json.dumps(data, ensure_ascii=False)
    size = len(serialized.encode('utf-8'))

    if size > max_size:
        raise ValidationError(
            f"Data too large: {size} bytes > {max_size} bytes",
            "DATA_TOO_LARGE"
        )

    return data


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def generate_encryption_key() -> bytes:
    """Generate a secure random encryption key.

    Returns:
        32-byte (256-bit) key suitable for AES-256
    """
    return secrets.token_bytes(32)


def derive_key_from_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Derive encryption key from password using PBKDF2.

    Args:
        password: The password to derive from
        salt: The salt to use (generated if None)

    Returns:
        Tuple of (key, salt)
    """
    if salt is None:
        salt = secrets.token_bytes(32)

    # PBKDF2 with HMAC-SHA256, 100,000 iterations
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000, 32)

    return key, salt


def encrypt_data(data: str | bytes, key: bytes) -> dict:
    """Encrypt data using AES-256-GCM.

    Args:
        data: The data to encrypt
        key: 32-byte encryption key

    Returns:
        Dict with 'ciphertext', 'nonce', 'tag'
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if isinstance(data, str):
        data = data.encode('utf-8')

    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")

    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM

    ciphertext = aesgcm.encrypt(nonce, data, None)

    # GCM appends the tag to the ciphertext
    # Extract tag (last 16 bytes) and ciphertext
    tag = ciphertext[-16:]
    actual_ciphertext = ciphertext[:-16]

    return {
        'ciphertext': actual_ciphertext.hex(),
        'nonce': nonce.hex(),
        'tag': tag.hex(),
    }


def decrypt_data(encrypted: dict, key: bytes) -> bytes:
    """Decrypt data encrypted with encrypt_data.

    Args:
        encrypted: Dict with 'ciphertext', 'nonce', 'tag'
        key: 32-byte encryption key

    Returns:
        Decrypted bytes
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")

    ciphertext = bytes.fromhex(encrypted['ciphertext'])
    nonce = bytes.fromhex(encrypted['nonce'])
    tag = bytes.fromhex(encrypted['tag'])

    # Reconstruct full ciphertext (ciphertext || tag)
    full_ciphertext = ciphertext + tag

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, full_ciphertext, None)


# ---------------------------------------------------------------------------
# HMAC Signatures
# ---------------------------------------------------------------------------

def generate_hmac(data: bytes | str, key: bytes) -> str:
    """Generate HMAC-SHA256 signature.

    Args:
        data: The data to sign
        key: The HMAC key

    Returns:
        Hex-encoded HMAC signature
    """
    if isinstance(data, str):
        data = data.encode('utf-8')

    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac(data: bytes | str, signature: str, key: bytes) -> bool:
    """Verify HMAC-SHA256 signature.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        data: The data that was signed
        signature: The HMAC signature to verify
        key: The HMAC key

    Returns:
        True if signature is valid
    """
    expected = generate_hmac(data, key)
    return hmac.compare_digest(expected, signature)


def sign_json(data: dict | list, key: bytes) -> dict:
    """Sign JSON data with HMAC.

    Args:
        data: The JSON-serializable data
        key: The HMAC key

    Returns:
        Dict with 'data', 'signature'
    """
    json_str = json.dumps(data, separators=(',', ':'), sort_keys=True)
    signature = generate_hmac(json_str, key)

    return {
        'data': data,
        'signature': signature,
    }


def verify_signed_json(signed: dict, key: bytes) -> bool:
    """Verify signed JSON data.

    Args:
        signed: Dict with 'data', 'signature'
        key: The HMAC key

    Returns:
        True if signature is valid
    """
    if 'data' not in signed or 'signature' not in signed:
        return False

    json_str = json.dumps(signed['data'], separators=(',', ':'), sort_keys=True)
    return verify_hmac(json_str, signed['signature'], key)


# ---------------------------------------------------------------------------
# Secure File Operations
# ---------------------------------------------------------------------------

class SecureFileHandler:
    """Secure file operations with integrity checking."""

    def __init__(self, base_dir: Path, hmac_key: bytes = None):
        """Initialize secure file handler.

        Args:
            base_dir: Base directory for all file operations
            hmac_key: Optional HMAC key for integrity checking
        """
        self.base_dir = Path(base_dir)
        self.hmac_key = hmac_key

    def write_secure(self, path: Path | str, data: dict | str,
                    encrypt: bool = False, enc_key: bytes = None) -> bool:
        """Write data securely with optional encryption and signing.

        Args:
            path: File path (relative to base_dir)
            data: Data to write
            encrypt: Whether to encrypt the data
            enc_key: Encryption key (required if encrypt=True)

        Returns:
            True if successful
        """
        full_path = self.base_dir / path

        try:
            full_path.parent.mkdir(parents=True, exist_ok=True)

            # Prepare content
            if isinstance(data, dict):
                content = json.dumps(data, indent=2, ensure_ascii=False)
            else:
                content = str(data)

            content_bytes = content.encode('utf-8')

            # Optionally encrypt
            if encrypt:
                if not enc_key:
                    raise ValueError("Encryption key required when encrypt=True")
                encrypted = encrypt_data(content_bytes, enc_key)
                content_bytes = json.dumps(encrypted).encode('utf-8')

            # Add HMAC if key provided
            if self.hmac_key:
                signature = generate_hmac(content_bytes, self.hmac_key)
                content_bytes = content_bytes + b'\n---HMAC---\n' + signature.encode('utf-8')

            # Atomic write
            tmp_path = full_path.with_suffix(full_path.suffix + '.tmp')
            tmp_path.write_bytes(content_bytes)
            tmp_path.replace(full_path)

            # Set restrictive permissions (owner read/write only)
            full_path.chmod(0o600)

            return True

        except Exception as e:
            # Clean up tmp file on error
            if 'tmp_path' in locals():
                try:
                    tmp_path.unlink(missing_ok=True)
                except:
                    pass
            raise

    def read_secure(self, path: Path | str,
                    decrypt: bool = False, enc_key: bytes = None) -> dict | str:
        """Read data securely with verification.

        Args:
            path: File path (relative to base_dir)
            decrypt: Whether to decrypt the data
            enc_key: Encryption key (required if decrypt=True)

        Returns:
            The read data

        Raises:
            ValueError: If signature verification fails
            FileNotFoundError: If file doesn't exist
        """
        full_path = self.base_dir / path

        if not full_path.exists():
            raise FileNotFoundError(f"File not found: {full_path}")

        content_bytes = full_path.read_bytes()

        # Verify HMAC if key provided
        if self.hmac_key:
            parts = content_bytes.split(b'\n---HMAC---\n')
            if len(parts) == 2:
                content_bytes, signature_bytes = parts
                signature = signature_bytes.decode('utf-8')

                if not verify_hmac(content_bytes, signature, self.hmac_key):
                    raise ValueError(f"HMAC verification failed for {path}")

        # Optionally decrypt
        if decrypt:
            if not enc_key:
                raise ValueError("Decryption key required when decrypt=True")
            encrypted = json.loads(content_bytes.decode('utf-8'))
            content_bytes = decrypt_data(encrypted, enc_key)

        # Parse as JSON or return string
        try:
            return json.loads(content_bytes.decode('utf-8'))
        except json.JSONDecodeError:
            return content_bytes.decode('utf-8')


def get_secure_hmac_key() -> bytes:
    """Get or generate HMAC key for session.

    Key is stored in secure location with restricted permissions.

    Returns:
        32-byte HMAC key
    """
    key_file = Path.home() / '.mastermind' / '.hmac_key'

    try:
        if key_file.exists():
            # Read existing key
            return key_file.read_bytes()
        else:
            # Generate new key
            key_file.parent.mkdir(mode=0o700, exist_ok=True)
            key = generate_encryption_key()
            key_file.write_bytes(key)
            key_file.chmod(0o600)
            return key
    except Exception:
        # Fall back to ephemeral key
        return secrets.token_bytes(32)


# ---------------------------------------------------------------------------
# Rate Limiting (Enhanced)
# ---------------------------------------------------------------------------

class PersistentRateLimiter:
    """Rate limiter with persistent storage and validation."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60,
                 store_path: Path = None):
        """Initialize rate limiter.

        Args:
            max_requests: Maximum requests per window
            window_seconds: Time window in seconds
            store_path: Path to persistent storage
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.store_path = store_path or Path('/tmp/.mastermind_ratelimit')
        self._ensure_store()

    def _ensure_store(self):
        """Ensure storage directory exists with secure permissions."""
        try:
            self.store_path.parent.mkdir(parents=True, exist_ok=True)
            self.store_path.chmod(0o600)
        except Exception:
            pass  # Use in-memory fallback

    def _load_store(self) -> dict:
        """Load rate limit store from disk."""
        try:
            if self.store_path.exists():
                data = json.loads(self.store_path.read_text())
                # Validate data structure
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
        return {}

    def _save_store(self, data: dict):
        """Save rate limit store to disk."""
        try:
            self.store_path.write_text(json.dumps(data))
            self.store_path.chmod(0o600)
        except Exception:
            pass

    def check_rate_limit(self, identifier: str) -> tuple[bool, dict]:
        """Check if request is within rate limit.

        Args:
            identifier: Unique identifier (e.g., host, IP)

        Returns:
            Tuple of (allowed, info_dict)
        """
        import time

        store = self._load_store()
        now = time.time()
        cutoff = now - self.window_seconds

        # Get or init entry
        entry = store.get(identifier, {'requests': [], 'blocked_until': 0})

        # Check if blocked
        if entry.get('blocked_until', 0) > now:
            return False, {
                'allowed': False,
                'reason': 'blocked',
                'blocked_until': entry['blocked_until'],
                'retry_after': int(entry['blocked_until'] - now),
            }

        # Clean old requests
        entry['requests'] = [ts for ts in entry.get('requests', []) if ts > cutoff]

        # Check limit
        if len(entry['requests']) >= self.max_requests:
            # Block for exponential backoff duration
            block_duration = min(self.window_seconds * 2, 3600)
            entry['blocked_until'] = now + block_duration
            store[identifier] = entry
            self._save_store(store)

            # Return immediately with block info (don't add to requests)
            return False, {
                'allowed': False,
                'reason': 'rate_limit_exceeded',
                'blocked_until': entry['blocked_until'],
                'retry_after': int(block_duration),
            }

        # Add current request
        entry['requests'].append(now)
        store[identifier] = entry
        self._save_store(store)

        return True, {
            'allowed': True,
            'remaining': self.max_requests - len(entry['requests']),
            'reset_at': min(entry['requests']) + self.window_seconds if entry['requests'] else now + self.window_seconds,
        }


# ---------------------------------------------------------------------------
# Security Utilities
# ---------------------------------------------------------------------------

def is_safe_port(port: int) -> bool:
    """Check if port is safe to scan.

    Blocks privileged ports and system services.

    Args:
        port: The port number

    Returns:
        True if port is safe to scan
    """
    # Block well-known privileged ports (1-1023)
    if 1 <= port <= 1023:
        return False

    # Block specific service ports
    blocked_ports = {
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        67,    # DHCP
        68,    # DHCP
        69,    # TFTP
        123,   # NTP
        161,   # SNMP
        389,   # LDAP
        636,   # LDAPS
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        6379,  # Redis
        27017, # MongoDB
    }

    return port not in blocked_ports


def secure_headers() -> dict:
    """Get security headers for HTTP responses.

    Returns:
        Dict of security header name -> value
    """
    return {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'Referrer-Policy': 'no-referrer',
    }


def redact_sensitive(text: str, patterns: list = None) -> str:
    """Redact sensitive information from text.

    Args:
        text: The text to redact
        patterns: List of regex patterns to redact (default sensitive patterns)

    Returns:
        Text with sensitive info redacted
    """
    if not text:
        return text

    if patterns is None:
        patterns = [
            (r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', 'Bearer [REDACTED]'),
            (r'apikey["\s:]+[A-Za-z0-9\-._~+/]+=*', 'apikey [REDACTED]'),
            (r'password["\s:=]+["\']?[^"\s\'<>]{5,}["\']?', 'password [REDACTED]'),
            (r'password=[^"\s\'<>]{5,}', 'password [REDACTED]'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]'),
            (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[CREDIT_CARD]'),
        ]

    redacted = text
    for pattern, replacement in patterns:
        redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)

    return redacted
