#!/usr/bin/env python3
"""
tests/test_security.py — Security Test Suite

Comprehensive security tests for Mastermind Bug Bounty system.
Tests all critical security fixes and validates protections.

Run: python -m pytest tests/test_security.py -v
Or: python tests/test_security.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.security import (
    validate_target_url,
    validate_hunt_dir,
    sanitize_string,
    ValidationError,
    SecureFileHandler,
    generate_encryption_key,
    encrypt_data,
    decrypt_data,
    sign_json,
    verify_signed_json,
    PersistentRateLimiter,
    is_safe_port,
    redact_sensitive,
)


class SecurityTestResult:
    """Test result tracker."""

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []

    def add(self, test_name: str, passed: bool, message: str = ""):
        self.results.append((test_name, passed, message))
        if passed:
            self.passed += 1
        else:
            self.failed += 1

    def print_summary(self):
        print("\n" + "="*60)
        print("SECURITY TEST SUMMARY")
        print("="*60)
        for name, passed, msg in self.results:
            status = "✓ PASS" if passed else "✗ FAIL"
            print(f"  {status}: {name}")
            if msg:
                print(f"         {msg}")
        print(f"\nTotal: {self.passed} passed, {self.failed} failed")
        print("="*60)
        return self.failed == 0


def test_input_validation():
    """Test input validation protections."""
    results = SecurityTestResult()

    # Test 1: Valid URLs should pass
    test_cases_valid = [
        "https://example.com",
        "http://example.com:8080",
        "https://example.com/path?query=value",
    ]

    for url in test_cases_valid:
        try:
            result = validate_target_url(url)
            results.add(f"Valid URL: {url}", True)
        except ValidationError:
            results.add(f"Valid URL: {url}", False, "Should have passed")

    # Test 2: Invalid schemes should fail
    test_cases_invalid_scheme = [
        "file:///etc/passwd",
        "data:text/html,<script>",
        "javascript:alert(1)",
        "ftp://example.com",
    ]

    for url in test_cases_invalid_scheme:
        try:
            validate_target_url(url)
            results.add(f"Invalid scheme: {url}", False, "Should have been rejected")
        except ValidationError:
            results.add(f"Invalid scheme: {url}", True)

    # Test 3: Loopback addresses should be rejected
    test_cases_loopback = [
        "http://127.0.0.1",
        "http://127.0.0.1:8080",
        "http://localhost",
        "http://localhost.localdomain",
        "http://[::1]",
    ]

    for url in test_cases_loopback:
        try:
            validate_target_url(url)
            results.add(f"Loopback rejected: {url}", False, "Should have been rejected")
        except ValidationError:
            results.add(f"Loopback rejected: {url}", True)

    # Test 4: Private IPs should be rejected
    test_cases_private = [
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://192.168.1.1",
    ]

    for url in test_cases_private:
        try:
            validate_target_url(url)
            results.add(f"Private IP rejected: {url}", False, "Should have been rejected")
        except ValidationError:
            results.add(f"Private IP rejected: {url}", True)

    # Test 5: Cloud metadata should be rejected
    try:
        validate_target_url("http://169.254.169.254")
        results.add("Cloud metadata rejected", False, "Should have been rejected")
    except ValidationError:
        results.add("Cloud metadata rejected", True)

    # Test 6: Empty URL should fail
    try:
        validate_target_url("")
        results.add("Empty URL rejected", False, "Should have been rejected")
    except ValidationError:
        results.add("Empty URL rejected", True)

    results.print_summary()
    return results.failed == 0


def test_path_traversal_protection():
    """Test path traversal protection."""
    results = SecurityTestResult()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)

        # Test 1: Valid directories should pass
        try:
            valid_dir = tmppath / "safe_hunt"
            result = validate_hunt_dir(valid_dir)
            results.add("Valid directory accepted", True)
        except ValidationError:
            results.add("Valid directory accepted", False, "Should have passed")

        # Test 2: Directory traversal should fail
        traversal_cases = [
            tmppath / "../../../etc",
            tmppath / ".." / ".." / "root",
            tmppath / "./../etc",
        ]

        for path in traversal_cases:
            try:
                validate_hunt_dir(path)
                results.add(f"Traversal blocked: {path}", False, "Should have been rejected")
            except ValidationError:
                results.add(f"Traversal blocked: {path}", True)

        # Test 3: System paths should fail
        system_paths = [
            "/etc/passwd",
            "/root/.ssh",
        ]

        for path in system_paths:
            try:
                validate_hunt_dir(path)
                results.add(f"System path blocked: {path}", False, "Should have been rejected")
            except ValidationError:
                results.add(f"System path blocked: {path}", True)

    results.print_summary()
    return results.failed == 0


def test_string_sanitization():
    """Test string sanitization."""
    results = SecurityTestResult()

    # Test 1: Normal strings should pass
    normal = "Hello World"
    result = sanitize_string(normal)
    if result == normal:
        results.add("Normal string preserved", True)
    else:
        results.add("Normal string preserved", False, f"Got: {result}")

    # Test 2: Null bytes should be removed
    test = "Hello\x00World"
    result = sanitize_string(test)
    if '\x00' not in result:
        results.add("Null bytes removed", True)
    else:
        results.add("Null bytes removed", False, "Null bytes still present")

    # Test 3: Excessive whitespace should be reduced
    test = "Test    more    spaces"
    result = sanitize_string(test)
    if '    ' not in result:
        results.add("Excessive whitespace reduced", True)
    else:
        results.add("Excessive whitespace reduced", False, "Excessive spaces present")

    # Test 4: Too long strings should be rejected
    try:
        long_string = "A" * 2000
        sanitize_string(long_string, max_length=1000)
        results.add("Long string rejected", False, "Should have been rejected")
    except ValidationError:
        results.add("Long string rejected", True)

    # Test 5: Dangerous control characters should be removed
    test = "Test\x1B[31mRed\x1B[0m"
    result = sanitize_string(test)
    if '\x1B' not in result:
        results.add("Control chars removed", True)
    else:
        results.add("Control chars removed", False, "Control chars still present")

    results.print_summary()
    return results.failed == 0


def test_encryption():
    """Test encryption functionality."""
    results = SecurityTestResult()

    # Test 1: Generate key
    try:
        key = generate_encryption_key()
        if len(key) == 32:
            results.add("Key generation", True)
        else:
            results.add("Key generation", False, f"Wrong length: {len(key)}")
    except Exception as e:
        results.add("Key generation", False, str(e))

    # Test 2: Encrypt and decrypt
    try:
        key = generate_encryption_key()
        original = b"Secret message"

        encrypted = encrypt_data(original, key)
        if 'ciphertext' in encrypted and 'nonce' in encrypted and 'tag' in encrypted:
            results.add("Encryption format", True)
        else:
            results.add("Encryption format", False, "Missing required fields")

        decrypted = decrypt_data(encrypted, key)
        if decrypted == original:
            results.add("Encrypt/Decrypt roundtrip", True)
        else:
            results.add("Encrypt/Decrypt roundtrip", False, f"Mismatch: {decrypted}")

    except Exception as e:
        results.add("Encrypt/Decrypt roundtrip", False, str(e))

    # Test 3: Wrong key should fail
    try:
        key1 = generate_encryption_key()
        key2 = generate_encryption_key()
        original = b"Secret"

        encrypted = encrypt_data(original, key1)
        decrypt_data(encrypted, key2)
        results.add("Wrong key rejected", False, "Should have failed")
    except Exception:
        results.add("Wrong key rejected", True)

    results.print_summary()
    return results.failed == 0


def test_hmac_signing():
    """Test HMAC signing functionality."""
    results = SecurityTestResult()

    try:
        key = b"test_key_32_bytes______________"
        data = {"test": "data"}

        # Test signing
        signed = sign_json(data, key)
        if 'data' in signed and 'signature' in signed:
            results.add("HMAC signing format", True)
        else:
            results.add("HMAC signing format", False, "Missing fields")

        # Test verification with correct key
        if verify_signed_json(signed, key):
            results.add("HMAC verification (correct key)", True)
        else:
            results.add("HMAC verification (correct key)", False, "Should have verified")

        # Test verification with wrong key
        wrong_key = b"wrong_key_32_bytes___________"
        if not verify_signed_json(signed, wrong_key):
            results.add("HMAC verification (wrong key)", True)
        else:
            results.add("HMAC verification (wrong key)", False, "Should have failed")

        # Test tampered data
        tampered = signed.copy()
        tampered['data'] = {'tampered': 'data'}
        if not verify_signed_json(tampered, key):
            results.add("HMAC tamper detection", True)
        else:
            results.add("HMAC tamper detection", False, "Should have detected tampering")

    except Exception as e:
        results.add("HMAC operations", False, str(e))

    results.print_summary()
    return results.failed == 0


def test_rate_limiting():
    """Test rate limiting functionality."""
    results = SecurityTestResult()

    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / ".ratelimit"

        try:
            # Create rate limiter: 5 requests per 60 seconds
            limiter = PersistentRateLimiter(
                max_requests=5,
                window_seconds=60,
                store_path=store_path
            )

            # Test 1: First 5 requests should pass
            for i in range(5):
                allowed, info = limiter.check_rate_limit("test_host")
                if allowed:
                    continue
                else:
                    results.add(f"Rate limit request {i+1}", False, "Should have been allowed")
                    break
            else:
                results.add("Rate limit (first 5)", True)

            # Test 2: 6th request should be blocked
            allowed, info = limiter.check_rate_limit("test_host")
            if not allowed:
                results.add("Rate limit (exceeded)", True)
            else:
                results.add("Rate limit (exceeded)", False, "Should have been blocked")

            # Test 3: Different identifier should still work
            allowed, info = limiter.check_rate_limit("different_host")
            if allowed:
                results.add("Rate limit (separate ID)", True)
            else:
                results.add("Rate limit (separate ID)", False, "Should have been allowed")

        except Exception as e:
            results.add("Rate limiting", False, str(e))

    results.print_summary()
    return results.failed == 0


def test_port_safety():
    """Test port safety checks."""
    results = SecurityTestResult()

    # Safe ports
    safe_ports = [8080, 8443, 3000, 5000, 8000]
    for port in safe_ports:
        if is_safe_port(port):
            results.add(f"Safe port: {port}", True)
        else:
            results.add(f"Safe port: {port}", False, "Should be safe")

    # Unsafe ports
    unsafe_ports = [22, 23, 25, 53, 3306, 6379, 27017]
    for port in unsafe_ports:
        if not is_safe_port(port):
            results.add(f"Unsafe port blocked: {port}", True)
        else:
            results.add(f"Unsafe port blocked: {port}", False, "Should be blocked")

    # Privileged ports (1-1023)
    for port in [1, 80, 443, 1023]:
        if not is_safe_port(port):
            results.add(f"Privileged port blocked: {port}", True)
        else:
            results.add(f"Privileged port blocked: {port}", False, "Should be blocked")

    results.print_summary()
    return results.failed == 0


def test_data_redaction():
    """Test sensitive data redaction."""
    results = SecurityTestResult()

    # Test cases
    test_cases = [
        ("Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9", "Bearer [REDACTED]"),
        ("password=secret123", "password [REDACTED]"),
        ("user@example.com", "[EMAIL]"),
        ("4111-1111-1111-1111", "[CREDIT_CARD]"),
    ]

    for original, expected_contains in test_cases:
        result = redact_sensitive(original)
        if expected_contains in result:
            results.add(f"Redaction: {original[:20]}...", True)
        else:
            results.add(f"Redaction: {original[:20]}...", False, f"Expected '{expected_contains}', got '{result}'")

    # Test that safe content is preserved
    safe_content = "Normal text without secrets"
    result = redact_sensitive(safe_content)
    if safe_content in result:
        results.add("Safe content preserved", True)
    else:
        results.add("Safe content preserved", False, "Safe content was modified")

    results.print_summary()
    return results.failed == 0


def main():
    """Run all security tests."""
    print("\n" + "="*60)
    print("MASTERMIND BUG BOUNTY - SECURITY TEST SUITE")
    print("="*60 + "\n")

    all_passed = True

    print("\n--- Testing Input Validation ---")
    if not test_input_validation():
        all_passed = False

    print("\n--- Testing Path Traversal Protection ---")
    if not test_path_traversal_protection():
        all_passed = False

    print("\n--- Testing String Sanitization ---")
    if not test_string_sanitization():
        all_passed = False

    print("\n--- Testing Encryption ---")
    if not test_encryption():
        all_passed = False

    print("\n--- Testing HMAC Signing ---")
    if not test_hmac_signing():
        all_passed = False

    print("\n--- Testing Rate Limiting ---")
    if not test_rate_limiting():
        all_passed = False

    print("\n--- Testing Port Safety ---")
    if not test_port_safety():
        all_passed = False

    print("\n--- Testing Data Redaction ---")
    if not test_data_redaction():
        all_passed = False

    print("\n" + "="*60)
    if all_passed:
        print("✓ ALL TESTS PASSED")
        print("="*60)
        return 0
    else:
        print("✗ SOME TESTS FAILED")
        print("="*60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
