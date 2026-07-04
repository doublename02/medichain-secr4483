# SECR4483/SCSR4483 — Secure Programming
## Final Examination (Alternative Assessment) — MediChain E-MedicVault Security Audit

**Student:** Cheah Seong Men  
**Matric No.:** A22EC0041  
**Section:** 02  
**Lecturer:** Dr Mohd Kufaisal bin Mohd Sidik  
**Session:** 2025/2026 Semester II

---

## Overview

This repository contains the post-incident security audit and remediation artifacts for the **MediChain E-MedicVault** Electronic Health Records system. Three legacy PHP source files were identified as primary breach vectors following a critical data exfiltration incident. This repository documents the vulnerability analysis, secure refactoring, and automated test verification.

---

## Repository Structure

```
medichain-secr4483/
│
├── Vulnerable Source Files (original — for audit reference)
│   ├── search.php              # Flaw A: SQL Injection | Flaws B,C: Reflected XSS
│   ├── auth.php                # Flaw D: strlen() byte/char mismatch | Flaw E: MD5
│   ├── crypto_vault.php        # Flaw F: AES-128-ECB pattern leakage | Flaw G: Hardcoded key
│   └── schema.sql              # Database schema and seed data
│
├── Secure Refactored Files
│   ├── search_secure.php       # PDO prepared statements + htmlspecialchars()
│   ├── auth_secure.php         # mb_strlen() + Argon2id (PASSWORD_ARGON2ID)
│   └── crypto_vault_secure.php # AES-256-GCM + random IV + AEAD tag serialization
│
├── Automated Test Suite
│   └── tests/
│       └── SecurityTest.php    # PHPUnit 10.x — 3 runtime state assertions
│
├── Configuration
    ├── .env.example            # Environment variable template (no real secrets)
    ├── .gitignore              # Excludes .env, vendor/, logs/
    └── phpunit.xml             # PHPUnit configuration

```

---

## Vulnerabilities Identified

| ID | File | Type | Secure Coding Principle Violated |
|----|------|------|----------------------------------|
| A | search.php | SQL Injection (UNION) | Separation of Data and Command |
| B/C | search.php | Reflected XSS | Input Validation Boundaries (Output Encoding) |
| D | auth.php | Bound Constraint Failure (byte vs character) | Input Validation Boundaries |
| E | auth.php | Obsolete Cryptographic Primitive (MD5) | Cryptographic Primitive Agility |
| F | crypto_vault.php | ECB Mode Pattern Leakage | Cryptographic Primitive Agility |
| G | crypto_vault.php | Hardcoded Encryption Key | Cryptographic Primitive Agility |

---

## Secure Refactoring Summary

### search.php → search_secure.php
- **SQL Injection fix:** Replaced `$conn->query($sql)` string concatenation with `$pdo->prepare()` + `bindParam()`. User input is transmitted as a binary protocol parameter, never parsed by the SQL grammar tokeniser.
- **XSS fix:** All output variables encoded with `htmlspecialchars($var, ENT_QUOTES, 'UTF-8')` at the HTML boundary. Browser tokeniser receives character entities, not markup tokens.
- **Boundary fix:** `mb_strlen($keyword, 'UTF-8')` replaces `strlen()` for semantically correct character-count validation.

### auth.php → auth_secure.php
- **Boundary fix:** `mb_strlen($inputKey, 'UTF-8') > 128` enforces a character-count limit consistent with downstream UTF-8 processing — eliminates multi-byte bypass anomalies.
- **Cryptographic fix:** `password_hash(PASSWORD_ARGON2ID)` with `memory_cost=65536` (64 MiB), `time_cost=4`, `threads=2`. Reduces GPU cracking throughput from ~64 billion (MD5) to ~1,097 hashes/second — approximately 58 million times harder to crack.
- **Key fix:** Hash stored in database via PDO, not hardcoded in source.

### crypto_vault.php → crypto_vault_secure.php
- **Algorithm fix:** Replaced `aes-128-ecb` (deterministic, unauthenticated) with `aes-256-gcm` (AEAD — confidentiality + integrity + authenticity).
- **IV fix:** `random_bytes(12)` generates a unique 96-bit IV per encryption via OS CSPRNG. Eliminates keystream reuse attacks.
- **Key fix:** 32-byte key loaded from `$_ENV['VAULT_ENCRYPTION_KEY']` (`.env` file), never hardcoded.
- **Serialization format:** `Base64( [12-byte IV] || [ciphertext] || [16-byte GCM tag] )`
- **Tampering detection:** Authentication tag mismatch throws `RuntimeException` before tampered data reaches the application layer.

---

## Running the Automated Tests

### Requirements
- PHP 8.1 or higher (with `openssl` extension enabled)
- Composer 2.x

### Install PHPUnit
```bash
composer require --dev phpunit/phpunit "^10"
```

### Run the test suite
```bash
.\vendor\bin\phpunit --testdox
```

### Expected output
```
MediChain\Tests\SecurityTest
 ✔ Clean encrypt decrypt cycle succeeds
 ✔ Tampered ciphertext throws AEAD exception
 ✔ Argon2id hash integrity match and rejection

OK (3 tests, 9 assertions)
```

### What each test asserts
| Test | Runtime State | Expected Result |
|------|--------------|-----------------|
| `testCleanEncryptDecryptCycleSucceeds` | Untampered encrypt→decrypt round-trip | Decrypted output === original plaintext |
| `testTamperedCiphertextThrowsAEADException` | Ciphertext corrupted (1 byte flipped) | `RuntimeException` thrown — PHPUnit: **PASSED** |
| `testArgon2idHashIntegrityMatchAndRejection` | Correct and incorrect passwords | `password_verify()` returns true / false respectively |

> **Note on Test 2:** A `PASSED` result means the `RuntimeException` was thrown as expected — the AEAD security control detected tampering. If decryption silently succeeded, the test would **FAIL**.

---

## Environment Setup

Copy `.env.example` to `.env` and populate the values:
```bash
cp .env.example .env
```

Generate an AES-256 encryption key:
```bash
php -r "echo bin2hex(random_bytes(32));"
```

Paste the output as the value of `VAULT_ENCRYPTION_KEY` in your `.env`.

> `.env` is excluded from version control by `.gitignore`. Never commit real secrets.

---

## PDPA 2010 Compliance Context

The vulnerabilities identified in this audit directly violated the Malaysian **Personal Data Protection Act (PDPA) 2010**, specifically **Section 9 (Security Principle)**, which requires data processors to take practical steps to protect personal data against loss, misuse, and unauthorised access. The secure refactoring addresses each violation at the structural level, eliminating the exploit delivery chains rather than applying superficial signature-based filtering.

---

## References

- OWASP Top 10 (2021) — A02 Cryptographic Failures, A03 Injection
- NIST SP 800-38D — Recommendation for GCM block cipher mode
- RFC 9106 — Argon2 memory-hard function
- Personal Data Protection Act 2010 (Act 709), Laws of Malaysia
- PHP Manual — `PDO::prepare()`, `password_hash()`, `openssl_encrypt()`
