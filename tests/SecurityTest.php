<?php
// tests/SecurityTest.php
// PHPUnit 10.x Automated Security Verification Suite
// Covers three explicit runtime states:
//   1. Untampered cryptographic lifecycle (clean encrypt/decrypt round-trip)
//   2. Tampered ciphertext execution path (AEAD exception assertion)
//   3. Credential hash integrity match (Argon2id password_verify)

declare(strict_types=1);

namespace MediChain\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../crypto_vault_secure.php';

class SecurityTest extends TestCase
{
    private string $testKey;

    protected function setUp(): void
    {
        // 32-byte (256-bit) test key drawn from CSPRNG.
        // Generated fresh per test run for isolation — NOT loaded from .env.
        $this->testKey = random_bytes(32);
    }

    // =========================================================================
    // TEST 1: Untampered Cryptographic Lifecycle
    //
    // Verifies that encryptPayload() -> decryptPayload() round-trip produces
    // the exact original plaintext. Validates the correctness of:
    //   - IV generation and embedding
    //   - GCM encryption and serialization
    //   - Base64 encoding/decoding
    //   - IV/ciphertext/tag deserialization
    //   - GCM decryption with matching tag
    // =========================================================================
    public function testCleanEncryptDecryptCycleSucceeds(): void
    {
        $originalPlaintext = 'DIAGNOSIS: Stage-2 Carcinoma. TREATMENT: Chemotherapy cycle 1. STATUS: Critical.';

        $encrypted = encryptPayload($originalPlaintext, $this->testKey);

        // Encrypted output must be a non-empty string differing from plaintext
        $this->assertIsString($encrypted);
        $this->assertNotEmpty($encrypted);
        $this->assertNotSame($originalPlaintext, $encrypted,
            'Encrypted output must differ from plaintext.');

        // Minimum serialized length: base64( 12 + 0 + 16 ) = base64(28) = 40 chars
        $this->assertGreaterThanOrEqual(40, strlen($encrypted),
            'Encrypted bundle must meet minimum length (IV + tag).');

        $decrypted = decryptPayload($encrypted, $this->testKey);

        // Byte-exact match — verifies end-to-end integrity of the serialization pipeline
        $this->assertSame($originalPlaintext, $decrypted,
            'Decrypted output must byte-exactly match the original plaintext.');
    }

    // =========================================================================
    // TEST 2: Tampered Ciphertext Path — AEAD Exception Assertion
    //
    // Verifies that any modification to the ciphertext region (between the IV
    // and tag) is detected by the GHASH authentication tag recomputation and
    // causes decryptPayload() to throw RuntimeException.
    //
    // PHPUnit's expectException() declares the anticipated exception BEFORE the
    // triggering call. The test PASSES only when the exception is thrown with
    // the correct class and message pattern. If decryption silently succeeds
    // (which would mean tampered data was accepted), the test FAILS.
    // =========================================================================
    public function testTamperedCiphertextThrowsAEADException(): void
    {
        // Declare the expected exception before the action that should trigger it
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches(
            '/AEAD authentication tag mismatch/',
            'Exception message must identify the AEAD tag mismatch.'
        );

        $plaintext = 'Controlled substance dosage: Morphine 10mg — authorised by dr_faizal';
        $encrypted = encryptPayload($plaintext, $this->testKey);

        // Simulate an adversary modifying the ciphertext in transit or storage.
        // Byte 20 is within the ciphertext region (after the 12-byte IV prefix).
        // XOR-flipping all bits guarantees the byte value changes.
        $binary = base64_decode($encrypted);
        $binary[20] = chr(ord($binary[20]) ^ 0xFF);
        $tamperedPayload = base64_encode($binary);

        // This call MUST throw RuntimeException('AEAD authentication tag mismatch...')
        // because the GHASH recomputed from the corrupted ciphertext will not match $tag.
        // If this line completes without throwing, PHPUnit marks the test as FAILED.
        decryptPayload($tamperedPayload, $this->testKey);
    }

    // =========================================================================
    // TEST 3: Argon2id Credential Hash Integrity Match and Rejection
    //
    // Verifies that:
    //   (a) password_hash(PASSWORD_ARGON2ID) produces an $argon2id$ formatted hash
    //   (b) password_verify() returns TRUE for the correct input
    //   (c) password_verify() returns FALSE for an incorrect input
    //
    // This validates the cryptographic primitive replacement from MD5 to Argon2id
    // and confirms the constant-time comparison mechanism rejects wrong passwords.
    // =========================================================================
    public function testArgon2idHashIntegrityMatchAndRejection(): void
    {
        $validPassword   = 'testkey123';
        $invalidPassword = 'wrongpassword';

        // Hash using Argon2id with production-equivalent parameters
        $hash = password_hash($validPassword, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,  // 64 MiB RAM per computation
            'time_cost'   => 4,      // 4 sequential memory passes
            'threads'     => 2,      // 2 parallel internal lanes
        ]);

        // Verify the hash uses the correct algorithm identifier
        $this->assertStringStartsWith('$argon2id$', $hash,
            'Hash must use the Argon2id algorithm identifier ($argon2id$).');

        // Assert that the salt is embedded (parameters section must be present)
        $this->assertStringContainsString('m=65536,t=4,p=2', $hash,
            'Hash must embed the configured memory, time, and parallelism parameters.');

        // Correct password must verify successfully
        $this->assertTrue(
            password_verify($validPassword, $hash),
            'password_verify() must return TRUE for the correct password.'
        );

        // Wrong password must be rejected
        $this->assertFalse(
            password_verify($invalidPassword, $hash),
            'password_verify() must return FALSE for an incorrect password.'
        );

        // Verify that two hashes of the same password differ (unique salt per invocation)
        $hash2 = password_hash($validPassword, PASSWORD_ARGON2ID);
        $this->assertNotSame($hash, $hash2,
            'Two hashes of the same password must differ (unique random salt per call).');
        $this->assertTrue(
            password_verify($validPassword, $hash2),
            'Second hash must also verify correctly despite different salt.'
        );
    }
}
