<?php
// crypto_vault_secure.php - Hardened Patient Medical Records Symmetric Protection
// Refactored to eliminate ECB pattern leakage (Flaw F) and key hardcoding (Flaw G)

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $medical_payload = $_POST['payload'] ?? '';

    if (empty($medical_payload)) {
        http_response_code(400);
        exit('No payload provided.');
    }

    // [S1] Load 32-byte AES-256 key from environment variable — NEVER hardcode secrets.
    // VAULT_ENCRYPTION_KEY must be set in .env as a 64-character hex string (32 raw bytes).
    // Generate: php -r "echo bin2hex(random_bytes(32));"
    $hexKey     = $_ENV['VAULT_ENCRYPTION_KEY'] ?? '';
    $secret_key = hex2bin($hexKey);

    if (strlen($secret_key) !== 32) {
        error_log('VAULT_ENCRYPTION_KEY missing or invalid: must be 64 hex chars (32 bytes).');
        http_response_code(500);
        exit('Cryptographic subsystem configuration error.');
    }

    try {
        $encrypted = encryptPayload($medical_payload, $secret_key);
        echo json_encode(["status" => "vaulted", "data" => $encrypted]);
    } catch (RuntimeException $e) {
        error_log('Encryption error: ' . $e->getMessage());
        http_response_code(500);
        exit('Encryption operation failed.');
    }
}

/**
 * Encrypts $plaintext using AES-256-GCM (AEAD).
 *
 * Serialization format (binary, then Base64-encoded):
 *   [ 12-byte random IV ] [ variable-length ciphertext ] [ 16-byte GCM authentication tag ]
 *
 * @param  string $plaintext  Raw plaintext to encrypt
 * @param  string $key        32-byte (256-bit) symmetric key
 * @return string             Base64-encoded serialized ciphertext bundle
 * @throws RuntimeException   If the OpenSSL encryption operation fails
 */
function encryptPayload(string $plaintext, string $key): string
{
    // [S2] Generate a cryptographically secure random 12-byte IV for each operation.
    // random_bytes() draws from the OS CSPRNG (/dev/urandom on Linux, CryptGenRandom on Windows).
    // A fresh IV per encryption prevents keystream reuse — IV reuse with the same key
    // in GCM mode allows C1 XOR C2 = P1 XOR P2, enabling plaintext recovery.
    $iv  = random_bytes(12); // 96-bit GCM standard nonce length

    $tag = '';

    // [S3] AES-256-GCM: Authenticated Encryption with Associated Data (AEAD).
    // GCM internally uses CTR mode (confidentiality) + GHASH over GF(2^128) (integrity).
    // The 16-byte authentication tag is computed over the entire ciphertext and written
    // to $tag by reference. Any subsequent modification to the ciphertext will produce
    // a different tag, which openssl_decrypt() will detect and reject.
    $ciphertext = openssl_encrypt(
        $plaintext,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,  // Output: 16-byte GHASH authentication tag
        '',    // Additional Authenticated Data (AAD) — empty for this implementation
        16     // Authentication tag length in bytes
    );

    if ($ciphertext === false) {
        throw new RuntimeException('openssl_encrypt failed: ' . openssl_error_string());
    }

    // [S4] Serialize: concatenate IV || ciphertext || tag, then Base64-encode for transport.
    // Fixed-length IV (12 bytes) at offset 0 and fixed-length tag (16 bytes) at the end
    // enable deterministic deserialization without delimiters or length-prefix fields.
    return base64_encode($iv . $ciphertext . $tag);
}

/**
 * Decrypts and authenticates a ciphertext bundle produced by encryptPayload().
 *
 * @param  string $serialized  Base64-encoded bundle: [12-byte IV][ciphertext][16-byte tag]
 * @param  string $key         32-byte (256-bit) symmetric key
 * @return string              Decrypted plaintext
 * @throws InvalidArgumentException  If the payload is structurally malformed
 * @throws RuntimeException          If the AEAD authentication tag does not match (tampering)
 */
function decryptPayload(string $serialized, string $key): string
{
    $binary = base64_decode($serialized, true);

    // Minimum valid bundle: 12 (IV) + 0 (empty ciphertext) + 16 (tag) = 28 bytes
    if ($binary === false || strlen($binary) < 28) {
        throw new InvalidArgumentException(
            'Malformed ciphertext payload: insufficient length or invalid Base64.'
        );
    }

    // [S5] Deserialize: extract the three components from their fixed-offset positions.
    $iv         = substr($binary, 0, 12);   // First 12 bytes  = IV
    $tag        = substr($binary, -16);     // Last 16 bytes   = GCM authentication tag
    $ciphertext = substr($binary, 12, -16); // Remaining bytes = ciphertext

    // [S6] AES-256-GCM decryption with mandatory authentication tag verification.
    // openssl_decrypt() recomputes the GHASH over the received ciphertext and compares it
    // to $tag using a constant-time byte comparison. If any ciphertext byte was modified
    // (by an attacker or transmission error), the tags differ and the function returns false.
    $plaintext = openssl_decrypt(
        $ciphertext,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );

    if ($plaintext === false) {
        // [S7] Halt execution before any tampered data reaches the application layer.
        // This exception propagates to the HTTP handler, which returns an error response
        // without disclosing internal state — an isolated, secure failure state.
        throw new RuntimeException(
            'AEAD authentication tag mismatch: ciphertext has been tampered with.'
        );
    }

    return $plaintext;
}
?>
