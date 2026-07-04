<?php
// auth_secure.php - Hardened Staff Key Authentication System
// Refactored to eliminate Bound Constraint Failure (Flaw D) and MD5 (Flaw E)

require_once 'db_config.php'; // $pdo must be a PDO instance loaded from .env credentials

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $inputKey = $_POST['auth_key'] ?? '';
    $username = $_POST['username'] ?? '';

    // [S1] Semantic character-length boundary using mb_strlen()
    // strlen() counts raw bytes — a 64-emoji string is 256 bytes but only 64 characters.
    // mb_strlen('UTF-8') counts Unicode scalar values (codepoints), which is the correct
    // semantic unit consistent with all downstream processing (database VARCHAR, mb_substr, etc.)
    if (mb_strlen($inputKey, 'UTF-8') > 128 || mb_strlen($username, 'UTF-8') > 100) {
        http_response_code(400);
        exit('Input exceeds maximum character limit.');
    }

    // [S2] Retrieve the Argon2id hash from the database using a PDO prepared statement.
    // The hash is stored in the DB — it is NEVER hardcoded in source code.
    // This eliminates the key exposure to any developer with repository access.
    try {
        $stmt = $pdo->prepare(
            "SELECT auth_key_hash FROM staff_credentials WHERE username = :username LIMIT 1"
        );
        $stmt->bindParam(':username', $username, PDO::PARAM_STR);
        $stmt->execute();
        $staff = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log('Auth DB error: ' . $e->getMessage());
        http_response_code(500);
        exit('Authentication service unavailable.');
    }

    if ($staff === false) {
        // [S3] Perform a dummy password_verify() to equalise timing between
        // "user not found" and "wrong password" — prevents user enumeration via timing.
        password_verify($inputKey, '$argon2id$v=19$m=65536,t=4,p=2$dummySaltBase64===$dummyHashBase64===');
        http_response_code(401);
        exit('Access Denied.');
    }

    // [S4] password_verify() uses constant-time comparison (preventing timing side-channels).
    // It reads the algorithm identifier ($argon2id$), version, and parameters (m, t, p)
    // from the stored hash string itself — enabling algorithm agility without code changes.
    // Argon2id requires 64 MiB RAM per computation, limiting GPU parallelism to ~384
    // instances on a 24 GiB GPU vs. 64 billion MD5 computations per second.
    if (password_verify($inputKey, $staff['auth_key_hash'])) {
        // Optionally re-hash with updated parameters if cost factors have been upgraded
        if (password_needs_rehash($staff['auth_key_hash'], PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost'   => 4,
            'threads'     => 2,
        ])) {
            $newHash = hashNewAuthKey($inputKey);
            $upd = $pdo->prepare("UPDATE staff_credentials SET auth_key_hash = :h WHERE username = :u");
            $upd->execute([':h' => $newHash, ':u' => $username]);
        }
        echo "Access Granted.";
    } else {
        http_response_code(401);
        exit('Access Denied.');
    }
}

/**
 * Hash a new credential for storage in staff_credentials.auth_key_hash.
 * password_hash() generates a cryptographically random 128-bit salt per call
 * and embeds it in the output string alongside the algorithm parameters.
 */
function hashNewAuthKey(string $rawKey): string
{
    return password_hash($rawKey, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,  // 64 MiB RAM required per computation
        'time_cost'   => 4,      // 4 sequential passes over the memory block
        'threads'     => 2,      // 2 parallel internal lanes per invocation
    ]);
}
?>
