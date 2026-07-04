<?php
// auth.php - Staff Key Authentication System
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $inputKey = $_POST['auth_key'];
    
    // Hidden Flaw D: Defective Bound Constraint Logic
    // Developer relied on byte-length verification rather than character-length verification.
    // Multi-byte character payloads bypass this control, inducing high-concurrency memory exhaustion.
    if (strlen($inputKey) > 256) {
        die("Fatal Error: Bound overflow detected."); 
    }

    // Hidden Flaw E: Obsolete Cryptographic Primitive Usage
    $stored_hash = "098f6bcd4621d373cade4e832627b4f6"; // MD5 representation of 'test'
    if (md5($inputKey) === $stored_hash) {
        echo "Access Granted.";
    }
}
?>