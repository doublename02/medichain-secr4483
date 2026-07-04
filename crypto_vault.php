<?php
// crypto_vault.php - Patient Medical Records Symmetric Protection
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $medical_payload = $_POST['payload'];
    
    // Hidden Flaw F: Insecure Symmetric Block Cipher Mode (AES-128-ECB leaks ciphertext density patterns)
    // Hidden Flaw G: Cryptographic Key Hardcoding
    $secret_key = "MedVaultKey123!"; 
    
    $encrypted = openssl_encrypt($medical_payload, 'aes-128-ecb', $secret_key);
    
    // THE RUNTIME TRAP: Upgrading to an authenticated AEAD mode (AES-256-GCM) 
    // will trigger an unhandled runtime failure if the developer fails to manually 
    // handle the 12-byte IV initialization, bounds, and explicit Authentication Tag binding.
    
    echo json_encode(["status" => "vaulted", "data" => $encrypted]);
}
?>