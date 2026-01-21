import base64
import hashlib
import hmac
import os
import random

# --- CONSTANTS ---
# AES key size is 32 bytes (256 bits)
AES_KEY_SIZE = 32 
# HMAC key size is 32 bytes (256 bits)
HMAC_KEY_SIZE = 32

def b64_encode(b: bytes) -> str:
    """Encodes bytes to a base64 string."""
    return base64.b64encode(b).decode()

def b64_decode(s: str) -> bytes:
    """Decodes a base64 string to bytes."""
    return base64.b64decode(s.encode())

# --- AES SIMULATION ---

def encrypt_aes(key: bytes, plaintext: str) -> dict:
    """
    Simulates AES-256 encryption.
    In a real system, this would use a library like Cryptography.
    It returns the plaintext, a simulated IV, and a simulated ciphertext.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes.")
    
    # Simulate an Initialization Vector (IV) - 16 bytes for AES
    simulated_iv = os.urandom(16)
    
    # Simple simulation of ciphertext: hash the plaintext + IV
    # This ensures the output is deterministic given the inputs, but is NOT real encryption.
    combined_data = key + simulated_iv + plaintext.encode('utf-8')
    simulated_ciphertext = hashlib.sha256(combined_data).digest()
    
    return {
        "ciphertext": b64_encode(simulated_ciphertext),
        "iv": b64_encode(simulated_iv)
    }

def decrypt_aes(key: bytes, encrypted_data: dict) -> str:
    """
    Simulates AES-256 decryption.
    Since encryption is simulated via hash, decryption is also simulated.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes.")
    
    # In a real system, decryption would use ciphertext, IV, and key.
    # In this simulation, we simply return the hardcoded simulation message.
    return f"Decrypted Message (Simulation Successful)"

# --- HMAC INTEGRITY CHECK ---

def sign_message(key: bytes, message_data: bytes) -> bytes:
    """
    Calculates an HMAC-SHA256 signature for message integrity.
    The key should be a separate key derived from the hybrid secret.
    """
    if len(key) != HMAC_KEY_SIZE:
        raise ValueError(f"HMAC key must be {HMAC_KEY_SIZE} bytes.")
    
    # Use HMAC-SHA256 to sign the data
    signature = hmac.new(key, message_data, hashlib.sha256).digest()
    return signature

def verify_message(key: bytes, message_data: bytes, signature: bytes) -> bool:
    """
    Verifies an HMAC-SHA256 signature.
    """
    if len(key) != HMAC_KEY_SIZE:
        raise ValueError(f"HMAC key must be {HMAC_KEY_SIZE} bytes.")
    
    # Calculate the expected signature
    expected_signature = sign_message(key, message_data)
    
    # Use hmac.compare_digest for secure, timing-attack-resistant comparison
    return hmac.compare_digest(expected_signature, signature)

if __name__ == "__main__":
    # Example usage for testing
    test_key = os.urandom(AES_KEY_SIZE)
    test_hmac_key = os.urandom(HMAC_KEY_SIZE)
    
    # 1. Encryption Test
    print("--- Encryption Test ---")
    message = "Hello, hybrid world!"
    encrypted = encrypt_aes(test_key, message)
    print(f"Original: {message}")
    print(f"Encrypted Ciphertext: {encrypted['ciphertext'][:10]}...")
    
    # 2. Decryption Test
    decrypted = decrypt_aes(test_key, encrypted)
    print(f"Decrypted: {decrypted}")
    
    # 3. Integrity Test
    print("\n--- HMAC Integrity Test ---")
    data_to_sign = message.encode('utf-8')
    signature = sign_message(test_hmac_key, data_to_sign)
    
    # Success case
    is_valid = verify_message(test_hmac_key, data_to_sign, signature)
    print(f"Signature Valid (Original Data): {is_valid}")
    
    # Failure case (tampered data)
    tampered_data = b"Hello, tampered world!"
    is_invalid = verify_message(test_hmac_key, tampered_data, signature)
    print(f"Signature Valid (Tampered Data): {is_invalid}")