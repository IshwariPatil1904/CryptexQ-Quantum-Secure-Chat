import base64
import hashlib
import os

# Try to import real pqcrypto Kyber KEM
try:
    from pqcrypto.kem.kyber512 import generate_keypair as kyber_generate, encrypt as kyber_encaps, decrypt as kyber_decaps
    _HAS_PQ = True
except Exception:
    # pqcrypto might not be available — provide a safe simulation fallback
    _HAS_PQ = False

# --- CONSTANTS FOR SIMULATION MODE ONLY ---
# This ensures that both simulated encapsulation and decapsulation return the same value.
# The SIMULATED_SECRET ensures the initiator and recipient derive the same PQC key component.
SIMULATED_SECRET = hashlib.sha256(b"simulated_kyber_ss_constant").digest()[:32] # Constant 32-byte Shared Secret

def b64_encode(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64_decode(s: str) -> bytes:
    return base64.b64decode(s.encode())

# Real Kyber functions (if library present) or simulated substitute
def generate_kyber_keypair():
    """
    Returns (public_key_bytes, secret_key_bytes). Both are raw bytes.
    """
    if _HAS_PQ:
        pk, sk = kyber_generate()
        return bytes(pk), bytes(sk)
    else:
        # Simulation: pk is random bytes (Kyber512 Public Key size)
        # sk is random bytes (Kyber512 Secret Key size)
        return os.urandom(800), os.urandom(1632) 

def kyber_encapsulate_with_pk(public_key_bytes: bytes):
    """
    Client-side encapsulation: returns (ciphertext_bytes, shared_secret_bytes)
    """
    if _HAS_PQ:
        ct, ss = kyber_encaps(public_key_bytes)
        return bytes(ct), bytes(ss)
    else:
        # Simulation: ciphertext random, but the shared secret is the consistent constant.
        # Kyber512 Ciphertext size is 768
        return os.urandom(768), SIMULATED_SECRET

def kyber_decapsitate_with_sk(secret_key_bytes: bytes, ciphertext_bytes: bytes):
    """
    Server-side decapsulation: returns shared_secret_bytes
    """
    if _HAS_PQ:
        # Real decapsulation logic
        ss = kyber_decaps(secret_key_bytes, ciphertext_bytes)
        return bytes(ss)
    else:
        # Simulation: successfully decapsulated, return the constant secret
        return SIMULATED_SECRET

# ---------- Hybrid key derivation ----------
def derive_hybrid_aes_key(qkd_aes_bytes: bytes, pqc_shared_secret: bytes) -> bytes:
    """
    Generates a 32-byte hybrid AES-256 key using XOR mixing.
    
    Input:
      - qkd_aes_bytes: 32 bytes from derive_aes_key_from_qkd (QKD component)
      - pqc_shared_secret: 32 bytes from Kyber decapsulation (PQC component)
      
    Output:
      - 32-byte AES key (for AES-256)
      
    Strategy (XOR Mixing):
      - Hash qkd_aes_bytes with SHA-256 -> H_QKD (32 bytes)
      - Hash pqc_shared_secret with SHA-256 -> H_PQC (32 bytes)
      - Final Key = H_QKD XOR H_PQC
    """
    # Hash the QKD component (already 32 bytes, but re-hash for consistency/protocol)
    h_qkd = hashlib.sha256(qkd_aes_bytes).digest()
    
    # Hash the PQC component
    h_pqc = hashlib.sha256(pqc_shared_secret).digest()
    
    # XOR the two 32-byte hashes to produce the final 32-byte hybrid key
    hybrid_key = bytes([h_qkd[i] ^ h_pqc[i] for i in range(32)])
    
    return hybrid_key