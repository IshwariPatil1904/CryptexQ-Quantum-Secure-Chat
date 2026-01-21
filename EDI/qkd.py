import random
import hashlib

def generate_qkd_key(n=256, error_rate=0.1):
    """
    Simulates BB84-like Quantum Key Distribution.
    Returns a list of shared key bits. 
    n is set high (256) to ensure enough raw material is generated for a 32-byte key, 
    since sifting will reduce the number of shared bits.
    """
    # Use n raw bits for Alice's photons
    alice_bits = [random.randint(0, 1) for _ in range(n)]
    alice_bases = [random.choice(["X", "Z"]) for _ in range(n)]
    bob_bases = [random.choice(["X", "Z"]) for _ in range(n)]

    bob_results = []
    # Simplified BB84 simulation: measurement results
    for bit, a_base, b_base in zip(alice_bits, alice_bases, bob_bases):
        if a_base == b_base:
            bob_results.append(bit)
        else:
            bob_results.append(random.randint(0, 1))

    # Add noise
    for i in range(len(bob_results)):
        if random.random() < error_rate:
            bob_results[i] = 1 - bob_results[i]

    # Sifting: keep only matching bases
    shared_key = [bit for bit, a_base, b_base in zip(alice_bits, alice_bases, bob_bases) if a_base == b_base]

    # Simple error correction (even parity)
    if shared_key and sum(shared_key) % 2 != 0:
        # Flip the last bit to ensure even parity
        shared_key[-1] = 1 - shared_key[-1] 

    # Return the full derived shared key bits list
    return shared_key

def derive_aes_key_from_qkd(qkd_bit_list: list) -> bytes:
    """
    Converts a list of QKD bits (integers 0 or 1) into a 32-byte (AES-256) key.
    
    This process uses SHA-256 to ensure a high-entropy, fixed-length key of 32 bytes.
    """
    # 1. Convert the list of integers [0, 1, 0, 1] into a string of bits "0101"
    bit_string = "".join(map(str, qkd_bit_list))
    
    # 2. Hash the bit string to derive a fixed-length key (32 bytes for SHA256)
    hash_digest = hashlib.sha256(bit_string.encode('utf-8')).digest()
    
    # Return the full 32 bytes
    return hash_digest