import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def symmetric_key_gen(master_key: bytes) -> dict:
    """
    Generates a random 256-bit symmetric key, derives a key from the master key,
    encrypts the symmetric key, and then decrypts it to verify the encryption process.
    
    Args:
    master_key (bytes): The master key from which a derived key is generated.
    salt (bytes): The salt used in the HKDF process for better security.
    
    Returns:
    dict: A dictionary containing the symmetric key, encrypted key, decrypted key, and the IV used.
    """
    print(f"Master Key: {master_key.hex()}")

    # Generate a random 256-bit key
    random_key = os.urandom(32)
    iv = os.urandom(16)  # Not used in ECB mode but generated for potential use in other modes.

    print(f"Generated symmetric key: {random_key.hex()}")

    # Stretch the Master Key to 512 bits using HKDF with SHA-256
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b"derive-key")
    derived_key = hkdf.derive(master_key)

    # Encrypt the symmetric key with the first 256 bits of the Derived Key using AES-256-ECB
    cipher = Cipher(algorithms.AES(derived_key[:32]), modes.ECB())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(random_key) + encryptor.finalize()

    print(f"Encrypted key: {encrypted_key.hex()}")
    print(f"Size: {len(encrypted_key)}")

    # Decrypt the symmetric key with the first 256 bits of the stretched Master Key using AES-256-ECB
    cipher = Cipher(algorithms.AES(derived_key[:32]), modes.ECB())
    decryptor = cipher.decryptor()
    decrypted_key = decryptor.update(encrypted_key) + decryptor.finalize()

    print(f"Decrypted key: {decrypted_key.hex()}")
    print(f"Size: {len(decrypted_key)}")

    return encrypted_key, iv, encrypted_key.hex(), iv.hex()

# Example usage:
# Assume 'master_key_hex' and 'salt_hex' are provided as hex strings.
master_key_hex = "8d1556255c52fb6380c03c01393f59c0d64071e614418e14f4ef74d0f5487e5c"
salt_hex = "f541d3029b299530b770b5687bde925b"
master_key = bytes.fromhex(master_key_hex)
salt = bytes.fromhex(salt_hex)

result = symmetric_key_gen(master_key)
print(result)
