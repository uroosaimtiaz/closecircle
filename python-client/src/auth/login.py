from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import constant_time
from util.file_encryption import FileEncryption
from typing import List, Dict
import click
import os
from typing import Tuple

class Login:
    """
        Class used to login an existing user.
    """

    def __init__(self):
        pass

    @staticmethod
    def get_master_key(password: str, salt: bytes) -> bytes:
        """
            Generate the Master Key using the password and salt.
        """
        # Derive the 256-bits Master Key
        master_kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000,)
        master_key = master_kdf.derive(password.encode())

        return master_key

    @staticmethod
    def hash_attempt(password: str, salt: bytes) -> bytes:
        """
            Hash the password attempt using the salt.
        """
        # Master Key
        master_key = Login.get_master_key(password, salt)

        # Derive 256-bits password hash using the Master Key and password as salt
        hash_kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=password.encode(), iterations=480000,)
        password_hash = hash_kdf.derive(master_key)

        return password_hash

    @staticmethod
    def verify_password(password: str, salt: bytes, password_hash: bytes) -> bool:
        """
            Check if the password attempt matches the stored password hash.
        """
        # hash the password attempt
        attempt_hash = Login.hash_attempt(password, salt)
        
        return constant_time.bytes_eq(attempt_hash, password_hash)

    @staticmethod
    def decrypt_key(encrypted_key: bytes, master_key: bytes) -> bytes:
        """
            Decrypts the given encrypted key using a stretched Master Key.

            This function utilizes HKDF (HMAC-based Key Derivation Function) to stretch
            the provided master key from 256 bits to 512 bits. HKDF follows the 
            'extract-then-expand' paradigm, extracting a pseudorandom key from the 
            initial keying material and then expanding it to the desired length. 
            
            The expanded key is then used to decrypt the encrypted key using AES-256 
            ECB (Electronic Codebook) mode. AES-256 is a symmetric encryption algorithm 
            that uses a 256-bit key, so we use the first 256 bits of the stretched key.
        """
        # Stretch Master Key to 512 bits using HKDF with SHA-256
        hkdf = HKDF(algorithm=hashes.SHA256(),length=64, salt=None, info=b"derive-key",)
        derived_key = hkdf.derive(master_key)

        # Decrypt secret key with first 256-bits of stretched Master Key using AES-256-ECB
        cipher = Cipher(algorithms.AES(derived_key[:32]), modes.ECB())
        decryptor = cipher.decryptor()
        decrypted_key = decryptor.update(encrypted_key) + decryptor.finalize()

        return decrypted_key
    
    @staticmethod
    def encrypt_files(user_data: Dict[str, str], file_paths: List[str], password) -> bool:
        """
            Encrypt the user's vault using the decrypted key and IV.
        """
        password = password
        salt = bytes.fromhex(user_data["salt"])
        encrypted_key = bytes.fromhex(user_data["encryption_key"])
        iv = bytes.fromhex(user_data["iv"])

        master_key = Login.get_master_key(password, salt)
        decrypted_key = Login.decrypt_key(encrypted_key, master_key)

        for file_path in file_paths:

            # Encrypt the user's vault using the decrypted key and IV
            FileEncryption.encrypt_file(file_path, decrypted_key, iv)

        return True
    
    @staticmethod
    def decrypt_files(user_data: Dict[str, str], file_paths: List[str], password) -> bool:
        """
            Encrypt the user's vault using the decrypted key and IV.
        """
        # Extract the password, salt, encrypted key, and IV from the user data
        password = password
        salt = bytes.fromhex(user_data["salt"])
        encrypted_key = bytes.fromhex(user_data["encryption_key"])
        iv = bytes.fromhex(user_data["iv"])

        master_key = Login.get_master_key(password, salt)
        decrypted_key = Login.decrypt_key(encrypted_key, master_key)

        for file_path in file_paths:
            # first verify checksum
            checksum_file_path = file_path + ".checksum"
            checksum = FileEncryption.get_bytes_from_file(checksum_file_path)
            ciphertext = FileEncryption.get_bytes_from_file(file_path)

            if not FileEncryption.verify_checksum(checksum, ciphertext):
                print(f"Error: Checksum verification failed for {file_path}.")
                return False
            
            # Encrypt the user's vault using the decrypted key and IV
            FileEncryption.decrypt_file(file_path, decrypted_key, iv)

        return True
    
    @staticmethod
    def encrypt_vault(user_data: Dict[str, str], password) -> bool:
        """
            Encrypt the user's vault using the decrypted key and IV.
        """

        # List all files in the vault in contacts, messages and subdirectories
        directories = ['../vault/contacts', '../vault/messages']
        file_paths = []
        for directory in directories:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if not file.endswith('.checksum'):
                        file_path = os.path.join(root, file)
                        file_paths.append(file_path)

        Login.encrypt_files(user_data, file_paths, password)

        return True
    
    @staticmethod
    def decrypt_vault(user_data: Dict[str, str], password) -> bool:
        """
            Decrypt the user's vault using the decrypted key and IV.
        """

        # Decrypt all files in the vault in contacts and messages and subdirectories
        directories = ['../vault/contacts', '../vault/messages']
        file_paths = []
        for directory in directories:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if not file.endswith('.checksum'):
                        file_path = os.path.join(root, file)
                        file_paths.append(file_path)

        Login.decrypt_files(user_data, file_paths, password)

        return True

    @staticmethod
    def login(user_data: Dict[str, str]) -> Tuple[bool, str]:
        """
            Login the user by verifying the password.
        """

        # Extract the username, salt, and password hash
        username = user_data["username"]
        salt = bytes.fromhex(user_data["salt"])
        password_hash = bytes.fromhex(user_data["password"])

        # Prompt the user for their password
        click.secho(f'Hi {username}! Enter your password to login.', fg='blue')
        password = click.prompt('Password', hide_input=True)

        # Verify the password
        if not Login.verify_password(password, salt, password_hash):
            print("Error: Incorrect password.")
            return False, None

        # Decrypt the user's vault
        Login.decrypt_vault(user_data, password)

        return True, password
    
    @staticmethod
    def logout(user_data: Dict[str, str], password : str) -> bool:
        """
            Logoff the user by encrypting the vault.
        """
        # Encrypt the user's vault
        Login.encrypt_vault(user_data, password)

        return True