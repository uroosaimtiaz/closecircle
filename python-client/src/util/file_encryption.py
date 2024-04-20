from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import constant_time
import os

class FileEncryption:
    """
        This class provides methods to encrypt and decrypt files using AES-256-CBC encryption.
        It is is in the utilities module because it is used by multiple classes.
    """
    def __init__(self):
        pass

    @staticmethod
    def verify_checksum(stored_hash: bytes, data: bytes) -> bool:
        """
            Verify the SHA-256 checksum of the data.
        """
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        checksum = digest.finalize()

        # crypto safe comparison
        return constant_time.bytes_eq(checksum, stored_hash)

    @staticmethod
    def checksum(data: bytes) -> bytes:
        """
            Generate SHA-256 checksum of the data.
        """
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        checksum = digest.finalize()
        return checksum

    @staticmethod
    def get_bytes_from_file(file_path : str) -> bytes:
        """
            Read the contents of a file and return it as bytes.
        """
        file_path = file_path.strip()  # Strip any leading or trailing spaces

        try:
            with open(file_path, 'rb') as file:
                return file.read() # Read the file as bytes
            
        except FileNotFoundError:
            print(f"Error: File not found at {file_path}")
            return None # Return None if file not found
        

    @staticmethod
    def write_bytes_to_file(file_path : str, data : bytes) -> None:
        """
            Write the given data to a file.
        """
        file_path = file_path.strip()  # Strip any leading or trailing spaces

        try:
            # Check if file exists, if not, create it
            if not os.path.exists(file_path):
                open(file_path, 'a').close()

            # Write the data to the file
            with open(file_path, 'wb') as file:  # Change 'rb' to 'wb'
                file.write(data)

        except FileNotFoundError:
            print(f"Error: File not found at {file_path}. Error creating file.")
            return None


    @staticmethod
    def encrypt_file(file_path: str, key: bytes, iv: bytes) -> bool:
        """
            Encrypt the file at the given path using AES-256-CBC encryption.
            Then write the ciphertext to the file, and the checksum to a separate file.
        """
        plaintext = FileEncryption.get_bytes_from_file(file_path)

        if plaintext is None:
            print(f"Error: plaintext was none")

        # Pad the plaintext for AES encryption, works even if plaintext is empty
        padder = padding.PKCS7(algorithms.AES.block_size).padder() # PKCS7 padding scheme
        padded_plaintext = padder.update(plaintext) + padder.finalize() # Add padding

        # Encrypt the padded plaintext
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) # AES-256-CBC encryption
        encryptor = cipher.encryptor() # Create an encryptor object
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize() # Encrypt the padded plaintext

        # Write the ciphertext to the file at the same path, overwriting the original file
        FileEncryption.write_bytes_to_file(file_path, ciphertext)
        
        # Generate checksum of the ciphertext
        checksum = FileEncryption.checksum(ciphertext)

        # Write the checksum to a separate file with .checksum extension
        checksum_file_path = file_path + ".checksum"
        FileEncryption.write_bytes_to_file(checksum_file_path, checksum)

        return True


    @staticmethod
    def decrypt_file(file_path : str, key : bytes, iv : bytes) -> bool:
        """
            Decrypt the file using AES-256-CBC decryption and 
            write the decrypted content back to the file.
        """
        ciphertext = FileEncryption.get_bytes_from_file(file_path)

        # Decrypt the ciphertext
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) # AES-256-CBC decryption
        decryptor = cipher.decryptor() # Create a decryptor object
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize() # Decrypt the ciphertext

        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder() # PKCS7 padding scheme
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize() # Remove padding
        
        # Write the decrypted content back to the file
        FileEncryption.write_bytes_to_file(file_path, plaintext)

        return True
