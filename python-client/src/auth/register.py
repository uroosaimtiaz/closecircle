import os
import click
import secrets
import json
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from util.file_encryption import FileEncryption
from auth.login import Login

class Register:
    def __init__(self):
        pass

    @staticmethod
    def set_username() -> str:
        """
            Prompts the user to set a username. The default username is the current OS's username.
        """
        default = lambda: os.environ.get("USER", "")
        click.secho('Choose a username. Your peers will discover you using this name.', fg='blue')
        if not click.confirm(f'The default username is: {default()}. Keep default?', default=True):
            username = click.prompt('Username')
        else:
            username = default()
        return username


    @staticmethod
    def set_password() -> str:
        """
            Prompts the user to set a password.
        """
        while True:
            if click.confirm('Generate strong password?', default=True):
                password = secrets.token_urlsafe(16)
                click.secho(f'Password: {password}', fg='green', nl=True)  # Use newline for clear separation
                if click.confirm('Keep this password?', default=True):
                    break
            else:
                click.secho('Enter a strong password. It is recommended to use a password manager to generate a random, difficult to guess password or pass phrase.', fg='blue')
                password = click.prompt('Password', hide_input=True, confirmation_prompt=True)
                break
            click.secho('WARNING: ', nl=False, fg='yellow', bold=True)
            click.secho('Please write down or securely store your password. There is no password recovery option.', fg='red') 
        return password


    @staticmethod
    def hash_password(password: str) -> Tuple[bytes, bytes, bytes]:
        """
            Used to hash the password and generate a Master Key for encryption/decryption.
            Returns the Master Key, password hash, and salt.
        """
        # Generate 128-bit salt recommended by NIST
        salt = os.urandom(16)

        # Derive 256-bits Master Key and password hash
        master_kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000,)
        hash_kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=password.encode(), iterations=480000,)
        
        # Generate Master Key
        master_key = master_kdf.derive(password.encode())

        # Generate the password hash
        password_hash = hash_kdf.derive(master_key)

        return master_key, password_hash, salt


    def symmetric_key_gen(master_key: bytes) -> dict:
        """
        Generates a random 256-bit symmetric key, derives a key from the master key,
        encrypts the symmetric key, and then decrypts it to verify the encryption process.

        """
        # Generate a random 256-bit key
        random_key = os.urandom(32)
        iv = os.urandom(16)

        # Stretch the Master Key to 512 bits using HKDF with SHA-256
        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b"derive-key")
        derived_key = hkdf.derive(master_key)

        # Encrypt the symmetric key with the first 256 bits of the Derived Key using AES-256-ECB
        cipher = Cipher(algorithms.AES(derived_key[:32]), modes.ECB())
        encryptor = cipher.encryptor()
        encrypted_key = encryptor.update(random_key) + encryptor.finalize()

        return encrypted_key, iv


    @staticmethod
    def generate_keys(password: str) -> Tuple[bytes, bytes, bytes, bytes]:
        """
            Generates and returns the password hash, salt, encrypted key, and IV for a user's profile. 
            A Master Key is also generated during this process, which is used for encrypting/decrypting the user's symmetric key. 
            This symmetric key is used to encrypt the user's vault. 
            Note: The Master Key is not stored and is only used during the current session.
        """
        # Hash password and generate Master Key
        master_key, password_hash, salt = Register.hash_password(password)

        # Generate random 256-bit key and 128-bit IV, encrypting the key with Master Key
        encrypted_key, iv = Register.symmetric_key_gen(master_key)

        # Return the password hash, salt, encrypted key, and IV
        return password_hash, salt, encrypted_key, iv
    

    @staticmethod
    def create_directories(user_data: bytes, password) -> None:
        """
        Create the necessary directories and files for the user's vault.
        Generates checksums for the user.json file and other files,
        and encrypts the vault using the user's password.
        """

        base_path="../vault"

        # Define all necessary subpaths
        paths = [
            "profile",
            "contacts",
            "messages",
            "messages/files"
        ]

        files = {
            "contacts/contacts.json": "{}",
            "messages/messages.json": "[]",
        }

        for path in paths:
            full_path = os.path.join(base_path, path)
            os.makedirs(full_path, exist_ok=True)

        # Write the user_data to the user.json file
        user_file_path = os.path.join(base_path, "profile/user.json")
        FileEncryption.write_bytes_to_file(user_file_path, user_data)

        # write checksum for user.json
        checksum = FileEncryption.checksum(user_data)
        checksum_file_path = os.path.join(base_path, "profile/user.json.checksum")
        FileEncryption.write_bytes_to_file(checksum_file_path, checksum)

        # create files
        for file, content in files.items():
            full_path = os.path.join(base_path, file)
            data = content.encode()

            # write the data to the files
            FileEncryption.write_bytes_to_file(full_path, data)

            # write checksum for the files
            checksum = FileEncryption.checksum(data)
            checksum_file_path = os.path.join(base_path, f"{file}.checksum")
            FileEncryption.write_bytes_to_file(checksum_file_path, checksum)

        # encrypt the vault
        Login.encrypt_vault(json.loads(user_data), password)


    @staticmethod
    def add_user() -> bool:
        """
            Write user profile to vault
        """
        try:
            username = Register.set_username()
            password = Register.set_password()

            # generate hash and keys
            password_hash, salt, encrypted_key, iv = Register.generate_keys(password)

            user_profile = {'username': username, 'password': password_hash.hex(), 
                        'salt': salt.hex(), 'encryption_key': encrypted_key.hex(), 
                        'iv': iv.hex()}
            
            user_data = json.dumps(user_profile).encode()

            # create directories and files
            Register.create_directories(user_data, password)

            click.echo(f'Registration successful. Thank you {username}.')
            click.echo('You can now log-in using your new account.')

            return True
        
        except Exception as e:
            click.echo(f'An error occurred: {e}')

    @staticmethod
    def user_exists() -> bool:
        """
            Check if user profile already exists  
        """
        USER_DATA_PATH = '../vault/profile/user.json'
        try:
            return os.path.isfile(USER_DATA_PATH)
        
        except Exception as e:
            print(f"An error occurred while checking if the user exists: {e}")
            return False