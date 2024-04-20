import json
import click

from .messages import MessageManager
from .contacts import ContactManager
from util.file_encryption import FileEncryption

class User:
    def __init__(self):
        self.USER_DATA_PATH = '../vault/profile/user.json'
        self.USER_HASH_PATH = '../vault/profile/user.json.checksum'
        self.user_data = self.load_user()
        self.message_Manager = None
        self.contact_Manager = None
        self.password = None
        

    def get_username(self) -> str:
        """
            Get the username of the current user
        """
        return self.user_data['username']
    

    def load_user(self) -> None:
        """
            Load user profile and store in user_data, checking its integrity.
        """
        try:
            # Load user profile from file and store in user_data
            user_profile = FileEncryption.get_bytes_from_file(self.USER_DATA_PATH)
            user_data = json.loads(user_profile)

            # Get the stored hash from the .checksum file
            stored_hash = FileEncryption.get_bytes_from_file(self.USER_HASH_PATH)

            if not FileEncryption.verify_checksum(stored_hash, user_profile):
                raise ValueError("Error: Checksum verification failed for user.json.")
            
            return user_data

        except json.JSONDecodeError:
            click.echo('User profile is not a valid JSON file.')
            return None
        
        except FileNotFoundError:
            click.echo('User profile not found.')
            return None
        
        except ValueError as e:
            click.echo(e)
            return None
        
    def start_managers(self) -> None:
        """
            Load the message and contact managers for the user.
        """
        if self.user_data is None:
            return

        self.message_Manager = MessageManager()
        self.contact_Manager = ContactManager()