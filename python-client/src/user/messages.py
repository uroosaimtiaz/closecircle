import json
import click
from datetime import datetime
from typing import List

from util.file_encryption import FileEncryption

class MessageManager:
    """
        This class contains methods to manage a user's messages.
        Messages are stored in a list of dictionaries.
    """

    def __init__(self):
        self.USER_MESSAGES_PATH = '../vault/messages/messages.json'
        self.USER_MESSAGES_HASH_PATH = '../vault/messages/messages.json.checksum'
        self.USER_FILES_PATH = '../vault/messages/files/'
        self.messages = self.load_messages()

    def load_messages(self) -> List[dict]:
        """
            Load the user's messages from the messages.json file into a list.
            Checks checksum to ensure data integrity.
        """
        try:
            # read messages from file
            messages_data = FileEncryption.get_bytes_from_file(self.USER_MESSAGES_PATH)

            # load messages from file into a list, decode bytes to string
            messages = json.loads(messages_data.decode('utf-8'))

            # Ensure messages is a list
            if not isinstance(messages, list):
                raise ValueError('messages.json should contain a JSON array, not a JSON object')
            
            return messages
        
        except FileNotFoundError:
            click.echo('Messages not found.')
            return []
        
        except json.JSONDecodeError:
            click.echo('Messages is not a valid JSON file.')
            return []


    def view_messages(self, name: str) -> None:
        """
            Filter the user's messages that contain the name.
        """
        # Filter messages that contain the name
        messages = [message for message in self.messages if message['receiver_name'] == name]
        if not messages:
            click.echo('No messages found.')
        else:
            click.echo('Messages:')
            for message in messages:
                click.echo(json.dumps(message))


    def save_messages(self) -> None:
        """
            Save the changes made to the user's messages to the messages.json file.
        """
        try:
            # Convert messages to bytes
            messages_data = json.dumps(self.messages).encode()

            # Write messages to file
            FileEncryption.write_bytes_to_file(self.USER_MESSAGES_PATH, messages_data) 

        except FileNotFoundError:
            click.echo('Messages file not found.')
            return


    def add_message(self, sender_name: str, receiver_name: str, message: str) -> bool:
        """
            Add a message to the user's messages.
        """
        new_message = {
            "type": "text",
            "sender_name": sender_name,
            "receiver_name": receiver_name,
            "timestamp": datetime.now().isoformat(),
            "content": message
        }
        self.messages.append(new_message)
        self.save_messages()

        return True

    def add_file(self, sender_name: str, receiver_name: str, file_data: bytes, file_name: str) -> bool:
        """
            Add a file to the user's messages.
        """
        # Define the file path in the vault
        file_path_vault = self.USER_FILES_PATH + file_name

        # Write the file data to the vault
        FileEncryption.write_bytes_to_file(file_path_vault, file_data)

        # Add the file to the user's messages
        new_message = {
            "type": "file",
            "sender_name": sender_name,
            "receiver_name": receiver_name,
            "timestamp": datetime.now().isoformat(),
            "content": {
                "file_name": file_name,
                "file_path": file_path_vault
            }
        }
        self.messages.append(new_message)
        self.save_messages()

        return True