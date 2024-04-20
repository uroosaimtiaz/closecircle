from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

import json
import click
from util.file_encryption import FileEncryption

class ContactManager:
    """
        This class contains methods to manage the user's contacts.
        Contacts are stored in a dictionary with the username as 
        the key and the shared password as the value.
    """

    def __init__(self):
        self.USER_CONTACTS_PATH = '../vault/contacts/contacts.json'
        self.USER_CONTACTS_HASH_PATH = '../vault/contacts/contacts.json.checksum'
        self.contacts = self.load_contacts()


    def contact_exists(self, username: str) -> bool:
        """
            Check if a contact exists in the user's contacts.
        """
        return username in self.contacts


    def load_contacts(self) -> None:
        """
            Load the user's contacts from the contacts file into a dictionary.
            Checks checksum to ensure data integrity.
        """
        try:
            # read contacts from file
            contacts_data = FileEncryption.get_bytes_from_file(self.USER_CONTACTS_PATH)

            # load contacts from file into a dictionary, decode bytes to string
            contacts = json.loads(contacts_data.decode('utf-8'))

            return contacts
        
        except FileNotFoundError:
            click.echo('Contacts not found.')
            return
        except json.JSONDecodeError:
            click.echo('Contacts is not a valid JSON file.')
            return
        

    def add_contact(self) -> bool:
        """
            This command asks for a contact name and a shared password, confirms the password,
            and returns a dictionary with the contact information.
        """
        click.secho('Contact Name:', fg='blue')
        username = click.prompt('Username')

        password = click.prompt('Shared Password:', hide_input=True, confirmation_prompt=True)
        click.secho('WARNING: ', nl=False, fg='yellow', bold=True)

        contact_info = {
            'name': username,
            'password': password
            
        }

        if self.contact_exists(username):
            click.secho('Contact already exists.', fg='red')
            return False
        else:
            self.contacts[username] = contact_info
            self.save_contacts()
            click.echo(f"Contact {username} added successfully.")
            return True
    

    def save_contacts(self) -> None:
        """
            Save the changes made to the user's contacts to the contacts.json file.
        """
        try:
            # write contacts to file, encode string to bytes
            contacts_data = json.dumps(self.contacts).encode('utf-8')
            FileEncryption.write_bytes_to_file(self.USER_CONTACTS_PATH, contacts_data)

        except FileNotFoundError:
            click.echo('Contacts file not found.')
            return
        
        except Exception as e:
            click.secho(f"An error occurred while saving contacts: {e}", fg='red')


    def list_contacts(self) -> None:
        """
            List all contacts stored in the user's contacts.
        """
        if self.contacts:
            click.secho('Contacts:', fg='green', bold=True)
            for contact in self.contacts:
                click.echo(f"  {contact}")
        else:
            click.echo('No contacts found.')


    def remove_contact(self) -> bool:
        """
            Remove a contact from the user's contacts.
        """
        click.secho('Enter the name of the contact you want to remove:', fg='blue')
        name = click.prompt('Contact Name')

        if not self.contact_exists(name):
            click.secho('Contact does not exist.', fg='red')
            return False
        
        else:
            del self.contacts[name]
            self.save_contacts()
            click.echo(f"Contact {name} removed successfully.")
            return True


    def edit_contact(self) -> bool:
        """
            Edit the shared password of an existing contact.
        """
        click.secho('Enter the name of the contact you want to edit:', fg='blue')
        name = click.prompt('Contact Name')
        if not self.contact_exists(name):
            click.secho(f'Contact {name} does not exist.', fg='red')
            return False

        password = click.prompt('Shared Password:', hide_input=True, confirmation_prompt=True)
        click.secho('WARNING: Make sure to share this password securely, out-of-band, and keep it a secret.', nl=False, fg='yellow', bold=True)

        self.contacts[name] = {'name': name, 'password': password}
        self.save_contacts()

        click.echo(f"Contact {name} updated successfully.")

        return True

    
    def KDFKeygen(self, password: str, key_size=32) -> bytes:
        """
            Key Derivation Function (KDF) using Scrypt for key stretching.
            Key size is set to 32 bytes (256 bits) for AES-256 encryption.
            This will be used for the handshake protocol.
        """
        salt = b'\x00' * 8  # This creates an 8-byte zeroed salt
        # Create the KDF object
        kdf = Scrypt(
            salt=salt,
            length=key_size,
            n=32768,
            r=8,
            p=1,
            backend=default_backend()
        )
        # Derive the key
        key = kdf.derive(password.encode())
        return key
    
    
    def get_shared_password(self, contact_name: str) -> bytes:
        """
            Returns the stretched shared password for the given contact.
        """
        try:
            if not self.contact_exists(contact_name):
                click.secho('Contact does not exist.', fg='red')
                return None
            else:
                # Get the shared password for the contact, and stretch it using KDF
                password = self.contacts[contact_name]['password']
                return self.KDFKeygen(password)
            
        except Exception as e:
            click.secho(f"An error occurred while getting shared password: {e}", fg='red')
            return None