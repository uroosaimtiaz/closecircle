import threading
import click
import sys

from prompt_toolkit import PromptSession
from prompt_toolkit.shortcuts import radiolist_dialog, message_dialog

from user.user import User

from auth.register import Register
from auth.login import Login

from chat.zeroconf_service import ZeroconfService
from chat.connection import Connection


class App:
    """
        The main application class
    """

    def __init__(self):
        self.user = None
        self.zeroconf_service = None
        self.connection = None
        self.listen_thread = None
        self.password = None

    def start_services(self):
        """
            Start the zeroconf service and connection
        """
        username = self.user.get_username()
        self.zeroconf_service = ZeroconfService(username)
        self.connection = Connection(self.zeroconf_service, self.user)
        main_thread = threading.Thread(target=self.menu)
        self.listen_thread = threading.Thread(target=self.connection.listen_for_connections)
        main_thread.start()
        self.listen_thread.start()
        self.listen_thread.join()
        main_thread.join()


    def new_session(self):
        """
            Start a new user session
        """
        # Login
        if Register.user_exists():
            self.user = User()
            success, self.password = Login.login(self.user.user_data)
            if success:
                self.user.start_managers()
        # Register and optionally login
        else:
            success = Register.add_user()
            if click.confirm('Would you like to login?', default=True):
                self.user = User()
                success, self.password = Login.login(self.user.user_data)
                if success:
                    self.user.start_managers()
            else:
                return False
        return success


    def display_peers(self):
        """
            Display a list of available peers in a dialog box
        """
        peers = [peer['name'] for peer in self.zeroconf_service.peers if peer['name'] != self.zeroconf_service.service_name]
        
        if not peers:
            print('No peers available.')
            return
        
        message_dialog(
            title="Available Peers",
            text="\n".join(peers),
        ).run()


    def connect(self) -> None:
        """
            Connect to a peer
        """
        peers = [peer for peer in self.zeroconf_service.peers if peer['name'] != self.zeroconf_service.service_name]

        if not peers:
            print('No peers available.')
            return

        options = [(peer['name'], peer['name']) for peer in peers]

        options.append(('main_menu', 'Return to main menu'))

        result = radiolist_dialog(
            values=options,
            title="Peer Selection",
            text="Please select a peer:",
        ).run()

        if result == 'main_menu':
            return
        
        elif result:

            selected_peer = next((peer for peer in peers if peer['name'] == result), None)
            
            if selected_peer:
                peer_ip, _ = selected_peer['addresses'][0].split(':')
                connect = self.connection.send_connection_request(peer_ip)
                if not connect:
                    print('Connection failed. Ensure your peer has the correct name and password for you.')
                    return
            
        return

    def manage_contacts(self):
        """
            Options to add, delete, edit, or list contacts
        """

        session = PromptSession()
        options = ['Add Contact', 'Delete Contact', 'Edit Contact', 'List Contacts', 'Main Menu']

        while True:
            for i, option in enumerate(options, 1):
                print(f"{i}. {option}")
            
            choice = session.prompt('Please enter the number of your choice: ')
                
            if choice == '1':
                self.user.contact_Manager.add_contact()

            elif choice == '2':
                self.user.contact_Manager.remove_contact()

            elif choice == '3':
                self.user.contact_Manager.edit_contact()

            elif choice == '4':
                self.user.contact_Manager.list_contacts()

            elif choice == '5':
                
                break # Return to the main menu


    def view_messages(self):
        """
            View messages from a contact
        """
        session = PromptSession()
        name = session.prompt('Enter the name of the contact: ')

        # is name a contact
        if not self.user.contact_Manager.contact_exists(name):
            print('Contact does not exist.')
            return
        
        self.user.message_Manager.view_messages(name)


    def menu(self):
        """
            The main menu of the application 
        """
        print('Welcome to CloseCircle!')
        print('CloseCircle is a peer-to-peer secure messaging system that works on your local network.')

        session = PromptSession()
        options = ['Discover Peers', 'Start Chat', 'Manage Contacts', 'View Messages', 'Exit']

        try:
            while True:

                for i, option in enumerate(options, 1):
                    print(f"{i}. {option}")
                
                choice = session.prompt('Please enter the number of your choice: ')
                    
                if choice == '1':
                    self.display_peers()
                    session.prompt("Press any key to continue: ")

                elif choice == '2':
                    self.connect()
                    session.prompt("Press any key to continue: ")

                elif choice == '3':
                    self.manage_contacts()
                    session.prompt("Press any key to continue: ")

                elif choice == '4':
                    self.view_messages()
                    session.prompt("Press any key to continue: ")

                elif choice == '5':
                    self.close()
                    break
                
        except KeyboardInterrupt:
            self.close()
            sys.exit(0)
    

    def close(self):
        """
            Close the application, all threads and services.
        """
        Login.logout(self.user.user_data, self.password)
        self.connection.listening_for_connections = False
        self.listen_thread.join()
        self.zeroconf_service.unregister_service()

def main():
    app = App()
    if app.new_session():
        app.start_services()
    else:
        click.echo('Goodbye!')
        sys.exit(0)


if __name__ == '__main__':
    main()