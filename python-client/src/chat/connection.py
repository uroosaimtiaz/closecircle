import os
import time
import socket
import threading
import base64
import pyautogui

from prompt_toolkit.shortcuts import button_dialog
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.layout import Justification

from .chat_ui import ChatUI
from .handshake import Handshake
from util.file_encryption import FileEncryption

class Connection:
    def __init__(self, zeroconf_service, user):
        self.ip_address = zeroconf_service.local_ip
        self.zeroconf_service = zeroconf_service
        self.user = user
        self.port = 3000
        self.app_socket = self.setup_socket()
        self.listening_for_connections = True
        self.busy = False
        self.chat_ui = None
        self.session_key = None
        self.peer_name = None

    def setup_socket(self):
        """
        This method sets up a socket that listens for incoming connection requests
        and is used for chatting.  
        """
        connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        connection_socket.bind((self.ip_address, self.port))
        connection_socket.listen(1)
        connection_socket.settimeout(1)
        return connection_socket

    def listen_for_connections(self):
        while True:
            if not self.listening_for_connections:
                self.app_socket.close()
                print("Stopped listening for connections.")
                return

            try:
                peer_socket, peer_address = self.app_socket.accept()
                if self.busy:
                    peer_socket.sendall('Currently unavailable.'.encode('utf-8'))
                    peer_socket.close()
                else:
                    initial_Message = peer_socket.recv(8192)
                    self.peer_name, contact = self.lookup_contact(peer_address[0])
                    if not contact:
                        peer_socket.close()
                    else:
                        self.handle_incoming_connection(peer_socket, initial_Message)
            except socket.timeout:
                continue
            except socket.error as e:
                print(f"Socket error: {e}")
        

    def lookup_contact(self, peer_ip : str) -> tuple[str, bool]:
        """
            This method searches peers list for a contact with the given IP address.
            Then it searches the contacts list and returns True if they are a contact, False otherwise.     
        """
        for peer in self.zeroconf_service.peers:
            ip_address = peer['addresses'][0].split(':')[0]  # Split the first address on the colon and take the first part
            if ip_address == peer_ip:
                peer_name = peer['name'].replace('._closecircle._tcp.local.', '')  # Remove the service name
                if self.user.contact_Manager.contact_exists(peer_name):
                    return (peer_name, True)
                else:
                    return (peer_name, False)


    def get_peers(self):
        return self.zeroconf_service.peers


    def handle_incoming_connection(self, peer_socket: socket.socket, initial_Message: Handshake.Message) -> bool:
        """
            This method is called when an incoming connection request is received.
            It displays a dialog box to the user asking whether to accept or deny the connection.
            If the connection is accepted, the user responds with their part of the handshake.
        """
        
        with patch_stdout():
            result = button_dialog(
                title='Incoming Connection',
                text=Justification.Center(f'You have an incoming connection request from {self.peer_name}, press yes to initiate handshake.'),
                buttons=[
                    ('Yes', True),
                ]
            ).run()

        if result:
            # get shared key
            shared_key = self.user.contact_Manager.get_shared_password(self.peer_name)
            if shared_key is None:
                print("No shared key.")
                return
            
            self.session_key = Handshake.accept_handshake(initial_Message, peer_socket, shared_key)
            if self.session_key is not None:
                threading.Thread(target=self.chat_session, args=(peer_socket,)).start()
            else:
                print("Handshake failed. Could not authenticate user.")
                peer_socket.close()
        else:
            peer_socket.close()

        return result


    def chat_session(self, peer_socket: socket.socket) -> bool:
        """
            Starts two threads: one for sending messages and another for receiving messages.
        """
        try:
            self.busy = True

            # Create a thread for receiving messages
            receive_thread = threading.Thread(target=self.receive_messages, args=(peer_socket,))
            receive_thread.start()

            # Start the chat UI
            self.chat_ui = ChatUI(self, peer_socket)
            self.chat_ui.run_chat()

            # Wait for the receive thread to finish
            receive_thread.join()

            self.end_session(peer_socket)
            self.busy = False
            return True

        except Exception as e:

            print(f"An error occurred during chat session: {e}")
            self.end_session(peer_socket)


    def send_file(self, file_path: str, peer_socket: socket.socket) -> None:
        """
            This method sends a file to the peer.
        """
        try:
            # Ensure the file exists before trying to open it
            if not os.path.exists(file_path):
                self.chat_ui.update_chat("File not found. Please check the file path.")
                return

            # Read the file content
            file_content = FileEncryption.get_bytes_from_file(file_path)

            # Encrypt file content
            encrypted_content, content_iv = Handshake.encrypt_data(file_content, self.session_key)
            
            # Extract and encrypt file name
            file_name = os.path.basename(file_path)  # Get only the file name, not the path
            encrypted_name, name_iv = Handshake.encrypt_data(file_name.encode(), self.session_key)
            
            # Create message objects for both file content and file name
            content_message = Handshake.Message(encrypted_content, content_iv)
            name_message = Handshake.Message(encrypted_name, name_iv)
            
            # Create a packet with both messages
            packet = Handshake.Packet([content_message, name_message])
            encoded_packet = Handshake.Packet.encode_packet(packet).encode()
            
            # Send the encoded packet to the peer
            peer_socket.sendall(encoded_packet)
            
            # Update chat UI to indicate file has been sent
            self.chat_ui.update_chat(f"File sent: {file_name}")

        except FileNotFoundError as fnf_error:
            print(f"Error: {fnf_error}")
            self.chat_ui.update_chat("File not found. Please check the file path.")

        except Exception as e:
            print(f"Error sending file: {e}")
            self.chat_ui.update_chat("Failed to send file.")


    def receive_file(self, file_message: Handshake.Message, filename_message: Handshake.Message) -> None:
        """
            This method receives a file from the peer.
        """
        try:
            # Decrypt file content
            decrypted_content = Handshake.decrypt_data(base64.b64decode(file_message.data), self.session_key, base64.b64decode(file_message.iv))
            
            # Decrypt file name
            decrypted_name = Handshake.decrypt_data(base64.b64decode(filename_message.data), self.session_key, base64.b64decode(filename_message.iv)).decode()
            
            # Secure file name handling to prevent directory traversal
            safe_file_name = os.path.basename(decrypted_name)  # Ensures that only the file name without path is used
            
            # Construct full path to save the file
            full_path = os.path.join(self.user.message_Manager.USER_FILES_PATH, safe_file_name)
            
            # Check if the directory exists, if not, create it
            if not os.path.exists(self.user.message_Manager.USER_FILES_PATH):
                os.makedirs(self.user.message_Manager.USER_FILES_PATH)
            
            # Save the decrypted file content to disk
            FileEncryption.write_bytes_to_file(full_path, decrypted_content)
            
            # Update chat UI to indicate file has been received
            self.chat_ui.update_chat(f"File received: {safe_file_name}")

            # add message to user's messages
            self.user.message_Manager.add_file(self.peer_name, self.zeroconf_service.username, decrypted_content, safe_file_name)
        
        except Exception as e:

            self.chat_ui.update_chat("Failed to receive file.")


    def send_messages(self, message: str, connection_socket: socket.socket) -> None:
        """
            This method sends messages to the peer.
        """
        try:

            # encrypt message
            encrypted_message, iv = Handshake.encrypt_data(message.encode(), self.session_key)
        
            # turn it into a message
            new_message = Handshake.Message(encrypted_message, iv)
            packet = Handshake.Packet([new_message])

            # send the message
            connection_socket.send(Handshake.Packet.encode_packet(packet).encode())

            # save message to user's messages
            self.user.message_Manager.add_message(self.zeroconf_service.username, self.peer_name, message)
            self.user.message_Manager.add_message(self.zeroconf_service.username, self.peer_name, message)

        except Exception as e:
            print(f"Error sending message: {e}")
            self.chat_ui.update_chat("Failed to send message.")


    def receive_messages(self, connection_socket: socket.socket):
        """
            This method receives messages from the peer.
        """
        while True:
            try:

                response = connection_socket.recv(8192)

                response_packet = Handshake.Packet.decode_packet(response.decode())

                # check if the message is a file
                if len(response_packet.messages) == 2:
                    file_message = response_packet.messages[0]
                    filename_message = response_packet.messages[1]
                    self.receive_file(file_message, filename_message)
                    continue

                response_message = response_packet.messages[0]
                decrypted_message = Handshake.decrypt_data(base64.b64decode(response_message.data), self.session_key, base64.b64decode(response_message.iv)).decode()

                # if the decoded message is exit, just call it
                if decrypted_message.lower() == 'exit1':
                    # send stop message
                    self.send_messages('exit2', connection_socket)
                    self.chat_ui.update_chat("Peer has left the chat. Press CTRL-C to return to menu.")
                    break

                elif decrypted_message.lower() == 'exit2':
                    self.chat_ui.update_chat("You have left the chat. Press CTRL-C to return to menu.")
                    break

                # save the message
                self.user.message_Manager.add_message(self.peer_name, self.zeroconf_service.username, decrypted_message)
                self.chat_ui.update_chat(f"Peer: {decrypted_message}")
            
            except Exception as e:

                print(f"Error receiving message: {e}")
                self.chat_ui.update_chat("Failed to receive message; peer may have disconnected or network unstable. Press CTRL-C to return to menu.")
                break


    def end_session(self, peer_socket):
        """
            This method ends the chat session.
        """
        self.busy = False
        if peer_socket:
            peer_socket.close()
            self.session_key = None
            self.peer_name = None
            print("Chat session ended.")
            pyautogui.hotkey('enter')
            

    def send_connection_request(self, peer_ip) -> None:
        """
            This method sends a connection request to the peer with the given IP address.
        """
        if not self.busy:
            try:
                # get shared key
                self.peer_name, contact = self.lookup_contact(peer_ip)

                if contact:
                    shared_key = self.user.contact_Manager.get_shared_password(self.peer_name)
                    if shared_key is not None:
                        print("shared key", shared_key)
                    else:
                        print("No shared key found.")
                        return False
                    
                    # Create a new socket for the outgoing connection
                    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    peer_socket.connect((peer_ip, self.port))
                    print("Sending connection request at", peer_ip, self.port)

                    try:
                        # initiate handshake message
                        print("Initiating handshake...")
                        self.session_key = Handshake.start_handshake(peer_socket, shared_key)

                        if self.session_key:
                            return self.chat_session(peer_socket)
                        else:
                            print("Connection denied by peer.")
                            peer_socket.close()
                            return False

                    except (BrokenPipeError, ConnectionResetError):
                        print("Peer closed the connection.")
                        peer_socket.close()
                        return False
                    
                else:
                    print("Contact not found.")
                    return False
                    
            except Exception as e:
                print(f"Error sending connection request: {e}")
                return False
    
    def close(self):
        self.zeroconf_service.unregister_service()
        self.listening_for_connections = False
        