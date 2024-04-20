import os
import json
import base64
from typing import Tuple
import socket

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hashes

class Handshake:
    class Message:
        def __init__(self, data, iv, hash=None):
            self.data = base64.b64encode(data).decode('utf-8')
            self.iv = base64.b64encode(iv).decode('utf-8')
            self.hash = base64.b64encode(hash if hash else self.hash_sha256(data)).decode('utf-8')

        @staticmethod
        def hash_sha256(data):
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(data)
            return digest.finalize()

    class Packet:
        def __init__(self, messages):
            self.messages = messages

        @staticmethod
        def encode_packet(packet):
            return json.dumps([message.__dict__ for message in packet.messages])

        @staticmethod
        def decode_packet(data):
            packet_list = json.loads(data)
            messages = [
                Handshake.Message(base64.b64decode(msg['data']), base64.b64decode(msg['iv']), base64.b64decode(msg['hash']))
                for msg in packet_list
            ]
            return Handshake.Packet(messages)

    @staticmethod
    def generate_challenge(session_key: bytes) -> Tuple[bytes, Message]:
        """
        Return the nonce and a message that contains the nonce encrypted with the session key.
        """
        nonce = os.urandom(8)
        encrypted_nonce, iv = Handshake.encrypt_data(nonce, session_key)
        return nonce, Handshake.Message(encrypted_nonce, iv)

    @staticmethod
    def respond_to_challenge(challenge: Message, session_key: bytes) -> Tuple[bytes, Message]:
        """
        Return a message that contains the decrypted challenge concatenated with the provided nonce, encrypted with the session key.
        """
        decrypted_challenge = Handshake.decrypt_data(base64.b64decode(challenge.data), session_key, base64.b64decode(challenge.iv))
        nonce = os.urandom(8)
        new_challenge = nonce + decrypted_challenge
        encrypted_response, iv = Handshake.encrypt_data(new_challenge, session_key)
        return nonce, Handshake.Message(encrypted_response, iv)

    @staticmethod
    def verify_challenge_accept(response: Message, session_key: bytes, nonce: bytes) -> Tuple[bool, Message]:
        """
        Verify that the response contains the provided nonce. Return a tuple with a boolean indicating
        whether the nonce was verified and a message containing the rest of the decrypted response.
        """
        decrypted_response = Handshake.decrypt_data(base64.b64decode(response.data), session_key, base64.b64decode(response.iv))
        split_index = len(decrypted_response) // 2
        challenge, response = decrypted_response[:split_index], decrypted_response[split_index:]
        if response == nonce:
            encrypted_challenge, iv = Handshake.encrypt_data(challenge, session_key)
            return True, Handshake.Message(encrypted_challenge, iv)
        return False, None

    @staticmethod
    def generate_ecdh_key_pair():
        # Generate an ECDH key pair
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        
        # Serialize the public key to raw uncompressed bytes
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return private_key, public_key_bytes
        
    """
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key
    """

    @staticmethod
    def generate_random_password():
        return os.urandom(32)

    @staticmethod
    def encrypt_data(data : bytes, password: bytes) -> Tuple[bytes, bytes]:
        iv = os.urandom(16)  # Generate a random IV
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(password), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return ct, iv

    @staticmethod
    def decrypt_data(ciphertext, password, iv):
        cipher = Cipher(algorithms.AES(password), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data
    
    @staticmethod
    def load_public_key_from_bytes(public_key_bytes):
        # Assuming public_key_bytes is in uncompressed format with the 0x04 prefix
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),  # Make sure to use the correct curve corresponding to the key
            public_key_bytes
        )
        return public_key

    @staticmethod
    def start_handshake(peer_socket, password):
        """
        The start handshake function is used to initiate a handshake with another peer.
        It sends the public key and challenge to the receiver, and waits for a response
        with the receiver's public key and challenge, derives the shared key, and responds
        with the challenge response. It then waits for the peer's challenge response to verify
        the connection.

        If there are padding or other errors decrypted and parsing the recieved data,
        default values for the incoming receiver's public key and challenge response
        are used, so the handshake can continue.

        This is in case of a peer sending invalid data or if the data is tampered with,
        or using an old, compromised password-derived key.

        """
        # Generate key pair
        private_key, public_key = Handshake.generate_ecdh_key_pair()

        # Encrypt the public key to send to the receiver
        encrypted_public_key, iv = Handshake.encrypt_data(public_key, password)

        message = Handshake.Message(encrypted_public_key, iv)
        packet = Handshake.Packet([message])
        peer_socket.send(Handshake.Packet.encode_packet(packet).encode())

        peer_socket.settimeout(30)

        # Wait to receive the new public key and challenge from the receiver
        try:
            encrypted_response = peer_socket.recv(8192)
        except socket.timeout:
            print("Handshake timed out.")
            return None
    
        if not encrypted_response:
            return None

        try:
            received_packet = Handshake.Packet.decode_packet(encrypted_response.decode())
            received_public_key_msg = received_packet.messages[0]
            received_challenge_msg = received_packet.messages[1]

            decrypted_peer_public_key_bytes = Handshake.decrypt_data(base64.b64decode(received_public_key_msg.data), password, base64.b64decode(received_public_key_msg.iv))
       
            # Assuming decrypted_peer_public_key_bytes is the raw bytes of the public key
            peer_public_key = Handshake.load_public_key_from_bytes(decrypted_peer_public_key_bytes)

            shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

        except Exception as e:
            return None

        # Respond to the challenge
        nonce, response_message = Handshake.respond_to_challenge(received_challenge_msg, shared_key)
        response_packet = Handshake.Packet([response_message])
        peer_socket.send(Handshake.Packet.encode_packet(response_packet).encode())

        # Wait for the nonce response to verify it matches the one sent
        try:
            nonce_response = peer_socket.recv(8192)
        except socket.timeout:
            return None
        
        if not nonce_response:
            return None

        try:
            # Decrypt the nonce response
            nonce_response_packet = Handshake.Packet.decode_packet(nonce_response.decode())
            nonce_response_message = nonce_response_packet.messages[0]
            decrypted_nonce = Handshake.decrypt_data(base64.b64decode(nonce_response_message.data), shared_key, base64.b64decode(nonce_response_message.iv))

        except Exception as e:
            return None
            
        # Verify the nonce
        if decrypted_nonce == nonce:
            return shared_key
        else:
            return None
        

    @staticmethod
    def accept_handshake(initial_message, peer_socket, password):
        """
        The accept handshake function is used to accept a handshake request from another peer.

        If there are padding or other errors decrypted and parsing the recieved data,
        default values for the incoming sender's public key and challenge response
        are used, so the handshake can continue.

        This is in case of a peer sending invalid data or if the data is tampered with,
        or using an old, compromised password-derived key.
        
        """
        # Receive the initial message containing the sender's public key

        if not initial_message:
            return None
        
        try:
            # Get the sender's public key
            received_packet = Handshake.Packet.decode_packet(initial_message.decode())
            received_message = received_packet.messages[0]
            sender_public_key_bytes = Handshake.decrypt_data(base64.b64decode(received_message.data), password, base64.b64decode(received_message.iv))
            sender_public_key = Handshake.load_public_key_from_bytes(sender_public_key_bytes)

        except Exception as e:
            return None
            
        # Generate this peer's key pair and derive the shared key
        private_key, public_key = Handshake.generate_ecdh_key_pair()

        shared_key = private_key.exchange(ec.ECDH(), sender_public_key)
        
        # Encrypt the public key to send back to the initiator
        encrypted_public_key, iv = Handshake.encrypt_data(public_key, password)

        # Generate a challenge to send back to the initiator
        nonce, challenge_message = Handshake.generate_challenge(shared_key)
        
        # Prepare and send both the encrypted public key and the challenge in one packet
        message1 = Handshake.Message(encrypted_public_key, iv)
        packet = Handshake.Packet([message1, challenge_message])
        peer_socket.send(Handshake.Packet.encode_packet(packet).encode())

        # Wait for the response to the challenge
        try:
            response_data = peer_socket.recv(8192)
        except socket.timeout:
            return None
        
        if not response_data:
            return None

        try:
            response_packet = Handshake.Packet.decode_packet(response_data.decode())
            response_message = response_packet.messages[0]

            # Verify the challenge
            verified, result_message = Handshake.verify_challenge_accept(response_message, shared_key, nonce)
            peer_socket.send(Handshake.Packet.encode_packet(Handshake.Packet([result_message])).encode())

        except Exception as e:
            return None
        
        if verified:
            return shared_key
        else:
            return None