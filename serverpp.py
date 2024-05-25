import os
import socket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generate_key():
    # Generate a random 256-bit key
    return os.urandom(32)


def encrypt_message(key, plaintext):
    # Pad the plaintext
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    # Generate an initialization vector
    iv = os.urandom(16)

    # Create a cipher object and encrypt the plaintext
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return iv + ciphertext


def decrypt_message(key, ciphertext):
    # Extract the initialization vector and ciphertext
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    # Create a cipher object and decrypt the ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data.decode('utf-8')

# Generate server key
server_key = generate_key()

# Create a TCP/IP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the address and port
server_address = ('localhost', 8000)
server_socket.bind(server_address)

# Listen for incoming connections
server_socket.listen(2)

print("Waiting for a connection...")

while True:
    # Accept incoming connection
    client_socket, client_address = server_socket.accept()
    print("Connection established with:", client_address)

    try:
        while True:
            # Receive message from client
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break

            # Decrypt message
            decrypted_message = decrypt_message(server_key, encrypted_message)
            print("Decrypted message:", decrypted_message)

    finally:
        # Clean up the connection
        client_socket.close()
