import pickle
import socket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generate_keypair():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def generate_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    return shared_key


def encrypt_message(key, message):
    iv = b'\x00' * 16  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext


def decrypt_message(ciphertext, key):
    iv = b'\x00' * 16  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext


def generate_symmetric_key(shared_key):
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'symmetric key generation',
        backend=default_backend()
    )
    return kdf.derive(shared_key)


# Client setup
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 8000)
client_socket.connect(server_address)

# Receive server's public key
server_public_key = pickle.loads(client_socket.recv(1024))

# Generate client's keypair
private_key_client, public_key_client = generate_keypair()

# Send client's public key to the server
client_socket.sendall(pickle.dumps(public_key_client))

# Generate shared key
shared_key_client = generate_shared_key(private_key_client, server_public_key)

while True:
    # Prompt user to enter message
    message = input("Enter message: ")

    # Send message to server
    shared_symmetric_key = generate_symmetric_key(shared_key_client)
    encrypted_message = encrypt_message(shared_symmetric_key)
    client_socket.sendall(encrypted_message)

    # Receive response from server
    encrypted_response = client_socket.recv(1024)
    if not encrypted_response:
        break

    # Decrypt and print response
    decrypted_response = decrypt_message(encrypted_response, shared_symmetric_key)
    print("Received response from server:", decrypted_response.decode())

# Close connection
client_socket.close()
