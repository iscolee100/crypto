from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

def load_private_key(filename):
    with open(filename, "rb") as key_file:
        private_key_data = key_file.read()
        private_key = serialization.load_pem_private_key(
            private_key_data, password=None)
    return private_key

def load_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key_data = key_file.read()
        public_key = serialization.load_pem_public_key(public_key_data)
    return public_key

def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def encrypt_message(public_key, message):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print('Message encrypted')
    return ciphertext

# Read the original message from a file
with open("message.txt", "rb") as f:
    original_message = f.read()

# Users involved 
sender = "user2"
receiver = "user1"

# Load the sender's private key and receiver's public key
sender_private_key = load_private_key(f"{sender}_private_key.pem")
receiver_public_key = load_public_key(f"{receiver}_public_key.pem")

# Encrypt the message with the receiver's public key
encrypted_message = encrypt_message(receiver_public_key, original_message)

# Sign the original message with the sender's private key
signature = sign_message(sender_private_key, original_message)

# Save the encrypted message and the signature
with open("encrypted_message.enc", "wb") as encrypted_message_file:
    encrypted_message_file.write(encrypted_message)

with open(f"{sender}_signature.sig", "wb") as signature_file:
    signature_file.write(signature)

print("Encrypted message and signature saved.")

