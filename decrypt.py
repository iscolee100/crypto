from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def load_private_key(filename):
    with open(filename, "rb") as key_file:
        private_key_data = key_file.read()
        return serialization.load_pem_private_key(private_key_data, password=None)

def load_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key_data = key_file.read()
        return serialization.load_pem_public_key(public_key_data)

def decrypt_message(private_key, encrypted_message):
    return private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# Users involved 
sender = "user2"
receiver = "user1"

# Load the receiver's private key and sender's public key
receiver_private_key = load_private_key(f"{receiver}_private_key.pem")
sender_public_key = load_public_key(f"{sender}_public_key.pem")

# Load the encrypted message
with open("encrypted_message.enc", "rb") as f:
    encrypted_message = f.read()

# Decrypt the message
decrypted_message = decrypt_message(receiver_private_key, encrypted_message)

# Load the signature
with open(f"{sender}_signature.sig", "rb") as sig_file:
    signature = sig_file.read()

# Verify the signature using sender's public key
is_valid = verify_signature(sender_public_key, decrypted_message, signature)
print(f"Signature valid: {is_valid}")

# Save the decrypted message
with open("decrypted_message.dec", "wb") as decrypted_message_file:
    decrypted_message_file.write(decrypted_message)
    print('Message decrypted')
