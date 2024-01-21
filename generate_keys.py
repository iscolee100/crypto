from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_key_pair(username):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Generate public key
    public_key = private_key.public_key()

    # Save private key to a file
    private_key_filename = f"{username}_private_key.pem"
    with open(private_key_filename, "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save public key to a file
    public_key_filename = f"{username}_public_key.pem"
    with open(public_key_filename, "wb") as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        print(f"Keys generated for {username}")

    return public_key, private_key

# Generate key pairs for two users
generate_rsa_key_pair("user1")
generate_rsa_key_pair("user2")
