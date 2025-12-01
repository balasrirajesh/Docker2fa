from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair(key_size: int = 4096):
    """
    Generate RSA key pair
    
    Returns:
        Tuple of (private_key, public_key) objects
    
    Implementation:
    - Use your language's crypto library to generate 4096-bit RSA key
    - Set public exponent to 65537
    - Serialize to PEM format
    - Return key objects for further use
    """
    # Generate the private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    # Get the public key from the private key
    public_key = private_key.public_key()

    return private_key, public_key

def save_keys_to_files(private_key, public_key):
    # Serialize private key to PEM format (No encryption for automation/Docker context)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key to PEM format
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save to files
    with open("student_private.pem", "wb") as f:
        f.write(pem_private)
    
    with open("student_public.pem", "wb") as f:
        f.write(pem_public)

    print("Keys generated and saved successfully:")
    print(" - student_private.pem")
    print(" - student_public.pem")

if __name__ == "__main__":
    # execute generation
    priv, pub = generate_rsa_keypair()
    # execute saving
    save_keys_to_files(priv, pub)