from cryptography.fernet import Fernet

def generate_key():
    """Returns a new random secure key as a string."""
    return Fernet.generate_key().decode()

def encrypt_text(message: str, key: str):
    """Encrypts text using the provided key."""
    try:
        f = Fernet(key.encode())
        return f.encrypt(message.encode()).decode()
    except Exception as e:
        print(f"Encryption Error: {e}") # Print error to terminal for debugging
        return None

def decrypt_text(encrypted_message: str, key: str):
    """Decrypts text using the provided key."""
    try:
        f = Fernet(key.encode())
        return f.decrypt(encrypted_message.encode()).decode()
    except Exception as e:
        print(f"Decryption Error: {e}") # Print error to terminal for debugging
        return None