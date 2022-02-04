# Signing
# Signing is used for verifying the authenticity of digital data
# Ed25519 is based on Curve25519 using EdDSA


# Importing Libraries/Modules
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


# Class for Operations on Private Key
class Private():
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def load_key(self, file_path, password=None):
        with open(file_path, "rb") as key_file:
            pem = key_file.read()
        self.private_key = serialization.load_pem_private_key(
            pem,
            password=password
        )
        self.public_key = self.private_key.public_key()

    def save_private_key(self, file_path, password=None):
        if password:
            pem = self.private_key.private_bytes(
               encoding=serialization.Encoding.PEM,
               format=serialization.PrivateFormat.PKCS8,
               encryption_algorithm=serialization.BestAvailableEncryption(password)
            )
        else:
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        with open(file_path, "wb") as key_file:
            key_file.write(pem)

    def save_public_key(self, file_path):
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(file_path, "wb") as key_file:
            key_file.write(pem)

    def sign_bytes(self, bytes_data):
        signature = self.private_key.sign(bytes_data)
        return signature

    def sign_string(self, string_data):
        bytes_data = string_data.encode()
        signature = self.sign_bytes(bytes_data)
        return signature

    def get_public_key(self):
        return self.public_key


# Class for Operations on Public Key
class Public():
    def __init__(self):
        self.public_key = None

    def key(self, public_key):
        self.public_key = public_key

    def load_key(self, file_path):
        with open(file_path, "rb") as key_file:
            pem = key_file.read()
        self.public_key = serialization.load_pem_public_key(
            pem
        )

    def verify_bytes(self, bytes_data, signature):
        try:
            self.public_key.verify(signature, bytes_data)
        except InvalidSignature:
            return False
        return True

    def verify_string(self, string_data, signature):
        bytes_data = string_data.encode()
        result = self.verify_bytes(bytes_data, signature)
        return result


# Signing
print("Signing:")

# Creating Objects
private = Private()
public = Public()

# Setting Keys
private.generate()
public_key = private.get_public_key()
public.key(public_key)

# Saving Keys
password = b"My Name is Khan"
private.save_private_key("Private Key (with password).pem", password)
private.save_private_key("Private Key (without password).pem")
private.save_public_key("Public Key.pub")

# Signing Bytes
bytes_data = b"The quick brown fox jumps over the lazy dog"
signature = private.sign_bytes(bytes_data)

result = public.verify_bytes(bytes_data, signature)
print(result)

signature = b"Altered Signature"
result = public.verify_bytes(bytes_data, signature)
print(result)

# Signing Strings
string_data = "The quick brown fox jumps over the lazy dog"
signature = private.sign_string(string_data)

result = public.verify_string(string_data, signature)
print(result)

signature = b"Altered Signature"
result = public.verify_string(string_data, signature)
print(result)

# Loading Private Key (with password)
private = Private()
file_path = "Private Key (with password).pem"
password = b"My Name is Khan"
private.load_key(file_path, password)

# Loading Private Key (without password)
private = Private()
file_path = "Private Key (without password).pem"
private.load_key(file_path)

# Loading Public Key
public = Public()
file_path = "Public Key.pub"
public.load_key(file_path)
