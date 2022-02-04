# Asymmetric Cryptography
# Asymmetric cryptography is a type of cryptography in which a pair of private and public keys is used instead of a single key
# We are using RSA for Asymmetric Cryptography
# Signing and Asymmetric Encryption

# Recommendation: Use Ed25519 for Signing


# Importing Libraries/Modules
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature


# Class for Operations on Private Key
class Private():
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
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
        signature = self.private_key.sign(
            bytes_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def sign_string(self, string_data):
        bytes_data = string_data.encode()
        signature = self.sign_bytes(bytes_data)
        return signature

    def __file_chunks(self, file_object, chunk_size=65536):
        while True:
            data_chunk = file_object.read(chunk_size)
            if not data_chunk:
                break
            yield data_chunk

    def sign_file(self, file_path):
        digest = hashes.Hash(hashes.SHA256())
        with open(file_path, "rb") as hash_file:
            for data_chunk in self.__file_chunks(hash_file):
                digest.update(data_chunk)
        hash_bytes = digest.finalize()
        signature = self.private_key.sign(
            hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return signature

    def decrypt(self, bytes_data):
        plaintext = self.private_key.decrypt(
            bytes_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

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
            self.public_key.verify(
                signature,
                bytes_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            return False
        return True

    def verify_string(self, string_data, signature):
        bytes_data = string_data.encode()
        result = self.verify_bytes(bytes_data, signature)
        return result

    def __file_chunks(self, file_object, chunk_size=65536):
        while True:
            data_chunk = file_object.read(chunk_size)
            if not data_chunk:
                break
            yield data_chunk

    def verify_file(self, file_path, signature):
        digest = hashes.Hash(hashes.SHA256())
        with open(file_path, "rb") as hash_file:
            for data_chunk in self.__file_chunks(hash_file):
                digest.update(data_chunk)
        hash_bytes = digest.finalize()
        try:
            self.public_key.verify(
                signature,
                hash_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                utils.Prehashed(hashes.SHA256())
            )
        except InvalidSignature:
            return False
        return True

    def encrypt(self, bytes_data):
        ciphertext = self.public_key.encrypt(
            bytes_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext


# Asymmetric Cryptography
print("Asymmetric Cryptography:")

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

# Creating a Sample File
file_path = "Sample File.txt"
with open(file_path, "w") as file:
    file.write("The quick brown fox jumps over the lazy dog")

# Signing Files
signature = private.sign_file(file_path)

result = public.verify_file(file_path, signature)
print(result)

signature = b"Altered Signature"
result = public.verify_file(file_path, signature)
print(result)

# Encrypting Data
bytes_data = b"The quick brown fox jumps over the lazy dog"
ciphertext = public.encrypt(bytes_data)

# Decrypting Data
plaintext = private.decrypt(ciphertext)
print(plaintext)

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
