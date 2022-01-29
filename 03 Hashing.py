# Hashing
# Hashing is used for generating a fixed sized string for input data of any size
# We are using SHA256 hash function


# Importing Libraries/Modules
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import constant_time
import binascii


# Class for Hashing
class Hash():
    def hash_bytes(self, bytes_data):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(bytes_data)
        hash_bytes = digest.finalize()
        return hash_bytes

    def verify_bytes(self, bytes_data, verify_bytes):
        hash_bytes = self.hash_bytes(bytes_data)
        result = constant_time.bytes_eq(hash_bytes, verify_bytes)
        return result

    def hash_string(self, string_data):
        bytes_data = string_data.encode()
        hash_hex = self.hash_bytes(bytes_data)
        return hash_hex

    def verify_string(self, string_data, verify_bytes):
        bytes_data = string_data.encode()
        result = self.verify_bytes(bytes_data, verify_bytes)
        return result

    def __file_chunks(self, file_object, chunk_size=65536):
        while True:
            data_chunk = file_object.read(chunk_size)
            if not data_chunk:
                break
            yield data_chunk

    def hash_file(self, file_path):
        digest = hashes.Hash(hashes.SHA256())
        with open(file_path, "rb") as hash_file:
            for data_chunk in self.__file_chunks(hash_file):
                digest.update(data_chunk)
        hash_bytes = digest.finalize()
        return hash_bytes

    def verify_file(self, file_path, verify_bytes):
        hash_bytes = self.hash_file(file_path)
        result = constant_time.bytes_eq(hash_bytes, verify_bytes)
        return result

    def bytes_to_hex(self, hash_bytes):
        hash_hex = binascii.b2a_hex(hash_bytes)
        hash_hex = hash_hex.decode()
        return hash_hex

    def hex_to_bytes(self, hash_hex):
        hash_hex = hash_hex.encode()
        hash_bytes = binascii.a2b_hex(hash_hex)
        return hash_bytes


# Hashing
print("Hashing:")

# Creating Object
hasher = Hash()

# Hashing Bytes
bytes_data = b"The quick brown fox jumps over the lazy dog"
hash_bytes = hasher.hash_bytes(bytes_data)
hash_hex = hasher.bytes_to_hex(hash_bytes)
print(hash_hex)

# Verifying Hash
result = hasher.verify_bytes(bytes_data, hash_bytes)
print(result)

bytes_data = b"The pagal brown fox jumps over the lazy dog"
result = hasher.verify_bytes(bytes_data, hash_bytes)
print(result)

# Hashing String
string_data = "The quick brown fox jumps over the lazy dog"
hash_bytes = hasher.hash_string(string_data)
hash_hex = hasher.bytes_to_hex(hash_bytes)
print(hash_hex)

# Verifying Hash
result = hasher.verify_string(string_data, hash_bytes)
print(result)

string_data = "The pagal brown fox jumps over the lazy dog"
result = hasher.verify_string(string_data, hash_bytes)
print(result)

# Creating a Sample File
sample_file_path = "Sample File.txt"
with open(sample_file_path, "w") as file:
    file.write("The quick brown fox jumps over the lazy dog")

malicious_file_path = "Altered File.txt"
with open(malicious_file_path, "w") as file:
    file.write("The pagal brown fox jumps over the lazy dog")

# Hashing File
hash_bytes = hasher.hash_file(sample_file_path)
hash_hex = hasher.bytes_to_hex(hash_bytes)
print(hash_hex)

# Verifying Hash
result = hasher.verify_file(sample_file_path, hash_bytes)
print(result)

result = hasher.verify_file(malicious_file_path, hash_bytes)
print(result)
