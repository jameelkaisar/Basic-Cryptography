# Constant Time Functions
# Constant Time Functions are used for countering side-channel timing attacks
# constant_time.bytes_eq() internally calls hmac.compare_digest()


# Importing Libraries/Modules
from cryptography.hazmat.primitives import constant_time
import time
import os


# Class for Constant Time Function
class Constant():
    def compare(self, bytes_data_1, bytes_data_2):
        result = constant_time.bytes_eq(bytes_data_1, bytes_data_2)
        return result


# Constant Time Functions
print("Constant Time Functions:")

# Creating Object
constant = Constant()

# Test 1
bytes_data_1 = b"My name is Khan"
bytes_data_2 = b"My name is Khan"
result = constant.compare(bytes_data_1, bytes_data_2)
print(result)

# Test 2
bytes_data_1 = b"My name is Khan"
bytes_data_2 = b"My name is Ajmi"
result = constant.compare(bytes_data_1, bytes_data_2)
print(result)

# Test 3 (Bulk)
total_time = 0
for _ in range(100000):
    bytes_data = os.urandom(15000)
    start_time = time.time()
    constant.compare(bytes_data, bytes_data)
    time_taken = time.time() - start_time
    total_time += time_taken
print(total_time)

# Test 4 (Bulk)
total_time = 0
for _ in range(100000):
    bytes_data_1 = os.urandom(15000)
    bytes_data_2 = os.urandom(15000)
    start_time = time.time()
    constant.compare(bytes_data_1, bytes_data_2)
    time_taken = time.time() - start_time
    total_time += time_taken
print(total_time)
