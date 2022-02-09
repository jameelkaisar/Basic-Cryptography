# Authentication Codes
# Authentication codes are used for Two-Factor Authentication (2FA)
# We are using TOTP (time-based) and HOTP (count-based) authentication codes


# Importing Libraries/Modules
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor import InvalidToken
import time
import os


# Class for Generating Time-Based Authentication Codes
class TOTP_2FA():
    def __init__(self):
        key = os.urandom(20)
        self.totp = TOTP(key, 6, SHA1(), 30)

    def generate(self, time_value=None):
        if time_value is None:
            time_value = time.time()
        otp = self.totp.generate(time_value)
        otp = otp.decode()
        return otp

    def verify(self, otp, time_value=None):
        otp = otp.encode()
        if time_value is None:
            time_value = time.time()
        try:
            self.totp.verify(otp, time_value)
        except InvalidToken:
            return False
        return True

    def get_uri(self, user, issuer):
        totp_uri = self.totp.get_provisioning_uri(user, issuer)
        return totp_uri


# Class for Generating Count-Based Authentication Codes
class HOTP_2FA():
    def __init__(self):
        key = os.urandom(20)
        self.hotp = HOTP(key, 6, SHA1())
        self.count = 0

    def generate(self, count=None):
        if count is None:
            count_value = self.count
            self.count += 1
        else:
            count_value = count
        otp = self.hotp.generate(count_value)
        otp = otp.decode()
        return otp

    def verify(self, otp, count):
        otp = otp.encode()
        count_value = count
        try:
            self.hotp.verify(otp, count_value)
        except InvalidToken:
            return False
        return True

    def get_uri(self, user, issuer, count=0):
        hotp_uri = self.hotp.get_provisioning_uri(user, count, issuer)
        return hotp_uri

    def get_count(self):
        return self.count


# TOTP
print("TOTP:")

# Creating Object
totp = TOTP_2FA()

# Generating OTP
time_value = time.time()
otp = totp.generate(time_value)
print(otp)

# Verifying OTP
verify = totp.verify(otp, time_value)
print(verify)
verify = totp.verify(otp, time_value+100)
print(verify)

# Generating Provisioning URI
uri = totp.get_uri("User", "Issuer")
print(uri)


# HOTP
print("HOTP:")

# Creating Object
hotp = HOTP_2FA()

# Generating OTP
count = 1
otp = hotp.generate(count)
print(otp)

# Verifying OTP
verify = hotp.verify(otp, count)
print(verify)
verify = hotp.verify(otp, count+100)
print(verify)

# Generating Provisioning URI
uri = hotp.get_uri("User", "Issuer")
print(uri)
