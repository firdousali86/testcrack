from cryptography.fernet import Fernet, InvalidToken
import hashlib
import base64
import itertools
import string

# List of Fernet tokens to decrypt
tokens = [
    b"gAAAAABn-Rna9RMvxaZX4Qfyo1eH4i73yTllL7HMC6NVeoCfgCPsjp4NbKZZgVaPmMH9B4-S5RYkCS4Rr5LPiseVmPTwc8LJOg==",
    b"gAAAAABn-Rna0ZE47CITq2HzrbIwGY7y08_NlqaIV0zq33NGeCNIoPvD7Rs0k8CFj9ah1ZDJZbu8gWg0o8KbJF_ganxRnU1cag=="
]

# Function to derive a Fernet key from a password
def derive_key(password):
    sha256_hash = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(sha256_hash)

# Generate all possible combinations of characters
def brute_force(max_length):
    chars = string.ascii_letters + string.digits + string.punctuation
    for length in range(1, max_length + 1):
        for candidate in itertools.product(chars, repeat=length):
            yield ''.join(candidate)

# Try each candidate password
for password in brute_force(max_length=6):  # Adjust max_length as needed
    key = derive_key(password)
    cipher_suite = Fernet(key)
    
    success = True
    for token in tokens:
        try:
            decrypted_data = cipher_suite.decrypt(token)
            print(f"Success! Password: {password}")
            print(f"Decrypted: {decrypted_data.decode('utf-8')}")
        except InvalidToken:
            success = False
            break
    
    if success:
        print(f"Key cracked: {key.decode('utf-8')}")
        break
else:
    print("Failed to crack the key with brute force.")