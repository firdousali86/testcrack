from cryptography.fernet import Fernet, InvalidToken
import hashlib
import base64
import itertools
import string
import time

# List of Fernet tokens to decrypt
tokens = [
    b"gAAAAABn-Rna9RMvxaZX4Qfyo1eH4i73yTllL7HMC6NVeoCfgCPsjp4NbKZZgVaPmMH9B4-S5RYkCS4Rr5LPiseVmPTwc8LJOg==",
    b"gAAAAABn-Rna0ZE47CITq2HzrbIwGY7y08_NlqaIV0zq33NGeCNIoPvD7Rs0k8CFj9ah1ZDJZbu8gWg0o8KbJF_ganxRnU1cag=="
]

# Function to derive a Fernet key from a password
def derive_key(password):
    sha256_hash = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(sha256_hash)

# Brute-force generator with dynamic character set
def brute_force(max_length, chars):
    total_combinations = sum(len(chars) ** i for i in range(1, max_length + 1))
    print(f"[INFO] Starting brute-force attack with max length {max_length}.")
    print(f"[INFO] Total combinations to test: {total_combinations}")
    
    tested_count = 0
    start_time = time.time()
    
    for length in range(1, max_length + 1):
        print(f"[INFO] Testing passwords of length {length}...")
        for candidate in itertools.product(chars, repeat=length):
            password = ''.join(candidate)
            tested_count += 1
            
            # Log progress periodically
            if tested_count % 1000 == 0:
                elapsed_time = time.time() - start_time
                speed = tested_count / elapsed_time if elapsed_time > 0 else 0
                print(f"[PROGRESS] Tested {tested_count}/{total_combinations} passwords "
                      f"({tested_count / total_combinations * 100:.2f}%) | Speed: {speed:.2f} passwords/sec")
            
            yield password
    
    print("[INFO] Brute-force attack completed.")

# Function to attempt decryption
def attempt_decryption():
    # Ask user for configuration
    include_uppercase = input("Include uppercase letters (A-Z)? (y/n): ").strip().lower() == "y"
    include_lowercase = input("Include lowercase letters (a-z)? (y/n): ").strip().lower() == "y"
    include_digits = input("Include digits (0-9)? (y/n): ").strip().lower() == "y"
    include_special = input("Include special characters (!@#$%^&*, etc.)? (y/n): ").strip().lower() == "y"
    max_length = int(input("Enter maximum password length to test: "))
    log_passwords = input("Log passwords during the process? (y/n): ").strip().lower() == "y"
    log_to_file = False
    log_filename = None
    if log_passwords:
        log_to_file = input("Log passwords to a file instead of console? (y/n): ").strip().lower() == "y"
        if log_to_file:
            log_filename = input("Enter the log file name (e.g., log.txt): ").strip()
            open(log_filename, "w").close()  # Clear the file if it exists
    
    # Build the character set based on user input
    chars = ""
    if include_uppercase:
        chars += string.ascii_uppercase
    if include_lowercase:
        chars += string.ascii_lowercase
    if include_digits:
        chars += string.digits
    if include_special:
        chars += string.punctuation
    
    if not chars:
        print("[ERROR] No character set selected. Exiting.")
        return
    
    print(f"[INFO] Character set: {chars}")
    
    # Attempt decryption
    tested_count = 0
    for password in brute_force(max_length, chars):
        key = derive_key(password)
        cipher_suite = Fernet(key)
        
        success = True
        for token in tokens:
            try:
                decrypted_data = cipher_suite.decrypt(token)
                print(f"\n[SUCCESS] Password found: {password}")
                print(f"[SUCCESS] Decrypted data: {decrypted_data.decode('utf-8')}")
                print(f"[SUCCESS] Key: {key.decode('utf-8')}")
                return
            except InvalidToken:
                success = False
                break
        
        if success:
            break
        
        # Log passwords every 1000th iteration
        tested_count += 1
        if log_passwords and (tested_count % 1000 == 0):
            if log_to_file:
                try:
                    with open(log_filename, "a") as f:
                        f.write(f"{password}\n")
                except Exception as e:
                    print(f"[ERROR] Failed to write to log file: {e}")
            else:
                print(f"[LOG] Password: {password}")
    
    else:
        print("\n[FAILURE] Failed to crack the key with brute force.")

# Run the decryption attempt
if __name__ == "__main__":
    attempt_decryption()