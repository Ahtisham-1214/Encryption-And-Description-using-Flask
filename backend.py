import random
import os
import datetime

def encrypt(file_path):
    key = random.randint(1000, 100000) # Generate a random key
    file_extension = os.path.splitext(file_path)[1].lower()

    if file_extension in [".txt", ".htm", ".html", ".py", ".csv", ".json"]:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            text = file.read()
            if text.startswith("ENCRYPTED:"):  # Check if already encrypted
                return False, "File is already encrypted."
            text = ''.join(
                chr(((ord(char) - 32 + key) % 95) + 32) if 32 <= ord(char) <= 126 else char
                for char in text
            )
        with open(file_path, 'w', encoding='utf-8', errors='ignore') as file:
            file.write(f"ENCRYPTED:{key}:{text}")  # append the key and marker to the encrypted text
            log(file_path, "Encrypted")
        return True, key

    else:
        return False, "Unsupported file type."

def decrypt(file_path, key):
    file_extension = os.path.splitext(file_path)[1].lower()

    if file_extension in [".txt", ".htm", ".html", ".py", ".csv", ".json"]:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            text = file.read()
            if not text.startswith("ENCRYPTED:"):  # Check if not encrypted
                return False, "File is not encrypted."
   
            # Extract the key and encrypted text
            try:
                marker, stored_key, encrypted_text = text.split(":", 2)
                stored_key = int(stored_key)
            except ValueError:
                return False, "Invalid file format."

            if stored_key != key:  # Check if the provided key matches the stored key
                return False, "Incorrect decryption key."

            # Decrypt the text
            decrypted_text = ''.join(
                chr(((ord(char) - 32 - key) % 95) + 32) if 32 <= ord(char) <= 126 else char
                for char in encrypted_text
            )
        with open(file_path, 'w', encoding='utf-8', errors='ignore') as file:
            file.write(decrypted_text)
            log(file_path, "Decrypted")
        return True, "File decrypted successfully."

    else:
        return False, "Unsupported file type."

def log(file_path, status):
    with open("log_file.txt", "a") as log_file:
        log_file.write(f"{file_path}\t\t")
        log_file.write(f"{datetime.datetime.now()}\t\t")
        log_file.write(f"{status}\n")