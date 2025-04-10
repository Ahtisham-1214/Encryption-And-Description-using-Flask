import random

def encrypt(file_path):
    key = random.randint(1, 100)
    with open(file_path, 'r') as file:
        text = file.read()
        text = ''.join(
            chr(((ord(char) - 32 + key) % 95) + 32) if 32 <= ord(char) <= 126 else char
            for char in text
        )
    with open(file_path, 'w') as file:
        file.write(text)
        return True, key
    return False

def decrypt(file_path, key):
    with open(file_path, 'r') as file:
        text = file.read()
        text = ''.join(
            chr(((ord(char) - 32 - key) % 95) + 32) if 32 <= ord(char) <= 126 else char
            for char in text
        )
    with open(file_path, 'w') as file:
        file.write(text)
        return True
    return False