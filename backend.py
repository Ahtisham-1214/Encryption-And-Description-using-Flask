def encrypt(file_path):
    with open(file_path, 'r') as file:
        text = file.read()
        text = ''.join(chr(ord(char) + 1) for char in text)
    with open(file_path, 'w') as file:
        file.write(text)
        return True
    return False

def decrypt(file_path):
    with open(file_path, 'r') as file:
        text = file.read()
        text = ''.join(chr(ord(char) - 1) for char in text)
    with open(file_path, 'w') as file:
        file.write(text)
        return True
    return False