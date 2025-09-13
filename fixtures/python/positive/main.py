from cryptography.fernet import Fernet

def main():
    key = Fernet.generate_key()
    f = Fernet(key)
    print(f)

