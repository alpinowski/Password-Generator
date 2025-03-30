import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def load_key():
    with open("key.key", "rb") as file:
        key = file.read()
    return key

master_pwd = input("What is the master password? ")

# Anahtar türetme fonksiyonu
def derive_key(master_pwd, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet anahtarı 32 bayt olmalı
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))

# Salt olarak "key.key" dosyasındaki değeri kullanıyoruz
salt = load_key()
key = derive_key(master_pwd, salt)
fer = Fernet(key)

def view():
    try:
        with open("passwords.txt", "r") as f:
            for line in f.readlines():
                data = line.rstrip()
                user, passw = data.split("|")
                decrypted_pass = fer.decrypt(passw.encode()).decode()
                print(f"Account: {user}, Password: {decrypted_pass}")
    except FileNotFoundError:
        print("No saved passwords found.")
    except Exception as e:
        print("Error decrypting passwords:", str(e))

def add():
    name = input("Account Name: ")
    pwd = input("Password: ")
    encrypted_pwd = fer.encrypt(pwd.encode()).decode()

    with open("passwords.txt", "a") as f:
        f.write(name + "|" + encrypted_pwd + "\n")

while True:
    mode = input("Would you like to add a new password or view an existing one? (view/add), press q to quit: ").lower()
    if mode == "q":
        break

    if mode == "view":
        view()
    elif mode == "add":
        add()
    else:
        print("Invalid mode.")
        continue
