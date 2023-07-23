from stegano import lsb
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64

"""This is a test environment dummy key grabbed from a demo website on AES for testing purposes only! 
Do not use hard coded keys in production environments!
For CLI program run SteggoCLI.py"""
key = "770A8A65DA156D24EE2A093277530142"

def aes_encrypt(message, key):
    cipher = AES.new(hashlib.sha256(key.encode()).digest(), AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')

def aes_decrypt(ciphertext, key):
    ct = base64.b64decode(ciphertext.encode('utf-8'))
    cipher = AES.new(hashlib.sha256(key.encode()).digest(), AES.MODE_CBC, iv=ct[:16])
    plaintext = unpad(cipher.decrypt(ct[16:]), AES.block_size)
    return plaintext.decode()

def encode(image_name, secret_data, key):
    secret_data = aes_encrypt(secret_data, key)
    secret_image = lsb.hide(image_name, secret_data)
    secret_image.save(image_name.split(".")[0] + "_encoded.png")

def decode(image_name, key):
    secret_data = lsb.reveal(image_name)
    decoded_data = aes_decrypt(secret_data, key)
    print(decoded_data)
    return decoded_data

# encode("test.png", "shhhh secret", key)
# decode("test_encoded.png", key)