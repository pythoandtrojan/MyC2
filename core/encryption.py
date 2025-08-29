import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

class EncryptionHandler:
    def __init__(self, key=None):
        if key:
            self.key = hashlib.sha256(key.encode()).digest()
        else:
            self.key = None
    
    def encrypt(self, data):
        if not self.key:
            return data
            
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        encrypted = cipher.encrypt(data.encode())
        return base64.b64encode(iv + encrypted).decode()
    
    def decrypt(self, data):
        if not self.key:
            return data
            
        try:
            raw = base64.b64decode(data)
            iv = raw[:16]
            cipher = AES.new(self.key, AES.MODE_CFB, iv)
            return cipher.decrypt(raw[16:]).decode()
        except:
            return data
