from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from base64 import b64encode, b64decode
import random
import string
import hashlib
import time
from django.http import JsonResponse  # Django의 JsonResponse 가져오기


class RSAEncryption:
    def __init__(self, phrase: str):
        self.phrase = phrase
        self.private_key = None
        self.public_key = None

    def generate_key_pair(self):
        """개인키와 공개키 생성 후 반환"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def get_private_key_strings(self):
        """키 페어를 PEM 형식의 문자열로 반환"""
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_pem.decode('utf-8')

    def get_public_key_strings(self):
        """키 페어를 PEM 형식의 문자열로 반환"""
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_pem.decode('utf-8')

    def encrypt(self, message: str):
        """공개키로 메시지 암호화 후 반환"""
        encrypted = self.public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return b64encode(encrypted).decode('utf-8')

    def decrypt(self, encrypted_message: str):
        """개인키로 메시지 복호화 후 반환"""
        decoded = b64decode(encrypted_message)
        decrypted = self.private_key.decrypt(
            decoded,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode('utf-8')

    def generate_hash_key(self, length=16):
        """주어진 길이의 해시 키를 반환"""
        timestamp = str(int(time.time() * 1000))
        base = self.phrase + timestamp
        hash_base = hashlib.sha256(base.encode()).hexdigest()

        chars = string.ascii_letters + string.digits
        must_have = [
            random.choice(string.ascii_uppercase),
            random.choice(string.ascii_lowercase),
            random.choice(string.digits)
        ]
        remaining_length = length - len(must_have)
        random_chars = [random.choice(chars) for _ in range(remaining_length)]
        all_chars = must_have + random_chars
        random.shuffle(all_chars)
        hash_key = ''.join(all_chars)

        return hash_key
