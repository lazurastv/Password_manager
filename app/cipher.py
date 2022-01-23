from sqlite import dao
from bcrypt import checkpw, hashpw, gensalt
from base64 import b64encode, b64decode
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import choice
from Crypto.Protocol.KDF import scrypt

WORK_FACTOR = 14

def generate_nonce():
	return get_random_bytes(8)
	
def generate_session_id():
	return b64encode(get_random_bytes(16)).decode()

def password_correct(username, password):
	text_hash = dao.get_hash(username)
	return hashes_match(password, text_hash)

def master_key_correct(username, key):
	text_hash = dao.get_master_hash(username)
	return hashes_match(key, text_hash)

def hashes_match(password, text_hash):
	if text_hash is None: return False
	encoded_password = parse_password(password)
	hashed = text_hash.encode()
	return checkpw(encoded_password, hashed)

def xor32(b1, b2):
	return bytes(a ^ b for a, b in zip(b1, b2))

def derive_key(username, master_password):
	salt = get_random_bytes(16)
	key = scrypt_kdf(master_password, salt)
	return key, salt

def derive_key_with_nonce(username, master):
	salt = dao.get_master_salt(username)
	key = scrypt_kdf(master, salt)
	nonce = get_random_bytes(32)
	key = xor32(key, nonce)
	return key, nonce

def scrypt_kdf(password, salt):
	return scrypt(parse_password(password), salt, 32, 2**WORK_FACTOR, 8, 1)

def pad_text(text):
	remainder = len(text) % 16
	if remainder != 0:
		text += '\0' * (16 - remainder)
	return text

def unpad_text(text):
	return text.strip('\x00')

def encrypt(value, key, iv=bytes(8), start=0):
	aes = AES.new(key, AES.MODE_CTR, nonce=iv, initial_value=start)
	encrypted = aes.encrypt(value)
	return encrypted

def decrypt_key(sid, nonce):
	nonce = b64decode(nonce)
	key = dao.get_encrypted_key(sid)
	return xor32(key, nonce)

def parse_password(password):
	try:
		pass_encoded = password.encode()
	except AttributeError:
		pass_encoded = password
	pass_hashed = SHA256.new(pass_encoded).digest()
	return b64encode(pass_hashed)

def hash_password(password):
	encoded_pass = parse_password(password)
	salt = gensalt(rounds=WORK_FACTOR)
	hashed = hashpw(encoded_pass, salt)
	return hashed.decode()

def weak_password(password):
	return password.isupper() or password.islower() or password.isalnum() or 8 > len(password)

