from cipher import *
from utils import *
from sqlite import dao
from datetime import datetime, timedelta

def add_user(username, email, password, master):
	key, salt = derive_key(username, master)
	dao.add_user(username, email, hash_password(password), hash_password(key), salt)

def add_entry(username, service, password):
	nonce = generate_nonce()
	service = pad_text(service)
	password = pad_text(password)
	key = decipher_key()
	service = encrypt(service.encode(), key, nonce)
	password = encrypt(password.encode(), key, nonce, len(service))
	dao.add_entry(username, service, password, nonce)

def read_services(user):
	data = dao.get_entries(user)
	key = decipher_key()
	for i in range(len(data)):
		rowid, service, password, iv = data[i]
		service = encrypt(service, key, iv).decode()
		service = unpad_text(service)
		data[i] = rowid, service, password, iv
	return data

def read_password(rowid):
	service, password, nonce = dao.get_entry(rowid)
	key = decipher_key()
	password = encrypt(password, key, nonce, len(service))
	return unpad_text(password.decode())

def get_expiry():
	return str(datetime.now() + timedelta(minutes=10))

def user_exists(username):
	return dao.get_email(username) is not None

def create_session(username):
	session_id = generate_session_id()
	expiry = get_expiry()
	dao.add_session(session_id, username, expiry)
	return session_id

def create_master_session(username, key):
	session_id = generate_session_id()
	expiry = get_expiry()
	dao.add_master_session(session_id, username, key, expiry)
	return session_id

def get_user():
	sid = get_from_cookie("session_id")
	user = dao.get_session(sid)
	return user

def logged_in():
	try:
		return get_user() is not None
	except ValueError:
		return False

def master_logged_in():
	if not logged_in():
		return False
	
	session_id = get_from_cookie("master_session_id")
	nonce = get_from_cookie("nonce")
	try:
		return (dao.get_master_session(session_id) or False) and master_key_correct(get_user(), decipher_key())
	except ValueError:
		return False

def decipher_key():
	sid = get_from_cookie("master_session_id")
	nonce = get_from_cookie("nonce")
	return decrypt_key(sid, nonce)
