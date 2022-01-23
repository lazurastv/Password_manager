import sqlite3
from init_sqlite import DATABASE_PATH
from base64 import b64encode, b64decode

def clean_date(date):
	return date[0:19]

class SqliteDAO:	
	def __init__(self):
		self.db = sqlite3.connect(DATABASE_PATH)
		self.sql = self.db.cursor()
	
	def get_hash(self, username):
		self.sql.execute("SELECT hash FROM user WHERE username = ?;", (username,))
		hashed, = self.sql.fetchone() or (None,)
		return hashed
	
	def get_master_hash(self, username):
		self.sql.execute("SELECT master_hash FROM user WHERE username = ?;", (username,))
		master_hash, = self.sql.fetchone() or (None,)
		return master_hash
	
	def get_master_salt(self, username):
		self.sql.execute("SELECT master_salt FROM user WHERE username = ?;", (username,))
		master_salt, = self.sql.fetchone() or (None,)
		return b64decode(master_salt)
	
	def get_session(self, sid):
		self.delete_expired_sessions()
		self.sql.execute("SELECT username FROM session WHERE sid = ?;", (sid,))
		username, = self.sql.fetchone() or (None,)
		return username
	
	def get_master_session(self, sid):
		self.delete_expired_sessions()
		self.sql.execute("SELECT username FROM master_session WHERE sid = ?;", (sid,))
		username, = self.sql.fetchone() or (None,)
		return username
	
	def get_encrypted_key(self, sid):
		self.delete_expired_sessions()
		self.sql.execute("SELECT key FROM master_session WHERE sid = ?;", (sid,))
		key, = self.sql.fetchone() or (None,)
		return b64decode(key)
	
	def get_entry(self, rowid):
		self.sql.execute("SELECT service, password, iv FROM entries WHERE rowid = ?;", (rowid,))
		service, password, iv = self.sql.fetchone() or (None, None, None)
		return b64decode(service), b64decode(password), b64decode(iv)
		
	def get_entries(self, username):
		self.sql.execute("SELECT rowid, service, password, iv FROM entries WHERE username = ?;", (username,))
		data = self.sql.fetchall() or []
		
		for i in range(len(data)):
			rowid, service, password, iv = data[i]
			data[i] = rowid, b64decode(service), b64decode(password), b64decode(iv)
		return data
	
	def add_user(self, username, hashed, master_hash, master_salt):
		master_salt = b64encode(master_salt).decode()
		self.sql.execute("INSERT INTO user (username, hash, master_hash, master_salt) VALUES (?, ?, ?, ?);", (username, hashed, master_hash, master_salt))
		self.db.commit()

	def add_session(self, sid, username, expiry):
		expiry = clean_date(expiry)
		self.sql.execute("INSERT INTO session (sid, username, expiry) VALUES (?, ?, ?);", (sid, username, expiry))
		self.db.commit()
	
	def add_master_session(self, sid, username, key, expiry):
		expiry = clean_date(expiry)
		key = b64encode(key).decode()
		self.sql.execute("INSERT INTO master_session (sid, username, key, expiry) VALUES (?, ?, ?, ?);", (sid, username, key, expiry))
		self.db.commit()
	
	def add_entry(self, username, service, password, iv):
		service = b64encode(service).decode()
		password = b64encode(password).decode()
		iv = b64encode(iv).decode()
		self.sql.execute("INSERT INTO entries (username, service, password, iv) VALUES (?, ?, ?, ?);", (username, service, password, iv))
		self.db.commit()
	
	def delete_session(self, sid):
		self.sql.execute("DELETE FROM session WHERE sid = ?;", (sid,))
		self.db.commit()
	
	def delete_master_session(self, sid):
		self.sql.execute("DELETE FROM master_session WHERE sid = ?;", (sid,))
		self.db.commit()
	
	def delete_expired_sessions(self):
		self.sql.execute("DELETE FROM session WHERE expiry < datetime('now', 'localtime');")
		self.sql.execute("DELETE FROM master_session WHERE expiry < datetime('now', 'localtime');")
		self.db.commit()
	
	def delete_entry(self, rowid):
		self.sql.execute("DELETE FROM entries WHERE rowid = ?;", (rowid,))
		self.db.commit()

dao = SqliteDAO()
