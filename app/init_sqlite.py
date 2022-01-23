import sqlite3
import os

DATABASE_PATH = "data.db"

if __name__ == "__main__":
	try:
		os.remove(DATABASE_PATH)
	except FileNotFoundError:
		pass

	db = sqlite3.connect(DATABASE_PATH)
	sql = db.cursor()

	sql.execute("""
	CREATE TABLE user (
		username VARCHAR(32),
		hash VARCHAR(60),
		master_hash VARCHAR(60),
		master_salt VARCHAR(60),
		PRIMARY KEY(username)
	);""")

	sql.execute("""
	CREATE TABLE session (
		sid VARCHAR(60),
		username VARCHAR(32),
		expiry SMALLDATETIME,
		PRIMARY KEY(sid)
	);""")
	
	sql.execute("""
	CREATE TABLE master_session (
		sid VARCHAR(60),
		username VARCHAR(32),
		key VARCHAR(60),
		expiry SMALLDATETIME,
		PRIMARY KEY(sid)
	);""")
	
	sql.execute("""CREATE TABLE entries (
		username VARCHAR(32),
		service VARCHAR(64),
		password VARCHAR(64),
		iv VARCHAR(60)
	);""")

	db.commit()
	db.close()
