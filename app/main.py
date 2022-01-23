from utils import *
from api import *
from cipher import *
from auth import unauth
from sqlite import dao
from flask import Blueprint
from flask import render_template, url_for, redirect, request
from base64 import b64encode

main = Blueprint('main', __name__, template_folder='templates')

@main.route("/")
def index(wrong=False, empty=False):
	if not logged_in():
		return force_logout()
	
	user = get_user()
	verified = master_logged_in()
	data = []
	if verified:
		data = read_services(user)
	
	return render_template("main.html", verified=verified, data=data, wrong=wrong, empty=empty)

@main.route("get_key", methods=["POST"])
def get_key():
	if not logged_in():
		return force_logout()
	
	user = get_user()
	master = get_from_form('master')
	key, nonce = derive_key_with_nonce(user, master)
	
	if not master_key_correct(user, xor32(key, nonce)):
		return render_template("main.html", wrong=True)
	
	session_id = create_master_session(user, key)
	
	response = make_response('', 303)
	response.headers["Location"] = url_for("main.index")
	add_cookie(response, "master_session_id", session_id)
	add_cookie(response, "nonce", b64encode(nonce))
	
	return response

@main.route("decrypt_password", methods=["POST"])
def decrypt_password():
	if not master_logged_in():
		force_logout()
		password = ''
	else:
		rowid = get_from_json("rowid")
		try:
			password = read_password(rowid)
		except UnicodeDecodeError:
			force_logout()
			password = ''
	return {'password': password}

@main.route("add", methods=["POST"])
def add():
	if not master_logged_in():
		return force_logout()
	
	user = get_user()
	service = get_from_form('service')
	password = get_from_form('password')
	if service == "" or password == "":
		return index(empty=True)
	
	add_entry(user, service, password)
	
	return redirect(url_for(".index"))

@main.route("delete", methods=["POST"])
def delete():
	if not master_logged_in():
		return force_logout()
	
	user = get_user()
	rowid = get_from_form('rowid')
	dao.delete_entry(rowid)
	
	return redirect(url_for(".index"))

