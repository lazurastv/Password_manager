from sqlite import dao
from flask import make_response, url_for, render_template, request
	
def add_cookie(response, name, value, max_age=None):
	response.set_cookie(name, value, max_age=max_age, httponly=True, secure=True, samesite='Strict')

def clear_cookie(response, name):
	add_cookie(response, name, "", -1)

def clear_session(location):
	session_id = get_from_cookie("session_id")
	master_id = get_from_cookie("master_session_id")
	
	dao.delete_session(session_id)
	if master_id: dao.delete_master_session(master_id)
	
	response = make_response('', 303)
	response.headers["Location"] = url_for(location)
	clear_cookie(response, "session_id")
	clear_cookie(response, "master_session_id")
	clear_cookie(response, "nonce")
	return response

def force_logout():
	return clear_session('auth.unauth')

def get_from_json(name):
	return request.json.get(name) or ""

def get_from_form(name):
	return request.form.get(name) or ""

def get_from_cookie(name):
	return request.cookies.get(name) or ""
