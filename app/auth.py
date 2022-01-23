from utils import *
from api import *
from cipher import *
from flask import Blueprint
from flask import render_template, url_for, redirect, make_response

auth = Blueprint('auth', __name__, template_folder='templates')

@auth.route("/")
def index():
	return render_template("welcome.html")

@auth.route("login", methods=["POST"])
def login():
	username = get_from_form('username')
	password = get_from_form('password')
	
	if not password_correct(username, password):
		return render_template("welcome.html", failed=True)
	
	session_id = create_session(username)
	
	response = make_response('', 303)
	response.headers["Location"] = url_for("main.index")
	add_cookie(response, "session_id", session_id)
	return response

@auth.route("logout")
def logout():
	return clear_session(".index")

@auth.route("register")
def register():
	return render_template("register.html")

@auth.route("create_account", methods=["POST"])
def create_account():
	username = get_from_form('username')
	email = get_from_form('email')
	password = get_from_form('password')
	master = get_from_form('master')
	if username == "" or email == "" or password == "" or master == "":
		return render_template("register.html", blank=True)
	elif weak_password(password) or weak_password(master):
		return render_template("register.html", weak=True)
	elif user_exists(username):
		return render_template("register.html", copy=True)
	add_user(username, email, password, master)
	return redirect(url_for(".login"), 307)

@auth.route("unauth")
def unauth():
	return render_template("unauth.html")
