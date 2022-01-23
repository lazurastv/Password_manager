from os import getenv
from flask import Flask
from auth import auth
from main import main

PREFIX = getenv('PREFIX','')
app = Flask(__name__)
app.register_blueprint(auth, url_prefix=PREFIX)
app.register_blueprint(main, url_prefix=PREFIX + "/main")
