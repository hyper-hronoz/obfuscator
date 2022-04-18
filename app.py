from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SECRET_KEY'] = "hell_bound_in_satan_in_wonderland"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Users(db.Model):
   id = db.Column(db.Integer, primary_key=True)
   email = db.Column(db.String(200))
   password = db.Column(db.String(200))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/registration")
def registration():
    return render_template("registration.html")

@app.route("/registration", methods=["POST"])
def regisrate():
    return "Hello"

@app.route("/login")
def login():
    return render_template("login.html")