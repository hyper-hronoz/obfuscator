from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import re
import base64
import uuid
from flask import Flask, render_template, request, jsonify, make_response
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
import smtplib
import ssl
import jwt
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)
api = Api(app)

app.config['SECRET_KEY'] = "hell_bound_in_satan_in_wonderland"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

gmail_address = os.environ["gmail_address"]
gmail_password = os.environ["gmail_password"]

html_headers = {'Content-Type': 'text/html'}
json_headers = {'Content-Type': 'application/json'}

class DifferentPasswordsException(Exception):
    def __init__(self, message="Passwords are different") -> None:
        super().__init__(message)

class ShortPasswordException(Exception):
    def __init__(self, message="Password are too shot min 8 symbols") -> None:
        super().__init__(message)

class LongPasswordException(Exception):
    def __init__(self, message="Password are too shot max 200 symbols") -> None:
        super().__init__(message)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    api_key = db.Column(db.String(400), nullable=True)


class Obfuscator(Resource):

    def post(self):
        data = request.get_json()
        obfuscated = {"value": Obfuscator.obfuscate(data["value"])}
        return jsonify(obfuscated)

    @staticmethod
    def obfuscate(code):
        code = f"# {uuid.uuid4()} \n" + code + f"# {uuid.uuid4()} \n"
        encoded = re.findall(r".{1,50}", str(
            base64.b64encode(str.encode(code)).decode("utf-8")))
        python_string = ""
        for i in range(0, len(encoded)):
            if i != 0:
                python_string += "         "
            python_string += f"b'{encoded[i]}'"
            if i != len(encoded) - 1:
                python_string += "\\\n"

        return str(f"""
from base64 import b64encode, b64decode
hidden = {python_string}
eval(compile(b64decode(hidden.decode()), "<string>", "exec")) 
        """).strip()


class AdvancedObfuscator(Obfuscator):
    def get(self, code, obfuscation_hardness, api_key):
        obfuscated = Obfuscator.obfuscate(code)

        for i in range(int(obfuscation_hardness)):
            obfuscated = Obfuscator.obfuscate(obfuscated)

        return obfuscated



class Registration(Resource):
    def get(self):
        return make_response(render_template('registration.html'), 200, html_headers)

    def post(self):

        email:str = str(request.form["email"]).strip()
        password:str = str(request.form["password"]).strip()
        password_again:str = str(request.form["password_again"]).strip()

        try:
            valid = validate_email(email)
            email = valid.email

            if (password != password_again):
                raise DifferentPasswordsException()

            if len(password) < 8:
                raise ShortPasswordException()

            if len(password) > 200:
                raise LongPasswordException()

        except EmailNotValidError as e:
            return "Invalide email", 401
        except ShortPasswordException as e:
            return "Minimal password length 8", 401
        except LongPasswordException as e:
            return "Maximal password length 200", 401

        return send_email(email, "link")

class Login(Resource):
    def get(self):
        return make_response(render_template('login.html'), 200, html_headers)

    def post(self):
        email:str = str(request.form["email"]).strip()
        password:str = str(request.form["password"]).strip()

        try:
            valid = validate_email(email)
            email = valid.email

            if len(password) < 8:
                raise ShortPasswordException()

            if len(password) > 200:
                raise LongPasswordException()

        except ShortPasswordException as e:
            return "Minimal password length 8", 401
        except LongPasswordException as e:
            return "Maximal password length 200", 401

        return send_email(email, "link")

def send_email(email, token_link):
    message = MIMEMultipart("alternative")
    html = str(render_template("email.html", token_link=token_link))
    message.attach(MIMEText(html, "html"))
    context = ssl.create_default_context()
    port = 465

    with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
        server.login(gmail_address, gmail_password)
        server.sendmail(gmail_address, email, message.as_string())
        return "Email sended"

@app.route("/")
def index():
    return render_template("index.html")

api.add_resource(Obfuscator, "/api/obfuscate")
api.add_resource(AdvancedObfuscator, "/api/obfuscate/<code>/<obfuscation_hardness>/<api_key>")
api.add_resource(Registration, "/registration")
api.add_resource(Login, "/login")

if __name__ == '__main__':
    app.run(debug=True)
