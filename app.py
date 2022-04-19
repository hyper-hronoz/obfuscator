import os
import re
import ssl
import jwt
import uuid
import base64
import smtplib
from email.mime.text import MIMEText
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, request, jsonify, make_response

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


class JSONWebToken:
    def __init__(self) -> None:
        pass

    def encode(self, data):
        return jwt.encode(data, "secret", algorithm="HS256")

    def decode(self, token):
        return jwt.decode(token, "secret", algorithms=["HS256"])


class Mailer(Resource):
    def __init__(self) -> None:
        self.is_success = False
        super().__init__()

    def get(self, jwt):
        try:
            print(jwt)
        except Exception as error:
            print(error.message())
            return "Internal server error", 500


    def send_email(self, email, token_link):
        try:
            isSuccess = False
            message = MIMEMultipart("alternative")
            html = str(render_template("email.html", jwt=token_link))
            message.attach(MIMEText(html, "html"))
            context = ssl.create_default_context()
            port = 465

            with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
                server.login(gmail_address, gmail_password)
                server.sendmail(gmail_address, email, message.as_string())

            self.is_success = True
        except Exception as e:
            print(e)


class Validator:
    def __init__(self) -> None:
        self.alerts = []

    def validate(self, string: str):
        self.validate_content = string.strip()
        return self

    def not_okey(self):
        return self.alerts

    def minimalLenght(self, minimal_length=8, message="Password are too shot min {minimal_length} symbols"):
        if len(self.validate_content) < minimal_length:
            self.alerts.append(message.format(minimal_length=minimal_length))
        return self

    def maximalLenght(self, maximal_length=100, message="Password are too long max {maximal_length} symbols"):
        if len(self.validate_content) > maximal_length:
            self.alerts.append(message.format(maximal_length=maximal_length))
        return self

    def same(self, strings=[], message="Different passwords"):
        strings = [i.strip() for i in strings]
        if len(set(strings)) != 1:
            self.alerts.append(message)
        return self

    def isEmpty(self, message="Field is empty"):
        if len(self.validate_content) == 0:
            self.alerts.append(message)
        return self

    def isEmail(self, message="Field must content email"):
        regular = r'([-!#-\'*+/-9=?A-Z^-~]+(\.[-!#-\'*+/-9=?A-Z^-~]+)*|"([]!#-[^-~ \t]|(\\[\t -~]))+")@[0-9A-Za-z]([0-9A-Za-z-]{0,61}[0-9A-Za-z])?(\.[0-9A-Za-z]([0-9A-Za-z-]{0,61}[0-9A-Za-z])?)+'
        if not re.match(regular, self.validate_content):
            self.alerts.append(message)
        return self


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
        try:
            return make_response(render_template('registration.html'), 200, html_headers)
        except Exception as error:
            print(error.message())
            return "Internal server error", 500

    def post(self):
        try:
            email: str = str(request.form["email"]).strip()
            password: str = str(request.form["password"]).strip()
            password_again: str = str(request.form["password_again"]).strip()

            jsonWebToken = JSONWebToken()

            token = jsonWebToken.encode({"email": email})

            mailer = Mailer()
            mailer.send_email(email, "http://127.0.0.1:5000/confirmation/" + token.decode("utf-8"))

            if mailer.is_success:
                pass

        except Exception as error:
            print(error)
            return "Internal server error", 500




class Login(Resource):
    def get(self):
        try:
            return make_response(render_template('login.html'), 200, html_headers)
        except Exception as error:
            print(error.message())
            return "Internal server error", 500

    def post(self):
        try:
            email: str = str(request.form["email"]).strip()
            password: str = str(request.form["password"]).strip()

        except Exception as error:
            print(error.message())
            return "Internal server error", 500


@app.route("/")
def index():
    return render_template("index.html")


api.add_resource(Obfuscator, "/api/obfuscate")
api.add_resource(AdvancedObfuscator, "/api/obfuscate/<code>/<obfuscation_hardness>/<api_key>")
api.add_resource(Registration, "/registration")
api.add_resource(Mailer, "/confirmation/<jwt>")
api.add_resource(Login, "/login")


if __name__ == '__main__':
    app.run(debug=True)
