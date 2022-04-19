import os
import re
import ssl
import jwt
import uuid
import bcrypt
import base64
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, request, jsonify, make_response, redirect, url_for

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
api = Api(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

app.jinja_env.auto_reload = True
app.config['TEMPLATES_AUTO_RELOAD'] = True
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

    def minimal_lenght(self, minimal_length=8, message="Password are too shot min {minimal_length} symbols"):
        if len(self.validate_content) < minimal_length:
            self.alerts.append(message.format(minimal_length=minimal_length))
        return self

    def maximal_lenght(self, maximal_length=100, message="Password are too long max {maximal_length} symbols"):
        if len(self.validate_content) > maximal_length:
            self.alerts.append(message.format(maximal_length=maximal_length))
        return self

    def same(self, strings=[], message="Different passwords"):
        strings = [i.strip() for i in strings]
        if len(set(strings)) != 1:
            self.alerts.append(message)
        return self

    def is_empty(self, message="Field is empty"):
        if len(self.validate_content) == 0:
            self.alerts.append(message)
        return self

    def is_email(self, message="Field must content email"):
        regular = r'([-!#-\'*+/-9=?A-Z^-~]+(\.[-!#-\'*+/-9=?A-Z^-~]+)*|"([]!#-[^-~ \t]|(\\[\t -~]))+")@[0-9A-Za-z]([0-9A-Za-z-]{0,61}[0-9A-Za-z])?(\.[0-9A-Za-z]([0-9A-Za-z-]{0,61}[0-9A-Za-z])?)+'
        if not re.match(regular, self.validate_content):
            self.alerts.append(message)
        return self

    def compare_hash(self, password, password_hashed, message="Login or password is incorrect"):
        password = str.encode(password)
        if not bcrypt.checkpw(password, password_hashed):
            self.alerts.append(message)
        return self


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    registration_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())
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
    @login_required
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

            validator = Validator()

            validator.validate(password).is_empty().minimal_lenght().maximal_lenght().same([password, password_again])
            validator.validate(email).is_empty().is_email()

            if validator.not_okey():
                return make_response(render_template("registration.html", errors=validator.alerts), 200, html_headers)

            jsonWebToken = JSONWebToken()

            token = jsonWebToken.encode({"email": email})

            mailer = Mailer()
            mailer.send_email(email, "http://127.0.0.1:5000/confirmation/" + token.decode("utf-8"))

            if mailer.is_success:
                password_hashed = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
                user = User(email=email, password=password_hashed)
                db.session.add(user)
                db.session.commit()
            
            return make_response(redirect(url_for("login")), 200, html_headers)

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
            
            validator = Validator()

            user = User.query.filter_by(email=email).first()

            validator.validate(password).is_empty().minimal_lenght().maximal_lenght().compare_hash(password, user.password)
            validator.validate(email).is_empty().is_email()

            if validator.not_okey():
                return make_response(render_template("login.html", errors=validator.alerts), 200, html_headers)

            login_user(user, remember=True)

        except Exception as error:
            print(error)
            return "Internal server error", 500


@app.route("/")
def index():
    print(current_user.is_authenticated)
    return render_template("index.html")


api.add_resource(Obfuscator, "/api/obfuscate")
api.add_resource(AdvancedObfuscator, "/api/obfuscate/<code>/<obfuscation_hardness>/<api_key>")
api.add_resource(Registration, "/registration")
api.add_resource(Mailer, "/confirmation/<jwt>")
api.add_resource(Login, "/login")


if __name__ == '__main__':
    app.run(debug=True, use_reloader=True)
