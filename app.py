import re, base64, uuid
from flask import Flask, render_template, request, jsonify
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
import smtplib, ssl

app = Flask(__name__)
api = Api(app)

app.config['SECRET_KEY'] = "hell_bound_in_satan_in_wonderland"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Users(db.Model):
   id = db.Column(db.Integer, primary_key=True)
   email = db.Column(db.String(200))
   password = db.Column(db.String(200))


class Obfuscator(Resource):

    def post(self):
        data = request.get_json()
        obfuscated = {"value" : Obfuscator.obfuscate(data["value"])}
        return jsonify(obfuscated)

    @staticmethod
    def obfuscate(code):
        code = f"# {uuid.uuid4()} \n" + code + f"# {uuid.uuid4()} \n"
        encoded = re.findall(r".{1,50}", str(base64.b64encode(str.encode(code)).decode("utf-8")))
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


@app.route("/")
def index():
    return render_template("index.html")

# ненавижу flask за это почему нельзя было сделать как в node js app.get("/registration", (req, res) => {}) app.post("/registration", (req, res) => {})
@app.route("/registration")
def registration():
    return render_template("registration.html")

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/registration", methods=["POST"])
def regisrate():
    email = request.form["email"]
    password = request.form["password"]
    password_again = request.form["password_again"]
    print(email, password, password_again)
    return "Hello"

api.add_resource(Obfuscator, "/api/obfuscate")
api.add_resource(AdvancedObfuscator, "/api/obfuscate/<code>/<obfuscation_hardness>/<api_key>")

if __name__ == '__main__':
    app.run(debug=True)