# import re
import jwt


# class Validator:
#     def __init__(self) -> None:
#         self.alerts = []

#     def validate(self, string:str):
#         self.validate_content = string.strip()
#         return self

#     def not_okey(self):
#         return self.alerts

#     def minimalLenght(self, minimal_length = 8, message="Password are too shot min {minimal_length} symbols"):
#         if len(self.validate_content) < minimal_length:
#             self.alerts.append(message.format(minimal_length=minimal_length))
#         return self

#     def maximalLenght(self, maximal_length=100, message="Password are too long max {maximal_length} symbols"):
#         if len(self.validate_content) > maximal_length:
#             self.alerts.append(message.format(maximal_length=maximal_length))
#         return self

#     def same(self, strings=[], message="Different passwords"):
#         strings = [i.strip() for i in strings]
#         if len(set(strings)) != 1:
#             self.alerts.append(message)
#         return self

#     def isEmpty(self, message="Field is empty"):
#         if len(self.validate_content) == 0:
#             self.alerts.append(message)
#         return self

#     def isEmail(self, message="Field must content email"):
#         regular = r'([-!#-\'*+/-9=?A-Z^-~]+(\.[-!#-\'*+/-9=?A-Z^-~]+)*|"([]!#-[^-~ \t]|(\\[\t -~]))+")@[0-9A-Za-z]([0-9A-Za-z-]{0,61}[0-9A-Za-z])?(\.[0-9A-Za-z]([0-9A-Za-z-]{0,61}[0-9A-Za-z])?)+'
#         if not re.match(regular, self.validate_content):
#             self.alerts.append(message)
#         return self


# validator = Validator()
# validator.validate("").isEmail().isEmpty()

# print(validator.alerts)

class app:
    config = {}

app.config["JWT_SECRET_KEY"] = "HELLO"

class JSONWebToken:
    def __init__(self) -> None:
        pass

    def encode(self, data):
        return jwt.encode(data, app.config["JWT_SECRET_KEY"], algorithm="HS256")

    def decode(self, token):
        return jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])


jsonWebToken = JSONWebToken()
token = jsonWebToken.encode({"Hello": "There"})
print(jsonWebToken.decode(token)["Hello"])
