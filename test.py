# import re
# import base64
# import uuid

# def obfuscate(code):
#     code = f"# {uuid.uuid4()} \n" + code + f"# {uuid.uuid4()} \n"
#     print(code)
#     encoded = re.findall(r".{1,50}", str(base64.b64encode(str.encode(code)).decode("utf-8")))
#     python_string = ""
#     for i in range(0, len(encoded)):
#         if i != 0:
#             python_string += "         "
#         python_string += f"b'{encoded[i]}'"
#         if i != len(encoded) - 1: 
#             python_string += "\\\n"

#     return str(f"""
# from base64 import b64encode, b64decode
# hidden = {python_string}
# eval(compile(b64decode(hidden.decode()), "<string>", "exec")) 
#     """).strip()


# print(obfuscate("""class Note:
#     def __init__(self, note, is_long=False):
#         self.note = note
#         self.is_long = is_long
#         self.default_notes = ["до", "ре", "ми", "фа", "соль", "ля", "си"]
#         self.logn_notes = ["до-о", "ре-э", "ми-и", "фа-а", "со-оль", "ля-а", "си-и"]
#         if self.is_long:
#             self.note = self.logn_notes[self.default_notes.index(self.note.lower())]

#     def __str__(self):
#         return self.note
# """))

# from base64 import b64encode, b64decode
# hidden = b'IyA4ZmVhNDhjMy0yMzM3LTQzNTQtOWIxZC1lOTA4MTg3NmQxYj'\
#          b'MgCmNsYXNzIE5vdGU6CiAgICBkZWYgX19pbml0X18oc2VsZiwg'\
#          b'bm90ZSwgaXNfbG9uZz1GYWxzZSk6CiAgICAgICAgc2VsZi5ub3'\
#          b'RlID0gbm90ZQogICAgICAgIHNlbGYuaXNfbG9uZyA9IGlzX2xv'\
#          b'bmcKICAgICAgICBzZWxmLmRlZmF1bHRfbm90ZXMgPSBbItC00L'\
#          b'4iLCAi0YDQtSIsICLQvNC4IiwgItGE0LAiLCAi0YHQvtC70Ywi'\
#          b'LCAi0LvRjyIsICLRgdC4Il0KICAgICAgICBzZWxmLmxvZ25fbm'\
#          b'90ZXMgPSBbItC00L4t0L4iLCAi0YDQtS3RjSIsICLQvNC4LdC4'\
#          b'IiwgItGE0LAt0LAiLCAi0YHQvi3QvtC70YwiLCAi0LvRjy3QsC'\
#          b'IsICLRgdC4LdC4Il0KICAgICAgICBpZiBzZWxmLmlzX2xvbmc6'\
#          b'CiAgICAgICAgICAgIHNlbGYubm90ZSA9IHNlbGYubG9nbl9ub3'\
#          b'Rlc1tzZWxmLmRlZmF1bHRfbm90ZXMuaW5kZXgoc2VsZi5ub3Rl'\
#          b'Lmxvd2VyKCkpXQoKICAgIGRlZiBfX3N0cl9fKHNlbGYpOgogIC'\
#          b'AgICAgIHJldHVybiBzZWxmLm5vdGUKIyBkOTlkNzQ4YS1lOTcw'\
#          b'LTQzZjMtOWNhMi1lNjk1Zjk1N2Q0NWQgCg=='
# eval(compile(b64decode(hidden.decode()), "<string>", "exec"))
from base64 import b64encode, b64decode
hidden = b'IyBkMzgzOWQ3Yy0yMmJjLTRiNzctODc4My0yY2JhMjJkNzY2MT'\
         b'ggCmNsYXNzIE5vdGU6CiAgICBkZWYgX19pbml0X18oc2VsZiwg'\
         b'bm90ZSwgaXNfbG9uZz1GYWxzZSk6CiAgICAgICAgc2VsZi5ub3'\
         b'RlID0gbm90ZQogICAgICAgIHNlbGYuaXNfbG9uZyA9IGlzX2xv'\
         b'bmcKICAgICAgICBzZWxmLmRlZmF1bHRfbm90ZXMgPSBbItC00L'\
         b'4iLCAi0YDQtSIsICLQvNC4IiwgItGE0LAiLCAi0YHQvtC70Ywi'\
         b'LCAi0LvRjyIsICLRgdC4Il0KICAgICAgICBzZWxmLmxvZ25fbm'\
         b'90ZXMgPSBbItC00L4t0L4iLCAi0YDQtS3RjSIsICLQvNC4LdC4'\
         b'IiwgItGE0LAt0LAiLCAi0YHQvi3QvtC70YwiLCAi0LvRjy3QsC'\
         b'IsICLRgdC4LdC4Il0KICAgICAgICBpZiBzZWxmLmlzX2xvbmc6'\
         b'CiAgICAgICAgICAgIHNlbGYubm90ZSA9IHNlbGYubG9nbl9ub3'\
         b'Rlc1tzZWxmLmRlZmF1bHRfbm90ZXMuaW5kZXgoc2VsZi5ub3Rl'\
         b'Lmxvd2VyKCkpXQoKICAgIGRlZiBfX3N0cl9fKHNlbGYpOgogIC'\
         b'AgICAgIHJldHVybiBzZWxmLm5vdGUjIDc4MTA5MGE4LTE2Mjgt'\
         b'NGU4Ny05OGUzLTFjMDVjYzk0ZWU3NSAK'
eval(compile(b64decode(hidden.decode()), "<string>", "exec"))

eval(compile(b64decode(hidden.decode()), "<string>", "exec"))
do_1 = Note("до", False)
doo = Note("до", True)
do_2 = Note("до")
print(do_1, doo, do_2)