from aes.AES import AES
import sys
from PyQt5.QtWidgets import QApplication
from ui.src.window_controller import WindowController

app = QApplication(sys.argv)

con = WindowController()
con.init()

sys.exit(app.exec_())

# ase = AES()
# ase.init()
# e = ase.encrypt(0x45C1)
# d = ase.decrypt(e)

# group1 = ase.group_encrypt([0x1212, 0x3454])
# group1 = ase.group_decrypt(group1)
# print(group1)

# group2 = ase.string_encrypt("hello world")
# group3 = ase.string_decrypt(group2)
# print(group2)
# print(group3)

# print(e)
# print(d)
# print(0x45C1)
# print(0x09DB)