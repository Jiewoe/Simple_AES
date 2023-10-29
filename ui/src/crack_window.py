from PyQt5.QtWidgets import QMainWindow
from PyQt5.QtCore import pyqtSignal
from ui.src.Ui_crack import *
from ui.src.window_utils import error_warning
import re

class CrackWindow(QMainWindow):
    change_window_signal = pyqtSignal(str)
    crack_signal = pyqtSignal(dict)

    def __init__(self) -> None:
        super().__init__()
        self.ui = Ui_CrackWindow()
        self.ui.setupUi(self)

    def init(self) -> None:
        self.ui.crack_button.clicked.connect(self.crack)
        self.ui.encryption_button.clicked.connect(self.change_encryption_window)
        self.ui.decryption_button.clicked.connect(self.change_decryption_window)

    def crack(self) -> None:
        plain_text = self.ui.plain_text_input.text().replace(" ", "")
        if plain_text == "":
            error_warning("Please enter plain text !  ")

        encrypted_text = self.ui.encrypted_text_input.text().replace(" ", "")
        if encrypted_text == "":
            error_warning("Please enter encrypted text !  ")
            return
        if re.match(r'^[01]+$', plain_text) is None or re.match(r'^[01]+$', encrypted_text) is None:
            error_warning("Plain text or encrypted text has format fault (need n*16bit binary input) !  ")
            return

        data_dict = {
            "en_text": encrypted_text,
            "pn_text": plain_text
        }

        self.crack_signal.emit(data_dict)

    def change_encryption_window(self):
        self.change_window_signal.emit("encrypt")

    def change_decryption_window(self):
        self.change_window_signal.emit("decrypt")

    def show_result(self, text: str):
        self.ui.key_result.setText(text)