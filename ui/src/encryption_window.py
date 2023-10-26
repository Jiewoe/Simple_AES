import re
from PyQt5.QtWidgets import QMainWindow
from PyQt5.QtCore import pyqtSignal
from ui.src.Ui_encryption_window import *
from ui.src.window_utils import error_warning

class EncryptionWindow(QMainWindow):
    change_window_signal = pyqtSignal()
    generate_signal = pyqtSignal(dict)
    decrypt_signal = pyqtSignal(dict)

    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"

    NORMAL = "normal encryption"
    DOUBLE = "double encryption"
    TROUPE = "troupe encryption"

    def __init__(self) -> None:
        self.mode = self.ENCRYPT
        super().__init__()
        self.ui = Ui_EncryptionWindow()
        self.ui.setupUi(self)

    def init(self) -> None:
        self.ui.generate_button.clicked.connect(self.generate)
        self.ui.crack_button.clicked.connect(self.change_window)
        self.ui.set_key_check.toggled.connect(self.set_key_setting)
        # self.ui.char_button.toggled.connect(self.plain_text_setting)
        self.ui.encryption_button.clicked.connect(self.change_encrypt_mode)
        self.ui.decryption_button.clicked.connect(self.change_decrypt_mode)
        self.ui.key_input.textChanged.connect(self.format_text)

        # key_validator = QtGui.QRegExpValidator(QtCore.QRegExp("[01]{10,10}"), self.ui.key_input)
        # self.ui.key_input.setValidator(key_validator)

        self.window_mode_init(self.ENCRYPT)

    def format_text(self):
        text = self.ui.key_input.toPlainText()
        if (text == ""):
            return 
        
        cursor_position = self.ui.key_input.textCursor().position()
        num = text.replace(" ", "")
        if (len(num)%4 == 0 and text[-1]!=" "):
            text += " "
            self.ui.key_input.setText(text)

            cursor = self.ui.key_input.textCursor()
            cursor.setPosition(cursor_position+1)
            self.ui.key_input.setTextCursor(cursor)

    def window_mode_init(self, mode: str):
        if self.mode == mode:
            return 
        
        if mode == "encrypt":
            self.ui.plain_text_input.setText("")
            self.ui.encrypted_text_input.setText("")
            self.ui.encrypted_text_input.setReadOnly(True)
            self.ui.plain_text_input.setReadOnly(False)
            self.ui.key_input.setReadOnly(True)
            self.ui.set_key_check.setChecked(False)
            self.ui.encryption_button.setStyleSheet("background-color:rgb(95, 0, 147);\ncolor:white;")
            self.ui.decryption_button.setStyleSheet("QPushButton::hover {\nbackground-color:rgb(230, 230, 230)\n}\nQPushButton::pressed {\nbackground-color:rgb(224, 220, 240)\n}")
            self.ui.encryption_button.setCursor(QtCore.Qt.CursorShape.ArrowCursor)
            self.ui.decryption_button.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)

        else:
            self.ui.plain_text_input.setText("")
            self.ui.encrypted_text_input.setText("")
            self.ui.encrypted_text_input.setReadOnly(False)
            self.ui.plain_text_input.setReadOnly(True)
            self.ui.key_input.setReadOnly(True)
            self.ui.set_key_check.setChecked(False)
            self.ui.decryption_button.setStyleSheet("background-color:rgb(95, 0, 147);\ncolor:white;")
            self.ui.encryption_button.setStyleSheet("QPushButton::hover {\nbackground-color:rgb(230, 230, 230)\n}\nQPushButton::pressed {\nbackground-color:rgb(224, 220, 240)\n}")
            self.ui.decryption_button.setCursor(QtCore.Qt.CursorShape.ArrowCursor)
            self.ui.encryption_button.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)

        self.mode = mode

    def change_encrypt_mode(self):
        self.window_mode_init(self.ENCRYPT)

    def change_decrypt_mode(self):
        self.window_mode_init(self.DECRYPT)

    def set_key_setting(self):
        if self.ui.set_key_check.isChecked():
            self.ui.key_input.setReadOnly(False)
        else:
            self.ui.key_input.setReadOnly(True)
            
    def plain_text_setting(self):
        choose_mode = self.ui.input_mode.currentText()
        if choose_mode == "binary":
            binary_validator = QtGui.QRegExpValidator(QtCore.QRegExp("[01]+"), self.ui.plain_text_input)
            self.ui.plain_text_input.setValidator(binary_validator)
        else:
            self.ui.plain_text_input.setValidator(None)

    def generate(self) -> None:
        if self.mode == self.ENCRYPT:
            text = self.ui.plain_text_input.text()
        else:
            text = self.ui.encrypted_text_input.toPlainText()

        encrypt_mode = self.ui.en_mode.currentText()
        choose_mode = self.ui.input_mode.currentText()

        if text == "":
            if self.mode == self.ENCRYPT:
                error_warning("Please enter plain text !  ")
                if choose_mode == "binary" and re.match(r'^[01]+$', text) is None:
                    error_warning("Plain text need n*16bit binary number !  ")
                    return
            else:
                error_warning("Please enter encrypted text !  ")
                if choose_mode == "binary" and re.match(r'^[01]+$', text) is None:
                    error_warning("Encrypted text need n*16bit binary number !  ")
                    return
            return

        if self.ui.set_key_check.isChecked():
            key = self.ui.key_input.toPlainText().replace(" ", "")
            if key == "":
                error_warning("Please set encryption key !  ")
                return
            elif re.match(r'^[01]+$', key) is None:
                error_warning("Encryption key has fault !  ")
                return
            elif encrypt_mode==self.NORMAL and len(key) != 16:
                error_warning("Encryption key need 16bit !  ")
                return
            elif encrypt_mode==self.DOUBLE and len(key)!=32:
                error_warning("Encryption key need 32bit !  ")
                return
            elif encrypt_mode==self.TROUPE and len(key)!=48:
                error_warning("Encryption key need 48bit !  ")
                return
        else:
            key = ""

        data_dict = {
            "codeset": choose_mode,
            "key": key,
            "text": text,
            "mode": self.mode,
            "encrypt_mode": encrypt_mode
        }
        self.generate_signal.emit(data_dict)

    def change_window(self):
        self.change_window_signal.emit()

    def show_result(self, text: str):
        if self.mode == self.ENCRYPT:
            self.ui.encrypted_text_input.setText(text)
        else:
            self.ui.plain_text_input.setText(text)