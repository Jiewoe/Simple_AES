from ui.src.crack_window import CrackWindow
from ui.src.encryption_window import EncryptionWindow
from ui.src.window_utils import error_warning
from aes.AES import AES


class WindowController:
    def __init__(self) -> None:
        self.aes = AES()
        self.crack_win = CrackWindow()
        self.encryption_win = EncryptionWindow()
        # self.crack_thread = CrackThread()
        
        self.crack_win.hide()
        self.encryption_win.show()

    def init(self):
        self.crack_win.init()
        self.encryption_win.init()
        self.aes.init()

        self.crack_win.change_window_signal.connect(self.show_encryption_window)
        self.encryption_win.change_window_signal.connect(self.show_crack_window)

        self.encryption_win.generate_signal.connect(self.generate_text)
        self.crack_win.crack_signal.connect(self.crack)

    def show_encryption_window(self, mode: str) -> None:
        self.crack_win.hide()
        self.encryption_win.window_mode_init(mode=mode)
        self.encryption_win.show()

    def show_crack_window(self):
        self.encryption_win.hide()
        self.crack_win.show()

    def generate_text(self, data_dict: dict):
        try:
            codeset = data_dict['codeset']
            key = data_dict['key']
            text = data_dict['text']
            mode = data_dict['mode']
            encrypt_mode = data_dict['encrypt_mode']

            if encrypt_mode == EncryptionWindow.NORMAL:
                key_size = 16
            elif encrypt_mode == EncryptionWindow.DOUBLE:
                key_size = 32
            elif encrypt_mode == EncryptionWindow.TROUPE:
                key_size = 48

            if codeset == "binary":
                texts = []
                for i in range(0, len(text), 8):
                    texts.append(self.to_number(text[i:2*i]))
                
                if key == "":
                    self.aes.generate_key(key_size)
                else:
                    self.aes.set_key(self.to_number(key))

                res = None
                if mode == EncryptionWindow.ENCRYPT:
                    if encrypt_mode == EncryptionWindow.NORMAL:
                        res = self.aes.group_encrypt(texts)
                else:
                    if encrypt_mode == EncryptionWindow.NORMAL:
                        res = self.aes.group_decrypt(texts)

                self.encryption_win.show_result(res)

        except Exception as e:
            error_warning("Some error happened, please enter again or restart the program !  ")

    def crack(self, data_dict: dict):
        try:
            print(data_dict["pn_text"])
            print(data_dict["en_text"])
            print(data_dict["codeset"])
            if data_dict["codeset"] == "unicode":
                res = ""
            else:
                self.crack_thread.solve(data_dict["pn_text"], data_dict["en_text"])
                res = "Possible keys are:\n"
                for key in self.crack_thread.get_keys():
                    res += key
                    res += '\n'
                res = res + "\nSpent time: " + '{:.6}s'.format(str(self.crack_thread.get_time())) + '\n'

            self.crack_win.show_result(res)
        except Exception as e:
            error_warning("Some error happened, please enter again or restart the program !  ")

    def to_string(self, text):
        res = []
        for each in text:
            for x in each:
                res.append(str(x))

        return res
    
    def to_number(self, binary_string):
        num = 0

        for number in binary_string:
            num = num << 1 + number

        return num