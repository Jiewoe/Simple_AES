from ui.src.crack_window import CrackWindow
from ui.src.encryption_window import EncryptionWindow
from multiple_encryption.multiple import Multiple
from ui.src.window_utils import error_warning, message_refer
from aes.AES import AES


class WindowController:
    def __init__(self) -> None:
        self.aes = AES()
        self.crack_win = CrackWindow()
        self.encryption_win = EncryptionWindow()
        self.multiple = Multiple()
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

        self.encryption_win.ui.get_info_button.clicked.connect(self.get_info)

    def show_encryption_window(self, mode: str) -> None:
        self.crack_win.hide()
        self.encryption_win.window_mode_init(mode=mode)
        self.encryption_win.show()

    def show_crack_window(self):
        self.encryption_win.hide()
        self.crack_win.show()

    def generate_text(self, data_dict: dict):
        # try:
            codeset = data_dict['codeset']
            key = data_dict['key']
            text = data_dict['text']
            mode = data_dict['mode']
            encrypt_mode = data_dict['encrypt_mode']
            vector = data_dict['vector']

            if key == "":
                self.aes.generate_key(16)
            else:
                key_num = self.to_number(key)
                if encrypt_mode == EncryptionWindow.NORMAL:
                    self.aes.set_key(key_num)
                elif encrypt_mode == EncryptionWindow.DOUBLE:
                    self.multiple.bit32_key = key_num
                else:
                    self.multiple.bit48_key = key_num

            if vector == "":
                self.aes.generate_vector()
            else:
                self.aes.set_initial_vector(self.to_number(vector))

            if codeset == "binary":
                texts = []
                for i in range(0, int(len(text)/16)):
                    texts.append(self.to_number(text[16*i:16*(i+1)]))

                res = None
                if mode == EncryptionWindow.ENCRYPT:
                    if encrypt_mode == EncryptionWindow.NORMAL:
                        if len(texts) == 1:
                            res = [self.aes.encrypt(texts[0])]
                        else:
                            res = self.aes.group_encrypt(texts)
                    else:
                        if len(texts) > 1:
                            error_warning("multiple encryption only support 16bit binary input!  ")
                            return
                        elif encrypt_mode == EncryptionWindow.DOUBLE:
                            res = [self.multiple.two_encrypt(self.multiple.get_bit32_key() ,texts[0])]
                        elif encrypt_mode == EncryptionWindow.TROUPE:
                            res = [self.multiple.three_two_encrypt(self.multiple.get_bit48_key(), texts[0])]
                else:
                    if encrypt_mode == EncryptionWindow.NORMAL:
                        if len(texts) == 1:
                            res = [self.aes.decrypt(texts[0])]
                        else:
                            res = self.aes.group_decrypt(texts)
                    else:
                        if len(texts) > 1:
                            error_warning("multiple decryption only support 16bit binary input!  ")
                            return
                        elif encrypt_mode == EncryptionWindow.DOUBLE:
                            res = [self.multiple.two_decrypt(self.multiple.get_bit32_key() ,texts[0])]
                        elif encrypt_mode == EncryptionWindow.TROUPE:
                            res = [self.multiple.three_two_decrypt(self.multiple.get_bit48_key(), texts[0])]

                res = self.to_binary_string(res)
                self.encryption_win.show_result(res)

            else:
                res = None
                if mode == EncryptionWindow.ENCRYPT:
                    if encrypt_mode == EncryptionWindow.NORMAL:
                        res = self.aes.string_encrypt(text)
                    else:
                        error_warning("multiple encryption only support 16bit binary input!  ")
                        return
                else:
                    if encrypt_mode == EncryptionWindow.NORMAL:
                        res = self.aes.string_decrypt(text)
                    else:
                        error_warning("multiple decryption only support 16bit binary input!  ")
                        return

                self.encryption_win.show_result(res)

        # except Exception as e:
            # print(e.args)
            # error_warning("Some error happened, please enter again or restart the program !  ")

    def crack(self, data_dict: dict):
        pt = data_dict['pn_text']
        et = data_dict['en_text']

        pc = []
        for i in range(0, int(len(pt)/16)):
            pc.append([self.to_number(pt[16*i:16*(i+1)]), self.to_number(et[16*i:16*(i+1)])])

        self.multiple.find_mid(pc)

        res = "The cracking results of double encryption of 32bit keys are as follows. Possible keys are:\n"

        for i in self.multiple.get_find_keys():
            res = res + format(i[0],'016b')+ " " +format(i[1],'016b') + '\n'

        self.crack_win.show_result(res)


    def to_binary_string(self, text: list[int]):
        res = []
        for item in text:
            binary = bin(item)
            res.append(((18-len(binary))*'0') + binary[2:])
        return " ".join(res)

    def to_number(self, binary_string):
        num = 0

        for number in binary_string:
            num = (num << 1) + int(number)

        return num
    
    def get_info(self):
        info = "initial vector: " + format(self.aes.initial_vector, '016b') + "\n"
        info += "normal encryption key: " + format(self.aes.keys[0], '016b') + "\n"
        info += "double encryption key: " + format(self.multiple.get_bit32_key(), '032b') + "\n"
        info += "triple encryption key: " + format(self.multiple.get_bit48_key(), '048b') + "\n"

        message_refer(info)