# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'd:\Jiewo\Folder\Done\2023_fall\intro_of_information_security\simple_aes\Simple_AES\ui\encryption_window.ui'
#
# Created by: PyQt5 UI code generator 5.15.7
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_EncryptionWindow(object):
    def setupUi(self, EncryptionWindow):
        EncryptionWindow.setObjectName("EncryptionWindow")
        EncryptionWindow.resize(1000, 600)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(EncryptionWindow.sizePolicy().hasHeightForWidth())
        EncryptionWindow.setSizePolicy(sizePolicy)
        EncryptionWindow.setMinimumSize(QtCore.QSize(1000, 600))
        EncryptionWindow.setMaximumSize(QtCore.QSize(1000, 600))
        EncryptionWindow.setCursor(QtGui.QCursor(QtCore.Qt.ArrowCursor))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/icons/icon/lock.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        EncryptionWindow.setWindowIcon(icon)
        EncryptionWindow.setIconSize(QtCore.QSize(26, 26))
        EncryptionWindow.setToolButtonStyle(QtCore.Qt.ToolButtonTextOnly)
        EncryptionWindow.setDockOptions(QtWidgets.QMainWindow.AnimatedDocks)
        self.centralwidget = QtWidgets.QWidget(EncryptionWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.main_frame = QtWidgets.QFrame(self.centralwidget)
        self.main_frame.setGeometry(QtCore.QRect(0, 0, 1011, 611))
        self.main_frame.setAutoFillBackground(False)
        self.main_frame.setStyleSheet("QFrame {\n"
"    background-color:rgb(255, 255, 255);\n"
"}\n"
"\n"
"QPushButton {\n"
"    border: none;\n"
"}\n"
"\n"
"")
        self.main_frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.main_frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.main_frame.setLineWidth(1)
        self.main_frame.setObjectName("main_frame")
        self.content_frame = QtWidgets.QFrame(self.main_frame)
        self.content_frame.setGeometry(QtCore.QRect(320, 40, 641, 531))
        self.content_frame.setStyleSheet("QLineEdit {\n"
"    border-radius:10px;\n"
"    background-color:rgb(240, 240, 240);\n"
"    padding-left:10px;\n"
"    padding-right:10px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"    background-color:rgb(240, 240, 240);\n"
"}\n"
"\n"
"#content_frame {\n"
"    border:3px solid rgb(170, 170, 255);\n"
"    border-radius:20px\n"
"}\n"
"\n"
"")
        self.content_frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.content_frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.content_frame.setObjectName("content_frame")
        self.plain_text_input = QtWidgets.QLineEdit(self.content_frame)
        self.plain_text_input.setGeometry(QtCore.QRect(220, 40, 371, 51))
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(12)
        self.plain_text_input.setFont(font)
        self.plain_text_input.setStyleSheet("")
        self.plain_text_input.setText("")
        self.plain_text_input.setObjectName("plain_text_input")
        self.set_key_check = QtWidgets.QCheckBox(self.content_frame)
        self.set_key_check.setGeometry(QtCore.QRect(50, 130, 161, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(11)
        font.setBold(False)
        font.setWeight(50)
        self.set_key_check.setFont(font)
        self.set_key_check.setObjectName("set_key_check")
        self.encrpyt_text_label = QtWidgets.QLabel(self.content_frame)
        self.encrpyt_text_label.setGeometry(QtCore.QRect(50, 230, 161, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(11)
        font.setBold(False)
        font.setWeight(50)
        self.encrpyt_text_label.setFont(font)
        self.encrpyt_text_label.setObjectName("encrpyt_text_label")
        self.plain_text_label = QtWidgets.QLabel(self.content_frame)
        self.plain_text_label.setGeometry(QtCore.QRect(50, 50, 161, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(11)
        font.setBold(False)
        font.setWeight(50)
        self.plain_text_label.setFont(font)
        self.plain_text_label.setObjectName("plain_text_label")
        self.generate_button = QtWidgets.QPushButton(self.content_frame)
        self.generate_button.setGeometry(QtCore.QRect(230, 450, 201, 51))
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(14)
        font.setBold(True)
        font.setWeight(75)
        self.generate_button.setFont(font)
        self.generate_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.generate_button.setMouseTracking(False)
        self.generate_button.setStyleSheet("QPushButton {\n"
"    color:white;\n"
"    background-color:rgb(85, 0, 127);\n"
"    border-radius:18px;\n"
"}\n"
"\n"
"QPushButton::pressed {\n"
"    background-color:rgb(170, 170, 255);\n"
"}\n"
"\n"
"")
        self.generate_button.setObjectName("generate_button")
        self.encrypted_text_input = QtWidgets.QTextEdit(self.content_frame)
        self.encrypted_text_input.setGeometry(QtCore.QRect(220, 230, 371, 131))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        self.encrypted_text_input.setFont(font)
        self.encrypted_text_input.setStyleSheet("QTextEdit {\n"
"    background-color:rgb(240, 240, 240);\n"
"    border:none;\n"
"    border-radius:10px;\n"
"    padding-left:10px;\n"
"    padding-right:10px;\n"
"}\n"
"\n"
"QTextEdit QScrollBar::handle:vertical {\n"
"    background-color:rgb(170, 170, 255);\n"
"    border-radius:5px\n"
"}")
        self.encrypted_text_input.setReadOnly(True)
        self.encrypted_text_input.setObjectName("encrypted_text_input")
        self.key_input = QtWidgets.QTextEdit(self.content_frame)
        self.key_input.setGeometry(QtCore.QRect(220, 120, 371, 91))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        self.key_input.setFont(font)
        self.key_input.setStyleSheet("QTextEdit {\n"
"    background-color:rgb(240, 240, 240);\n"
"    border:none;\n"
"    border-radius:10px;\n"
"    padding-left:10px;\n"
"    padding-right:10px;\n"
"}\n"
"\n"
"QTextEdit QScrollBar::handle:vertical {\n"
"    background-color:rgb(170, 170, 255);\n"
"    border-radius:5px\n"
"}")
        self.key_input.setReadOnly(True)
        self.key_input.setObjectName("key_input")
        self.en_mode = QtWidgets.QComboBox(self.content_frame)
        self.en_mode.setGeometry(QtCore.QRect(390, 380, 201, 31))
        self.en_mode.setStyleSheet("QComboBox{\n"
"    border:1px solid #242424;\n"
"    border-radius:3px;\n"
"    padding:2px;\n"
"    background:none;\n"
"    border-color: rgb(22,63,23);\n"
"    background-color: rgb(255, 255, 255);\n"
"    selection-background-color:#484848;\n"
"    selection-color:#DCDCDC;\n"
"}\n"
" \n"
" \n"
"QComboBox::down-arrow{\n"
"    image: url(:/icons/icon/down-arrow.png);\n"
"    width:20px;\n"
"    height:25px;\n"
"    right:0px;\n"
"}\n"
" \n"
"QComboBox::drop-down{\n"
"    subcontrol-origin:padding;\n"
"    subcontrol-position:top right;\n"
"    width:20px;\n"
"    border-left-width:0px;\n"
"    border-left-style:solid;\n"
"}\n"
" \n"
"QComboBox::drop-down:on{\n"
"    top:1px;\n"
"}\n"
"QComboBox QAbstractItemView::item{\n"
"    min-height:24px;\n"
"    min-width:20px;\n"
"    color: rgb(239, 239, 239);\n"
"}\n"
"QComboBox QAbstractItemView::item:selected\n"
"{    \n"
"    background-color: rgb(170, 170, 255);\n"
"}\n"
"\n"
"")
        self.en_mode.setObjectName("en_mode")
        self.en_mode.addItem("")
        self.en_mode.addItem("")
        self.en_mode.addItem("")
        self.input_mode = QtWidgets.QComboBox(self.content_frame)
        self.input_mode.setGeometry(QtCore.QRect(220, 380, 151, 31))
        self.input_mode.setStyleSheet("QComboBox{\n"
"    border:1px solid #242424;\n"
"    border-radius:3px;\n"
"    padding:2px;\n"
"    background:none;\n"
"    border-color: rgb(22,63,23);\n"
"    background-color: rgb(255, 255, 255);\n"
"    selection-background-color:#484848;\n"
"    selection-color:#DCDCDC;\n"
"}\n"
" \n"
" \n"
"QComboBox::down-arrow{\n"
"    image: url(:/icons/icon/down-arrow.png);\n"
"    width:20px;\n"
"    height:25px;\n"
"    right:0px;\n"
"}\n"
" \n"
"QComboBox::drop-down{\n"
"    subcontrol-origin:padding;\n"
"    subcontrol-position:top right;\n"
"    width:20px;\n"
"    border-left-width:0px;\n"
"    border-left-style:solid;\n"
"}\n"
" \n"
"QComboBox::drop-down:on{\n"
"    top:1px;\n"
"}\n"
"QComboBox QAbstractItemView::item{\n"
"    min-height:24px;\n"
"    min-width:20px;\n"
"    color: rgb(239, 239, 239);\n"
"}\n"
"QComboBox QAbstractItemView::item:selected\n"
"{    \n"
"    background-color: rgb(170, 170, 255);\n"
"}\n"
"\n"
"")
        self.input_mode.setObjectName("input_mode")
        self.input_mode.addItem("")
        self.input_mode.addItem("")
        self.encrpyt_text_label_2 = QtWidgets.QLabel(self.content_frame)
        self.encrpyt_text_label_2.setGeometry(QtCore.QRect(60, 370, 131, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(11)
        font.setBold(False)
        font.setWeight(50)
        self.encrpyt_text_label_2.setFont(font)
        self.encrpyt_text_label_2.setObjectName("encrpyt_text_label_2")
        self.menu_frame = QtWidgets.QFrame(self.main_frame)
        self.menu_frame.setGeometry(QtCore.QRect(30, 40, 251, 531))
        self.menu_frame.setStyleSheet("QPushButton {\n"
"    border-radius:10px;\n"
"    background-color:rgb(255, 255, 255);\n"
"}\n"
"\n"
"QFrame {\n"
"    background-color:rgb(210, 213, 255);\n"
"    border-radius:20px\n"
"}\n"
"\n"
"")
        self.menu_frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.menu_frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.menu_frame.setObjectName("menu_frame")
        self.decryption_button = QtWidgets.QPushButton(self.menu_frame)
        self.decryption_button.setGeometry(QtCore.QRect(30, 110, 191, 51))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.decryption_button.setFont(font)
        self.decryption_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.decryption_button.setStyleSheet("QPushButton::hover {\n"
"    background-color:rgb(230, 230, 230)\n"
"}\n"
"\n"
"QPushButton::pressed {\n"
"    background-color:rgb(224, 220, 240)\n"
"}")
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(":/icons/icon/decryption.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.decryption_button.setIcon(icon1)
        self.decryption_button.setObjectName("decryption_button")
        self.encryption_button = QtWidgets.QPushButton(self.menu_frame)
        self.encryption_button.setGeometry(QtCore.QRect(30, 30, 191, 51))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.encryption_button.setFont(font)
        self.encryption_button.setCursor(QtGui.QCursor(QtCore.Qt.ArrowCursor))
        self.encryption_button.setStyleSheet("background-color:rgb(95, 0, 147);\n"
"color:white;")
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(":/icons/icon/encryption.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.encryption_button.setIcon(icon2)
        self.encryption_button.setCheckable(False)
        self.encryption_button.setObjectName("encryption_button")
        self.crack_button = QtWidgets.QPushButton(self.menu_frame)
        self.crack_button.setGeometry(QtCore.QRect(30, 190, 191, 51))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.crack_button.setFont(font)
        self.crack_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.crack_button.setStyleSheet("QPushButton::hover {\n"
"    background-color:rgb(230, 230, 230)\n"
"}\n"
"\n"
"QPushButton::pressed {\n"
"    background-color:rgb(224, 220, 240)\n"
"}")
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(":/icons/icon/spider.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.crack_button.setIcon(icon3)
        self.crack_button.setObjectName("crack_button")
        self.get_info_button = QtWidgets.QPushButton(self.menu_frame)
        self.get_info_button.setGeometry(QtCore.QRect(30, 440, 191, 51))
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.get_info_button.setFont(font)
        self.get_info_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.get_info_button.setMouseTracking(False)
        self.get_info_button.setStyleSheet("QPushButton {\n"
"    color:white;\n"
"    background-color:rgb(119, 0, 255);\n"
"    border-radius:18px;\n"
"}\n"
"\n"
"QPushButton::pressed {\n"
"    background-color:rgb(170, 170, 255);\n"
"}\n"
"\n"
"")
        self.get_info_button.setObjectName("get_info_button")
        EncryptionWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(EncryptionWindow)
        QtCore.QMetaObject.connectSlotsByName(EncryptionWindow)

    def retranslateUi(self, EncryptionWindow):
        _translate = QtCore.QCoreApplication.translate
        EncryptionWindow.setWindowTitle(_translate("EncryptionWindow", "Simple-DES"))
        self.set_key_check.setText(_translate("EncryptionWindow", "Set Key"))
        self.encrpyt_text_label.setText(_translate("EncryptionWindow", "Encrypted Text"))
        self.plain_text_label.setText(_translate("EncryptionWindow", "Plain Text"))
        self.generate_button.setText(_translate("EncryptionWindow", "Generate"))
        self.en_mode.setItemText(0, _translate("EncryptionWindow", "normal encryption"))
        self.en_mode.setItemText(1, _translate("EncryptionWindow", "double encryption"))
        self.en_mode.setItemText(2, _translate("EncryptionWindow", "triple encryption"))
        self.input_mode.setItemText(0, _translate("EncryptionWindow", "string"))
        self.input_mode.setItemText(1, _translate("EncryptionWindow", "binary"))
        self.encrpyt_text_label_2.setText(_translate("EncryptionWindow", "settings"))
        self.decryption_button.setText(_translate("EncryptionWindow", "  Decryption"))
        self.encryption_button.setText(_translate("EncryptionWindow", "  Encryption"))
        self.crack_button.setText(_translate("EncryptionWindow", "Crack"))
        self.get_info_button.setText(_translate("EncryptionWindow", "Encryption Info"))
from ui.src import res_rc
