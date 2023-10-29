from PyQt5.QtWidgets import QMessageBox
from PyQt5 import QtGui

def error_warning(message: str) -> None:
    mes = QMessageBox(QMessageBox.Icon.Warning, "Error", message)
    icon = QtGui.QIcon()
    icon.addPixmap(QtGui.QPixmap("ui/icon/error-message.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
    mes.setWindowIcon(icon)
    mes.exec_()

def message_refer(message: str) -> None:
    mes = QMessageBox(QMessageBox.Icon.Information, "Encryption Info", message)
    mes.exec_()