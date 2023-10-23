from PyQt5.QtWidgets import QMessageBox
from PyQt5 import QtGui

def error_warning(message: str) -> None:
    mes = QMessageBox(QMessageBox.Icon.Warning, "Error", message)
    icon = QtGui.QIcon()
    icon.addPixmap(QtGui.QPixmap("d:\\Jiewo\\Folder\\Done\\2023_fall\\intro_of_information_security\\simple_des\\Simple_DES\\ui\\icon/error-message.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
    mes.setWindowIcon(icon)
    mes.exec_()