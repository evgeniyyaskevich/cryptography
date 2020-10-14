from PyQt5.QtWidgets import QApplication, QWidget, QTextEdit, QVBoxLayout, QListWidget, QPushButton, QMainWindow, QDialogButtonBox, QLineEdit, QLabel, QFormLayout, QDialog, QRadioButton, QMessageBox
from PyQt5 import QtCore, QtGui
from aes import encrypt_text, decrypt_file
import rsa
import base64
import requests
import aes
import sys
import json

RSA_KEY_SIZE = 512
SERVER_ADDRESS = 'http://localhost:5000'

username = ''

def login(username, passwd):
    (pubkey, privkey) = rsa.newkeys(RSA_KEY_SIZE)
    r = requests.post(SERVER_ADDRESS + '/login', 
        json={'n': pubkey['n'], 'e': pubkey['e'], 'username': username, 'password': passwd})
    if r.ok:
        return rsa.decrypt(base64.b64decode(r.json()['session_key'].encode('utf8')), privkey)
    else:
        return {'error': r.json().get('result_msg')}

def get_filelist():
    r = requests.post(SERVER_ADDRESS + '/filelist',
        json={'username': username})
    return r.json().get('files')

def get_file_content(filename):
        r = requests.post(SERVER_ADDRESS + '/read',
        json={'username': username, 'filename': filename})

        b64 = r.json()
        json_keys = [ 'nonce', 'cipher_text', 'tag' ]
        json_vals = {key:base64.b64decode(b64[key]) for key in json_keys}

        return aes.decrypt_file(session_key, json_vals['nonce'], json_vals['cipher_text'], 
                json_vals['tag']).decode('utf8')

def update_file(filename, text):
        data = encrypt_text(session_key, text.encode('utf8'))
        res = json.loads(data)
        res['username'] = username
        res['filename'] = filename
        requests.post(SERVER_ADDRESS + '/update', json=res)

class FilenameDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Filename?')

        QBtn = QDialogButtonBox.Ok | QDialogButtonBox.Cancel

        self.buttonBox = QDialogButtonBox(QBtn)
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)
        
        self.filename_widget = QLineEdit()

        self.layout = QVBoxLayout()
        self.layout.addWidget(self.filename_widget)
        self.layout.addWidget(self.buttonBox)
        self.setLayout(self.layout)

    def accept(self):
        self.done(0)
    
    def reject(self):
        self.done(1)

class MainWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Cryptography')

        ### Editor ###
        self.editor_widget = QTextEdit()

        ### Filelist ###
        self.filelist_widget = QListWidget()
        self.filelist_widget.currentItemChanged.connect(self.update_file)
        self.update_filelist()

        ### Buttons ###
        self.pb_create = QPushButton('New')
        self.pb_create.clicked.connect(self.create_file)
        self.pb_save = QPushButton('Save')
        self.pb_save.clicked.connect(self.save_file)
        self.pb_delete = QPushButton('Delete')
        self.pb_delete.clicked.connect(self.delete_file)

        ### Layout ###
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.filelist_widget)
        self.layout.addWidget(self.editor_widget)
        self.layout.addWidget(self.pb_create)
        self.layout.addWidget(self.pb_save)
        self.layout.addWidget(self.pb_delete)

        self.setLayout(self.layout)
        self.show()
    
    def save_file(self):
        update_file(self.filelist_widget.currentItem().text(), self.editor_widget.document().toPlainText()) 

    def delete_file(self):
        try:
            requests.post(SERVER_ADDRESS + '/delete', json={'username': username, 'filename': self.filelist_widget.currentItem().text()})
        except:
            pass
        self.update_filelist()

    def update_file(self):
        try:
            self.editor_widget.document().setPlainText(get_file_content(self.filelist_widget.currentItem().text()))
        except:
            self.editor_widget.document().setPlainText('')

    def create_file(self):
        dlg = FilenameDialog() 
        if not dlg.exec():
            update_file(dlg.filename_widget.text(), '')
            self.update_filelist()

    def update_filelist(self):
        self.filelist_widget.clear()
        for f in get_filelist():
            self.filelist_widget.addItem(f)
        self.filelist_widget.setCurrentRow(0)

class AuthDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Cryptography')
        self.setAttribute(QtCore.Qt.WA_DeleteOnClose)
        dlgLayout = QVBoxLayout()
        formLayout = QFormLayout()

        self.label = QLabel()
        pal = self.label.palette()
        pal.setColor(QtGui.QPalette.WindowText, QtGui.QColor("red"))
        self.label.setPalette(pal)
        formLayout.addRow(self.label)

        self.login_field = QLineEdit()
        formLayout.addRow('Login:', self.login_field)
        self.passwd_field = QLineEdit(echoMode=QLineEdit.Password)
        formLayout.addRow('Password:', self.passwd_field)

        dlgLayout.addLayout(formLayout)
        btns = QDialogButtonBox()
        btns.setStandardButtons(QDialogButtonBox.Cancel)
        btns.rejected.connect(self.reject)

        signInButton = QPushButton('SignIn')
        signInButton.clicked.connect(self.signIn)

        btns.addButton(signInButton, QDialogButtonBox.ActionRole)

        dlgLayout.addWidget(btns)
        self.setLayout(dlgLayout)

    def extractUser(self):
        return {
            'username': self.login_field.text(),
            'password': self.passwd_field.text()
        }

    def signIn(self):
        user = AuthDialog.extractUser(self)
        res = login(user['username'], user['password'])
        errorMsg = res.get('error', '') if type(res) is dict else ''

        if not errorMsg:
            self.session_key = res
            global username
            username = user['username']
            self.done(0)
        else:
            self.label.setText(errorMsg)

    def reject(self):
        self.done(1)

if __name__ == '__main__':
    session_key = b''

    app = QApplication(sys.argv)
    authDlg = AuthDialog()
    if not authDlg.exec_():
        session_key = authDlg.session_key
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())
