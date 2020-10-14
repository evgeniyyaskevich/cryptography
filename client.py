from PyQt5.QtWidgets import QApplication, QWidget, QTextEdit, QVBoxLayout, QListWidget, QPushButton, QMainWindow
import rsa
import base64
import requests
import aes

RSA_KEY_SIZE = 512
SERVER_ADDRESS = 'http://localhost:5000'

def login(username, passwd):
    (pubkey, privkey) = rsa.newkeys(RSA_KEY_SIZE)
    r = requests.post(SERVER_ADDRESS + '/login', 
        json={'n': pubkey['n'], 'e': pubkey['e'], 'username': username, 'password': passwd})
    if r.ok:
        session_key = rsa.decrypt(base64.b64decode(r.json()['session_key'].encode('utf8')), privkey)
    else:
        print('Error msg:', r.json().get('result_msg'))
    return session_key

def get_filelist():
    r = requests.post(SERVER_ADDRESS + '/filelist',
        json={'username': 'Bob'})
    return r.json().get('files')

def get_file_content(filename):
        r = requests.post(SERVER_ADDRESS + '/read',
        json={'username': 'Bob', 'filename': filename})

        b64 = r.json()
        json_keys = [ 'nonce', 'cipher_text', 'tag' ]
        json_vals = {key:base64.b64decode(b64[key]) for key in json_keys}

        return aes.decrypt_file(session_key, json_vals['nonce'], json_vals['cipher_text'], 
                json_vals['tag']).decode('utf8')

class MainWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Cryptography')

        ### Filelist ###
        self.filelist_widget = QListWidget()
        for f in get_filelist():
            self.filelist_widget.addItem(f)
        self.filelist_widget.currentItemChanged.connect(self.update_file)

        ### Editor ###
        self.editor_widget = QTextEdit()

        ### Buttons ###
        self.pb_create = QPushButton('New')
        self.pb_save = QPushButton('Save')
        self.pb_delete = QPushButton('Delete')

        ### Layout ###
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.filelist_widget)
        self.layout.addWidget(self.editor_widget)
        self.layout.addWidget(self.pb_create)
        self.layout.addWidget(self.pb_save)
        self.layout.addWidget(self.pb_delete)

        self.setLayout(self.layout)
        self.show()
    
    def update_file(self):
        self.editor_widget.document().setPlainText(get_file_content(self.filelist_widget.currentItem().text()))

if __name__ == '__main__':
    session_key = login('Bob', 'Bob')

    app = QApplication([])
    window = MainWindow()
    app.exec_()
