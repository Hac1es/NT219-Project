import sys
import os
import numpy as np
import openfhe as fhe
from PyQt6 import QtWidgets, uic
from PyQt6.QtWidgets import QFileDialog, QMessageBox
from PyQt6.QtCore import QTimer
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

# Set platform plugin
os.environ["QT_QPA_PLATFORM"] = "xcb"

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        # Load the UI file
        uic.loadUi("MainWindow.ui", self)
        
        # Initialize CKKS
        self.cc = None
        self.keys = None
        
        # Connect signals and slots here
        self.calc_button.clicked.connect(self.calc_data)
        self.pushButton_3.clicked.connect(self.load_public_key)
        self.pushButton_4.clicked.connect(self.load_eval_mult_key)
        
        # Loading value
        self.loading = False
        
        # Tạo timer để kiểm tra trạng thái loading
        self.loading_timer = QTimer(self)
        self.loading_timer.timeout.connect(self.check_loading)
        self.loading_timer.start(100)  # kiểm tra mỗi 100ms
        
        # Show the window
        self.show()
    
    def initialize_ckks(self):
        parameters = fhe.CCParamsCKKSRNS()
        parameters.SetMultiplicativeDepth(15)
        parameters.SetScalingModSize(59)
        parameters.SetBatchSize(1) 

        crypto_context = fhe.GenCryptoContext(parameters)
        crypto_context.Enable(fhe.PKESchemeFeature.PKE)
        crypto_context.Enable(fhe.PKESchemeFeature.LEVELEDSHE)
        crypto_context.Enable(fhe.PKESchemeFeature.ADVANCEDSHE)

        return crypto_context

    def generate_and_save_keys(self, bank_name):
        try:
            """Generate new key pair and save to files"""
            self.loading = True
            self.cc = self.initialize_ckks()
            self.keys = self.cc.KeyGen()
            self.cc.EvalMultKeyGen(self.keys.secretKey)

            # Create keys directory if it doesn't exist
            if not os.path.exists(f'keys_{bank_name}'):
                os.makedirs(f'keys_{bank_name}')

            # Save keys to files
            if not fhe.SerializeToFile(f'keys_{bank_name}/publicKey.txt', self.keys.publicKey, fhe.BINARY):
                raise Exception("Không thể lưu public key")
            if not fhe.SerializeToFile(f'keys_{bank_name}/privateKey.txt', self.keys.secretKey, fhe.BINARY):
                raise Exception("Không thể lưu private key")
            if not self.cc.SerializeEvalMultKey(f'keys_{bank_name}/eval-mult-key.txt', fhe.BINARY):
                raise Exception("Không thể lưu eval mult key")
            self.loading = False
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Có lỗi xảy ra: {str(e)}")
            self.loading = False

    def encrypt_data(self, data):
        # Create plaintext from data
        plaintext = self.cc.MakeCKKSPackedPlaintext(data)
        # Encrypt using the public key
        ciphertext = self.cc.Encrypt(self.keys.publicKey, plaintext)
        return ciphertext

    def serialize_ciphertext(self, ciphertext):
        """Serialize ciphertext to string"""
        try:
            serialized = fhe.Serialize(ciphertext, fhe.BINARY)
            return serialized
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Có lỗi xảy ra: {str(e)}")
            return None

    def calc_data(self):
        try:
            # Check if keys exist, if not generate new ones
            if self.keys is None:
                self.loading = True
                self.generate_and_save_keys(self.selectBank.currentText())
                QMessageBox.information(self, "Thông báo", "Đã tạo cặp khóa mới")
                self.loading = False

            # Get values from text fields
            payment_history = float(self.S_payment.toPlainText() or "0")
            credit_util = float(self.S_util.toPlainText() or "0")
            credit_age = float(self.S_length.toPlainText() or "0")
            credit_mix = float(self.S_creditmix.toPlainText() or "0")
            credit_inquiries = float(self.S_inquiries.toPlainText() or "0")
            income_stability = float(self.S_incomestability.toPlainText() or "0")
            financial_behavior = float(self.S_behavorial.toPlainText() or "0")
            customer_name = self.customerName.toPlainText()
            bank_name = self.selectBank.currentText()

            # Prepare data as simple lists
            user_data = {
                'S_payment': [payment_history],
                'S_util': [credit_util],
                'S_length': [credit_age],
                'S_creditmix': [credit_mix],
                'S_inquiries': [credit_inquiries],
                'S_behavioral': [financial_behavior],
                'S_incomestability': [income_stability]
            }

            # Encrypt and serialize data
            self.loading = True
            try:
                # Đọc hoặc sinh cặp khóa ECDSA nếu chưa có
                if not (os.path.exists("ecdsa_private.pem") and os.path.exists("ecdsa_public.pem")):
                    self.generate_ecdsa_keys()
                with open("ecdsa_private.pem", "rb") as f:
                    private_key = serialization.load_pem_private_key(f.read(), password=None)

                # Đọc file
                with open(f'ciphertext_{bank_name}.bin', 'wb') as f:
                    # Write metadata as text
                    metadata = f"-----BEGIN METADATA-----\nBank: {bank_name}\nCustomer: {customer_name}\n-----END METADATA-----\n\n"
                    f.write(metadata.encode('utf-8'))

                    # Write each ciphertext
                    for k, v in user_data.items():
                        ciphertext = self.encrypt_data(v)
                        serialized = self.serialize_ciphertext(ciphertext)
                        if serialized:
                            # Write header
                            header = f"-----BEGIN CIPHERTEXT {k}-----\n"
                            f.write(header.encode('utf-8'))
                            
                            # Write binary data
                            f.write(serialized)
                            
                            # Write footer
                            footer = f"\n-----END CIPHERTEXT {k}-----\n\n"
                            f.write(footer.encode('utf-8'))
                            
                    # Write public key
                    serialized_public_key = fhe.Serialize(self.keys.publicKey, fhe.BINARY)
                    # Write header
                    header = f"-----BEGIN PUBLIC KEY-----\n"
                    f.write(header.encode('utf-8'))
                    # Write binary data
                    f.write(serialized_public_key)
                    # Write footer
                    footer = f"\n-----END PUBLIC KEY-----\n\n"
                    f.write(footer.encode('utf-8'))

                # Đọc private key
                with open("ecdsa_private.pem", "rb") as f:
                    private_key = serialization.load_pem_private_key(f.read(), password=None)

                # Đọc file
                with open("ciphertext.bin", "rb") as f:
                    data = f.read()

                # Hash và ký
                signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

                # Lưu chữ ký
                with open("ciphertext.bin.sig", "wb") as f:
                    f.write(signature)

                QMessageBox.information(self, "Kết quả", "Đã mã hóa và lưu dữ liệu vào file ciphertext.bin")
            except Exception as e:
                QMessageBox.critical(self, "Lỗi", f"Không thể lưu file: {str(e)}")
            finally:
                self.loading = False
                self.close()

        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Có lỗi xảy ra: {str(e)}")

    def load_public_key(self):
        self.loading = True
        file_name, _ = QFileDialog.getOpenFileName(self, "Chọn file khóa bí mật", "", "BINARY Files (*.txt);;All Files (*)")
        if file_name:
            try:
                if self.cc is None:
                    self.cc = self.initialize_ckks()
                publicKey, result = fhe.DeserializePublicKey(file_name, fhe.BINARY)
                if not result:
                    raise Exception("Không thể load public key")
                
                # Initialize keys if not exists
                if self.keys is None:
                    self.keys = type('KeyPair', (), {})()
                self.keys.publicKey = publicKey
                QMessageBox.information(self, "Thành công", "Đã load public key!")
            except Exception as e:
                QMessageBox.critical(self, "Lỗi", f"Không load được public key: {str(e)}")
        self.loading = False
        
    def load_eval_mult_key(self):
        self.loading = True
        file_name, _ = QFileDialog.getOpenFileName(self, "Chọn file khóa đa nhân", "", "BINARY Files (*.txt);;All Files (*)")
        if file_name:
            try:
                if self.cc is None:
                    self.cc = self.initialize_ckks()
                
                if not self.cc.DeserializeEvalMultKey(file_name, fhe.BINARY):
                    raise Exception("Không thể load eval mult key")
                QMessageBox.information(self, "Thành công", "Đã load eval mult key!")
            except Exception as e:
                QMessageBox.critical(self, "Lỗi", f"Không load được eval mult key: {str(e)}")
        self.loading = False
        
    def check_loading(self):
        if self.loading:
            self.outputShow.setText("Loading...")
        else:
            # Nếu muốn xóa chữ loading khi xong, có thể set rỗng hoặc giữ nguyên
            self.outputShow.setText("")

    def generate_ecdsa_keys(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # Lưu private key
        with open("ecdsa_private.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Lưu public key
        with open("ecdsa_public.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    sys.exit(app.exec()) 