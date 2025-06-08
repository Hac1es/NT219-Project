"""
File: SerializeData.py
Mô tả: Giao diện người dùng (GUI) cho quá trình mã hóa và quản lý dữ liệu sử dụng mã hóa đồng hình (homomorphic encryption) với OpenFHE.
Chức năng chính:
- Sinh, lưu trữ và nạp các loại khóa (public, private, eval mult key)
- Mã hóa dữ liệu đầu vào từ người dùng
- Giao diện trực quan với PyQt6
"""

import sys
import os
import numpy as np
import openfhe as fhe
from PyQt6 import QtWidgets, uic
from PyQt6.QtWidgets import QFileDialog, QMessageBox
from PyQt6.QtCore import QTimer

# Set platform plugin
os.environ["QT_QPA_PLATFORM"] = "xcb"

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        # Load the UI file
        uic.loadUi("MainWindow.ui", self)
        
        # Initialize empty objects
        self.cc = None
        self.keys = type('KeyPair', (), {})()
        
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

    def initialize_crypto_context(self):
        """Initialize crypto context with required parameters"""
        parameters = fhe.CCParamsCKKSRNS()
        parameters.SetMultiplicativeDepth(15)
        parameters.SetScalingModSize(59)
        parameters.SetBatchSize(1)

        self.cc = fhe.GenCryptoContext(parameters)
        self.cc.Enable(fhe.PKESchemeFeature.PKE)
        self.cc.Enable(fhe.PKESchemeFeature.LEVELEDSHE)
        self.cc.Enable(fhe.PKESchemeFeature.ADVANCEDSHE)
        return self.cc

    def check_required_params(self):
        """Check if required parameters are loaded"""
        if not hasattr(self.keys, 'publicKey'):
            reply = QMessageBox.question(
                self,
                "Thiếu tham số",
                "Chưa load public key. Bạn có muốn load ngay bây giờ không?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.load_public_key()
            return False

        if self.cc is None:
            reply = QMessageBox.question(
                self,
                "Thiếu tham số",
                "Chưa load eval mult key. Bạn có muốn load ngay bây giờ không?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.load_eval_mult_key()
            return False

        return True

    def generate_and_save_keys(self, bank_name):
        try:
            """Generate new key pair and save to files"""
            self.loading = True
            self.cc = self.initialize_crypto_context()
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
            # Check if required parameters are loaded
            if not self.check_required_params():
                return

            # Check if keys exist, if not generate new ones
            if not hasattr(self.keys, 'publicKey'):
                self.loading = True
                self.generate_and_save_keys(self.selectBank.currentText())
                QMessageBox.information(self, "Thông báo", "Đã tạo cặp khóa mới")
                self.loading = False

            # Get values from text fields and only include non-empty ones
            user_data = {}
            fields = {
                'S_payment': self.S_payment.toPlainText(),
                'S_util': self.S_util.toPlainText(),
                'S_length': self.S_length.toPlainText(),
                'S_creditmix': self.S_creditmix.toPlainText(),
                'S_inquiries': self.S_inquiries.toPlainText(),
                'S_behavioral': self.S_behavorial.toPlainText(),
                'S_incomestability': self.S_incomestability.toPlainText()
            }

            for key, value in fields.items():
                if value.strip():  # Only include non-empty values
                    try:
                        user_data[key] = [float(value)]
                    except ValueError:
                        QMessageBox.warning(self, "Cảnh báo", f"Giá trị không hợp lệ cho {key}: {value}")
                        continue

            if not user_data:
                QMessageBox.warning(self, "Cảnh báo", "Không có dữ liệu nào để mã hóa")
                return

            customer_name = self.customerName.toPlainText()
            bank_name = self.selectBank.currentText()

            # Encrypt and serialize data
            self.loading = True
            try:
                # Lưu metadata
                with open(f'metadata_{bank_name}.txt', 'w') as f:
                    f.write(f"Bank: {bank_name}\n")
                    f.write(f"Customer: {customer_name}\n")

                # Mã hóa và lưu từng tham số
                for k, v in user_data.items():
                    # Mã hóa dữ liệu
                    ciphertext = self.encrypt_data(v)
                    serialized = self.serialize_ciphertext(ciphertext)
                    if serialized:
                        # Lưu vào file riêng cho từng tham số
                        with open(f'ciphertext_{bank_name}_{k}.txt', 'wb') as f:
                            f.write(serialized)

                QMessageBox.information(self, "Kết quả", f"Đã mã hóa và lưu dữ liệu thành công!")
            except Exception as e:
                QMessageBox.critical(self, "Lỗi", f"Không thể lưu file: {str(e)}")
            finally:
                self.loading = False
                self.close()

        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Có lỗi xảy ra: {str(e)}")

    def load_public_key(self):
        self.loading = True
        file_name, _ = QFileDialog.getOpenFileName(self, "Chọn file khóa công khai", "", "BINARY Files (*.txt);;All Files (*)")
        if file_name:
            try:
                publicKey, result = fhe.DeserializePublicKey(file_name, fhe.BINARY)
                if not result:
                    raise Exception("Không thể load public key")
                
                # Initialize keys if not exists
                if not hasattr(self.keys, 'publicKey'):
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
                # Initialize crypto context if not exists
                if self.cc is None:
                    self.cc = self.initialize_crypto_context()

                with open(file_name, 'rb') as f:
                    eval_key_bytes = f.read()
                eval_key = fhe.DeserializeEvalKeyString(eval_key_bytes, fhe.BINARY)
                self.cc.InsertEvalMultKey([eval_key])
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

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    sys.exit(app.exec()) 