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

    def aggregate_files(self):
        """Aggregate multiple encrypted files into one"""
        try:
            # Chọn các file cần gộp
            files, _ = QFileDialog.getOpenFileNames(
                self,
                "Chọn các file cần gộp",
                "",
                "Binary Files (*.bin);;All Files (*)"
            )
            
            if not files:
                return None

            # Đọc và gộp metadata từ file đầu tiên
            with open(files[0], 'rb') as f:
                content = f.read()
                metadata_end = content.find(b"\n\n")
                if metadata_end == -1:
                    raise Exception("Không tìm thấy metadata trong file")
                metadata = content[:metadata_end + 2]

            # Tạo file mới để ghi kết quả
            output_file = "aggregated_ciphertext.bin"
            with open(output_file, 'wb') as out_f:
                # Ghi metadata
                out_f.write(metadata)

                # Gộp các ciphertext từ các file
                seen_ciphertexts = set()
                for file_path in files:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        # Bỏ qua metadata
                        content = content[content.find(b"\n\n") + 2:]
                        
                        # Tìm và ghi từng ciphertext
                        while True:
                            start = content.find(b"-----BEGIN CIPHERTEXT")
                            if start == -1:
                                break
                            
                            end = content.find(b"-----END CIPHERTEXT", start)
                            if end == -1:
                                break
                            
                            # Lấy tên ciphertext
                            ciphertext_name = content[start:content.find(b"\n", start)].decode('utf-8')
                            if ciphertext_name not in seen_ciphertexts:
                                seen_ciphertexts.add(ciphertext_name)
                                # Ghi toàn bộ ciphertext
                                out_f.write(content[start:end + len(b"-----END CIPHERTEXT") + 2])
                            
                            content = content[end + len(b"-----END CIPHERTEXT") + 2:]

                # Thêm public key và eval mult key
                if hasattr(self.keys, 'publicKey'):
                    serialized_public_key = fhe.Serialize(self.keys.publicKey, fhe.BINARY)
                    out_f.write(b"-----BEGIN PUBLIC KEY-----\n")
                    out_f.write(serialized_public_key)
                    out_f.write(b"\n-----END PUBLIC KEY-----\n\n")

                    if self.cc:
                        eval_mult_key = self.cc.SerializeEvalMultKey("", fhe.BINARY)
                        if eval_mult_key:
                            out_f.write(b"-----BEGIN EVAL MULT KEY-----\n")
                            out_f.write(eval_mult_key)
                            out_f.write(b"\n-----END EVAL MULT KEY-----\n")

            return output_file

        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi gộp file: {str(e)}")
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

            # Nếu là aggregator, thực hiện gộp file
            if self.isAggregator.isChecked():
                output_file = self.aggregate_files()
                if output_file:
                    QMessageBox.information(self, "Thành công", f"Đã gộp các file vào {output_file}")
                return

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
                with open(f'ciphertext_{bank_name}.bin', "rb") as f:
                    data = f.read()

                # Hash và ký
                signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

                # Lưu chữ ký
                with open(f'ciphertext_{bank_name}.bin.sig', "wb") as f:
                    f.write(signature)

                QMessageBox.information(self, "Kết quả", f"Đã mã hóa và lưu dữ liệu vào file ciphertext_{bank_name}.bin")
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