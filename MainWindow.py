import sys
import os
import numpy as np
import openfhe as fhe
from PyQt6 import QtWidgets, uic
from PyQt6.QtWidgets import QFileDialog, QMessageBox

# Set platform plugin
os.environ["QT_QPA_PLATFORM"] = "xcb"

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        # Load the UI file
        uic.loadUi("MainWindow.ui", self)
        
        # Initialize CKKS
        self.cc, self.keys = self.initialize_ckks()
        
        # Connect signals and slots here
        self.pushButton.clicked.connect(self.select_file)
        self.pushButton_2.clicked.connect(self.send_data)
        
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

        keys = crypto_context.KeyGen()
        crypto_context.EvalMultKeyGen(keys.secretKey)

        return crypto_context, keys

    def encrypt_data(self, data_list):
        if not isinstance(data_list, list):
            data_list = [data_list]
        plaintext = self.cc.MakeCKKSPackedPlaintext(data_list)
        ciphertext = self.cc.Encrypt(self.keys.publicKey, plaintext)
        return ciphertext

    def get_A(self, S_util, S_inquiries):
        S_inquiries_sq = self.cc.EvalMult(S_inquiries, S_inquiries)
        result = self.cc.EvalAdd(S_util, S_inquiries_sq)
        return result

    def get_B(self, S_creditmix, S_incomestability):
        total = self.cc.EvalAdd(S_creditmix, S_incomestability)
        total = self.cc.EvalAdd(total, self.cc.MakeCKKSPackedPlaintext([1.0]))
        result = self.cc.EvalChebyshevFunction(
            func=lambda x: np.sqrt(x),
            ciphertext=total,
            a=1.0,
            b=3.0,
            degree=15 
        )
        return result

    def get_first_param(self, S_payment, w1=0.35):
        w1_p = self.cc.MakeCKKSPackedPlaintext([w1])
        S_payment_scaled = self.cc.EvalMult(S_payment, w1_p)
        result = self.cc.EvalMult(S_payment_scaled, S_payment_scaled)
        return result

    def get_second_param(self, S_util, S_behavioral, w2=0.30, w7=0.02):
        w2_p = self.cc.MakeCKKSPackedPlaintext([w2])
        w7_p = self.cc.MakeCKKSPackedPlaintext([w7])
        S_util_scaled = self.cc.EvalMult(S_util, w2_p)
        S_behavioral_scaled = self.cc.EvalMult(S_behavioral, w7_p)
        S_behavioral_scaled = self.cc.EvalMult(S_behavioral_scaled, S_behavioral_scaled)
        S_behavioral_scaled = self.cc.EvalMult(S_behavioral_scaled, self.cc.MakeCKKSPackedPlaintext([3.0]))
        result = self.cc.EvalAdd(S_util_scaled, S_behavioral_scaled)
        result = self.cc.EvalChebyshevFunction(
            func=lambda x: np.sqrt(x),
            ciphertext=result,
            a=0.0,
            b=0.3012,
            degree=15
        )
        return result

    def get_third_param(self, S_length, S_creditmix, B, w3=0.20, w4=0.10):
        w3_p = self.cc.MakeCKKSPackedPlaintext([w3])
        w4_p = self.cc.MakeCKKSPackedPlaintext([w4])
        S_length_scaled = self.cc.EvalMult(S_length, w3_p)
        S_creditmix_scaled = self.cc.EvalMult(S_creditmix, w4_p)
        S_creditmix_scaledsqed = self.cc.EvalMult(S_creditmix_scaled, S_creditmix_scaled)
        B_plus = self.cc.EvalAdd(B, self.cc.MakeCKKSPackedPlaintext([1.0]))
        B_plus_inverse = self.cc.EvalDivide(B_plus, 2, np.sqrt(3) + 1, 7)
        S_total = self.cc.EvalAdd(S_length_scaled, S_creditmix_scaledsqed)
        result = self.cc.EvalMult(S_total, B_plus_inverse)
        return result
    
    def get_fourth_param(self, S_inquiries, S_incomestability, w5=0.05, w6=0.03):
        w5_p = self.cc.MakeCKKSPackedPlaintext([w5])
        w6_p = self.cc.MakeCKKSPackedPlaintext([w6])
        S_inquiries_scaled = self.cc.EvalMult(S_inquiries, w5_p)
        S_incomestability_scaled = self.cc.EvalMult(S_incomestability, w6_p)
        S_total = self.cc.EvalAdd(S_inquiries_scaled, S_incomestability_scaled)
        S_totalplus = self.cc.EvalAdd(S_total, self.cc.MakeCKKSPackedPlaintext([1.0]))
        result = self.cc.EvalChebyshevFunction(
            func=lambda x: np.log(x),
            ciphertext=S_totalplus,
            a=1.0,
            b=1.08,
            degree=15
        )
        return result

    def calculate_credit_score(self, encrypted_params):
        weights = {
            'w1': 0.35,  # payment history weight
            'w2': 0.30,  # utilization weight
            'w3': 0.20,  # length weight
            'w4': 0.10,  # credit mix weight
            'w5': 0.05,  # inquiries weight
            'w6': 0.03,  # income stability weight
            'w7': 0.02   # behavioral weight
        }

        A = self.get_A(encrypted_params['S_util'], encrypted_params['S_inquiries'])
        B = self.get_B(encrypted_params['S_creditmix'], encrypted_params['S_incomestability'])
        
        weighted_scores = []
        weighted_scores.append(self.get_first_param(encrypted_params['S_payment'], weights['w1']))
        weighted_scores.append(self.get_second_param(encrypted_params['S_util'], encrypted_params['S_behavioral'], weights['w2'], weights['w7']))
        weighted_scores.append(self.get_third_param(encrypted_params['S_length'], encrypted_params['S_creditmix'], B, weights['w3'], weights['w4']))
        weighted_scores.append(self.get_fourth_param(encrypted_params['S_inquiries'], encrypted_params['S_incomestability'], weights['w5'], weights['w6']))
        
        final_score = weighted_scores[0]
        for score in weighted_scores[1:]:
            final_score = self.cc.EvalAdd(final_score, score)
        
        A_plus = self.cc.EvalAdd(A, self.cc.MakeCKKSPackedPlaintext([1.0]))
        A_plus_inverse = self.cc.EvalDivide(A_plus, 1, 3, 5)
        final_score = self.cc.EvalMult(final_score, A_plus_inverse)
        
        return final_score

    def select_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Chọn file khóa công khai", "", "All Files (*)")
        if file_name:
            self.pushButton.setText(os.path.basename(file_name))
            # TODO: Implement public key loading logic

    def send_data(self):
        try:
            # Get values from text fields
            payment_history = float(self.textEdit.toPlainText() or "0")
            credit_util = float(self.textEdit_2.toPlainText() or "0")
            credit_age = float(self.textEdit_3.toPlainText() or "0")
            credit_mix = float(self.textEdit_4.toPlainText() or "0")
            credit_inquiries = float(self.textEdit_5.toPlainText() or "0")
            income_stability = float(self.textEdit_6.toPlainText() or "0")
            financial_behavior = float(self.textEdit_7.toPlainText() or "0")
            customer_name = self.textEdit_8.toPlainText()

            # Prepare data
            user_data = {
                'S_payment': [payment_history],
                'S_util': [credit_util],
                'S_length': [credit_age],
                'S_creditmix': [credit_mix],
                'S_inquiries': [credit_inquiries],
                'S_behavioral': [financial_behavior],
                'S_incomestability': [income_stability]
            }

            # Encrypt data
            encrypted_params = {k: self.encrypt_data(v) for k, v in user_data.items()}
            
            # Calculate credit score
            encrypted_result = self.calculate_credit_score(encrypted_params)
            
            # Decrypt result
            result_ptxt = self.cc.Decrypt(self.keys.secretKey, encrypted_result)
            result_ptxt.SetLength(1)
            raw_score = result_ptxt.GetRealPackedValue()[0]
            credit_score = 300 + (raw_score * 550)  # Map [0,1] to [300,850]
            
            # Show result
            QMessageBox.information(self, "Kết quả", 
                f"Khách hàng: {customer_name}\n"
                f"Ngân hàng: {self.comboBox.currentText()}\n"
                f"Điểm tín dụng: {np.round(credit_score, 2)}")

        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Có lỗi xảy ra: {str(e)}")

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    sys.exit(app.exec())
