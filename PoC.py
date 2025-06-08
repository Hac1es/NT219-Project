import numpy as np
import openfhe as fhe

"""
==============================================================================
CÁC HÀM TÍNH TOÁN ĐỒNG CẤU (GIỮ NGUYÊN)
Các hàm này không thay đổi vì chúng hoạt động trên các bản mã,
không quan tâm đến việc khóa được tạo ra như thế nào.
==============================================================================
"""

def get_A(crypto_context, S_util, S_inquiries):
    S_inquiries_sq = crypto_context.EvalMult(S_inquiries, S_inquiries)
    result = crypto_context.EvalAdd(S_util, S_inquiries_sq)
    return result

def get_B(crypto_context, S_creditmix, S_incomestability):
    total = crypto_context.EvalAdd(S_creditmix, S_incomestability)
    total = crypto_context.EvalAdd(total, crypto_context.MakeCKKSPackedPlaintext([1.0]))
    result = crypto_context.EvalChebyshevFunction(
        func=lambda x: np.sqrt(x),
        ciphertext=total,
        a=1.0,
        b=3.0,
        degree=15
    )
    return result

def get_first_param(crypto_context, S_payment, w1=0.35):
    w1_p = crypto_context.MakeCKKSPackedPlaintext([w1])
    S_payment_scaled = crypto_context.EvalMult(S_payment, w1_p)
    result = crypto_context.EvalMult(S_payment_scaled, S_payment_scaled)
    return result

def get_second_param(crypto_context, S_util, S_behavioral, w2=0.30, w7=0.02):
    w2_p = crypto_context.MakeCKKSPackedPlaintext([w2])
    w7_p = crypto_context.MakeCKKSPackedPlaintext([w7])
    S_util_scaled = crypto_context.EvalMult(S_util, w2_p)
    S_behavioral_scaled = crypto_context.EvalMult(S_behavioral, w7_p)
    S_behavioral_scaled = crypto_context.EvalMult(S_behavioral_scaled, S_behavioral_scaled)
    S_behavioral_scaled = crypto_context.EvalMult(S_behavioral_scaled, crypto_context.MakeCKKSPackedPlaintext([3.0]))
    result = crypto_context.EvalAdd(S_util_scaled, S_behavioral_scaled)
    result = crypto_context.EvalChebyshevFunction(
        func=lambda x: np.sqrt(x),
        ciphertext=result,
        a=0.0,
        b=0.3012,
        degree=15
    )
    return result

def get_third_param(crypto_context, S_length, S_creditmix, B, w3=0.20, w4=0.10):
    w3_p = crypto_context.MakeCKKSPackedPlaintext([w3])
    w4_p = crypto_context.MakeCKKSPackedPlaintext([w4])
    S_length_scaled = crypto_context.EvalMult(S_length, w3_p)
    S_creditmix_scaled = crypto_context.EvalMult(S_creditmix, w4_p)
    S_creditmix_scaledsqed = crypto_context.EvalMult(S_creditmix_scaled, S_creditmix_scaled)
    B_plus = crypto_context.EvalAdd(B, crypto_context.MakeCKKSPackedPlaintext([1.0]))
    B_plus_inverse = crypto_context.EvalChebyshevFunction(lambda x: 1/x, B_plus, 1, 3, 7)
    S_total = crypto_context.EvalAdd(S_length_scaled, S_creditmix_scaledsqed)
    result = crypto_context.EvalMult(S_total, B_plus_inverse)
    return result

def get_fourth_param(crypto_context, S_inquiries, S_incomestability, w5=0.05, w6=0.03):
    w5_p = crypto_context.MakeCKKSPackedPlaintext([w5])
    w6_p = crypto_context.MakeCKKSPackedPlaintext([w6])
    S_inquiries_scaled = crypto_context.EvalMult(S_inquiries, w5_p)
    S_incomestability_scaled = crypto_context.EvalMult(S_incomestability, w6_p)
    S_total = crypto_context.EvalAdd(S_inquiries_scaled, S_incomestability_scaled)
    S_totalplus = crypto_context.EvalAdd(S_total, crypto_context.MakeCKKSPackedPlaintext([1.0]))
    result = crypto_context.EvalChebyshevFunction(
        func=lambda x: np.log(x),
        ciphertext=S_totalplus,
        a=1.0,
        b=1.08,
        degree=15
    )
    return result

def homomorphic_credit_score(crypto_context, weights, encrypted_params):
    weighted_scores = []
    A = get_A(crypto_context, encrypted_params['S_util'], encrypted_params['S_inquiries'])
    B = get_B(crypto_context, encrypted_params['S_creditmix'], encrypted_params['S_incomestability'])
    weighted_scores.append(get_first_param(crypto_context, encrypted_params['S_payment'], weights['w1']))
    weighted_scores.append(get_second_param(crypto_context, encrypted_params['S_util'], encrypted_params['S_behavioral'], weights['w2'], weights['w7']))
    weighted_scores.append(get_third_param(crypto_context, encrypted_params['S_length'], encrypted_params['S_creditmix'], B, weights['w3'], weights['w4']))
    weighted_scores.append(get_fourth_param(crypto_context, encrypted_params['S_inquiries'], encrypted_params['S_incomestability'], weights['w5'], weights['w6']))
    
    # Sum all components
    final_score = weighted_scores[0]
    for score in weighted_scores[1:]:
        final_score = crypto_context.EvalAdd(final_score, score)

    A_plus = crypto_context.EvalAdd(A, crypto_context.MakeCKKSPackedPlaintext([1.0]))
    A_plus_inverse = crypto_context.EvalChebyshevFunction(lambda x: 1/x, A_plus, 1, 3, 5)
    final_score = crypto_context.EvalMult(final_score, A_plus_inverse)
    return final_score

"""
==============================================================================
PHẦN CHÍNH ĐÃ ĐƯỢC SỬA ĐỔI
==============================================================================
"""

if __name__ == "__main__":
    print("--- THRESHOLD FHE DEMO FOR 5 PARTIES ---")
    # 1. Thiết lập môi trường mã hóa chung
    parameters = fhe.CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(15)
    parameters.SetScalingModSize(59)
    parameters.SetBatchSize(1)

    cc = fhe.GenCryptoContext(parameters)
    cc.Enable(fhe.PKESchemeFeature.PKE)
    cc.Enable(fhe.PKESchemeFeature.KEYSWITCH)
    cc.Enable(fhe.PKESchemeFeature.LEVELEDSHE)
    cc.Enable(fhe.PKESchemeFeature.ADVANCEDSHE)
    cc.Enable(fhe.PKESchemeFeature.MULTIPARTY)

    print("\nStep 1: Interactive Key Generation for 5 parties")

    # Mỗi bên sẽ giữ cặp khóa của riêng mình
    keys = [cc.KeyGen() for _ in range(5)]

    # Vòng 1: Bên 1 (A) khởi tạo
    print("  - Party 1 (A) generating initial keys...")
    keys[0] = cc.KeyGen()

    # Các bên còn lại lần lượt tham gia
    for i in range(1, 5):
        print(f"  - Party {i+1} joining...")
        # Bên i+1 nhận khóa công khai chung của i bên trước đó và tham gia
        keys[i] = cc.MultipartyKeyGen(keys[i-1].publicKey)

    # Khóa công khai chung cuối cùng nằm ở bên cuối cùng
    joint_public_key = keys[4].publicKey
    print("Joint Public Key generated successfully.")

    # Tạo khóa đánh giá phép nhân (EvalMultKey) một cách tương tác
    print("\nStep 2: Interactive Evaluation Key Generation")

    # Giai đoạn 1: Tích lũy tiến (Forward accumulation)
    print("  - Forward accumulation phase...")
    eval_mult_keys = []
    # Bên 1 (A) tạo phần khóa đầu tiên
    eval_mult_keys.append(cc.KeySwitchGen(keys[0].secretKey, keys[0].secretKey))

    for i in range(1, 5):
        # Bên i+1 tạo phần khóa riêng
        new_key_part = cc.MultiKeySwitchGen(keys[i].secretKey, keys[i].secretKey, eval_mult_keys[i-1])
        # Kết hợp với khóa tích lũy trước đó
        accumulated_key = cc.MultiAddEvalKeys(eval_mult_keys[i-1], new_key_part, keys[i].publicKey.GetKeyTag())
        eval_mult_keys.append(accumulated_key)

    # Khóa tích lũy cuối cùng
    eval_mult_ab = eval_mult_keys[-1]

    # Giai đoạn 2: Hoàn thiện khóa (Backward finalization)
    print("  - Backward finalization phase...")
    final_key_parts = []
    for i in range(5):
        # Mỗi bên tạo ra thành phần s_i * s_tong
        part = cc.MultiMultEvalKey(keys[i].secretKey, eval_mult_ab, joint_public_key.GetKeyTag())
        final_key_parts.append(part)
        
    # Kết hợp tất cả các thành phần cuối cùng lại
    eval_mult_final = final_key_parts[0]
    for i in range(1, 5):
        eval_mult_final = cc.MultiAddEvalMultKeys(eval_mult_final, final_key_parts[i], eval_mult_final.GetKeyTag())

    # Nạp khóa đánh giá cuối cùng vào môi trường
    cc.InsertEvalMultKey([eval_mult_final])
    print("Joint Evaluation Key generated and inserted.")

    # 2. Dữ liệu đầu vào và mã hóa
    print("\nStep 3: Each party encrypts their data")

    # Giả sử mỗi bên cung cấp một phần dữ liệu
    party_data = {
        'S_payment': [0.92],           # Bên 1
        'S_util': [0.25],              # Bên 2
        'S_length': [0.72],            # Bên 3
        'S_creditmix': [0.65],         # Bên 4
        'S_inquiries': [0.05],         # Bên 5
        # Giả sử 2 tham số còn lại do một bên khác (ví dụ bên 1) cung cấp
        'S_behavioral': [0.88],        # Bên 1
        'S_incomestability': [0.75]    # Bên 1
    }

    encrypted_params = {}
    for key, value in party_data.items():
        print(f"  - Encrypting {key}...")
        encrypted_params[key] = cc.Encrypt(joint_public_key, cc.MakeCKKSPackedPlaintext(value))

    # 3. Tính toán đồng cấu (thực hiện bởi máy chủ)
    print("\nStep 4: Homomorphic credit score computation on the server")
    weights = { 'w1': 0.35, 'w2': 0.30, 'w3': 0.20, 'w4': 0.10, 'w5': 0.05, 'w6': 0.03, 'w7': 0.02 }
    encrypted_result = homomorphic_credit_score(cc, weights, encrypted_params)

    # 4. Giải mã ngưỡng
    print("\nStep 5: Threshold Decryption")

    # Mỗi bên tạo ra một bản giải mã một phần
    print("  - Parties generating partial decryptions...")
    partial_decryptions = []
    # Bên 1 là "Lead"
    partial_decryptions.append(cc.MultipartyDecryptLead([encrypted_result], keys[0].secretKey)[0])
    # Các bên còn lại là "Main"
    for i in range(1, 5):
        partial_decryptions.append(cc.MultipartyDecryptMain([encrypted_result], keys[i].secretKey)[0])

    # Tổng hợp các bản giải mã một phần
    print("  - Fusing partial decryptions...")
    result_ptxt = cc.MultipartyDecryptFusion(partial_decryptions)
    result_ptxt.SetLength(1)

    # 5. Hiển thị kết quả
    raw_score = result_ptxt.GetRealPackedValue()[0]
    credit_score = 300 + (raw_score * 550)

    print("\n--- FINAL RESULT ---")
    print(f"Decrypted Credit Score: {np.round(credit_score, 2)}")