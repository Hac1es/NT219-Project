import numpy as np
import openfhe as fhe 

# 1. Khởi tạo CKKS
def initialize_ckks():
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

# 2. Hàm mã hóa dữ liệu
def encrypt_data(crypto_context, public_key, data_list):
    # Đảm bảo data_list là một list, ngay cả khi chỉ có 1 giá trị
    if not isinstance(data_list, list):
        data_list = [data_list]
    plaintext = crypto_context.MakeCKKSPackedPlaintext(data_list)
    ciphertext = crypto_context.Encrypt(public_key, plaintext)
    return ciphertext

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
        degree=7  # Reduced from 15 to 7 for sqrt
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
        degree=7  # Reduced from 15 to 7 for sqrt
    )
    return result

def get_third_param(crypto_context, S_length, S_creditmix, B, w3=0.20, w4=0.10):
    w3_p = crypto_context.MakeCKKSPackedPlaintext([w3])
    w4_p = crypto_context.MakeCKKSPackedPlaintext([w4])
    S_length_scaled = crypto_context.EvalMult(S_length, w3_p)
    S_creditmix_scaled = crypto_context.EvalMult(S_creditmix, w4_p)
    S_creditmix_scaledsqed = crypto_context.EvalMult(S_creditmix_scaled, S_creditmix_scaled)
    B_plus = crypto_context.EvalAdd(B, crypto_context.MakeCKKSPackedPlaintext([1.0]))
    B_plus_inverse = crypto_context.EvalDivide(B_plus, 2, np.sqrt(3) + 1, 7)  # Reduced from 15 to 7
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
        degree=10  # Keep higher for log function but reduced from 15
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
    A_plus_inverse = crypto_context.EvalDivide(A_plus, 1, 3, 5)
    final_score = crypto_context.EvalMult(final_score, A_plus_inverse)
    return final_score

# 4. Ví dụ sử dụng
if __name__ == "__main__":
    # Initialize CKKS
    cc, keys = initialize_ckks()

    # Test data for a single user (BatchSize = 1)
    single_user_data = {
        'S_payment': [0.92],           # normalized payment history score
        'S_util': [0.25],              # credit utilization ratio 
        'S_length': [0.72],            # normalized credit length score
        'S_creditmix': [0.65],         # normalized credit mix score
        'S_inquiries': [0.05],         # normalized number of inquiries
        'S_behavioral': [0.88],        # behavioral score
        'S_incomestability': [0.75]    # income stability score
    }

    # Complete set of weights according to the formula
    weights = {
        'w1': 0.35,  # payment history weight
        'w2': 0.30,  # utilization weight
        'w3': 0.20,  # length weight
        'w4': 0.10,  # credit mix weight
        'w5': 0.05,  # inquiries weight
        'w6': 0.03,  # income stability weight
        'w7': 0.02   # behavioral weight
    }

    print("Encrypting data for single user...")
    encrypted_params_single = {
        k: encrypt_data(cc, keys.publicKey, v) for k, v in single_user_data.items()
    }

    print("Computing homomorphic credit score...")
    encrypted_result_single = homomorphic_credit_score(cc, weights, encrypted_params_single)

    print("Decrypting result...")
    result_ptxt_single = cc.Decrypt(keys.secretKey, encrypted_result_single)
    result_ptxt_single.SetLength(1)
    
    # Convert to 300-850 credit score range
    raw_score = result_ptxt_single.GetRealPackedValue()[0]
    credit_score = 300 + (raw_score * 550)  # Map [0,1] to [300,850]
    
    print(f"Credit Score (decrypted): {np.round(credit_score, 2)}")

    # Multiple users example (sequential because BatchSize = 1)
    print("\n--- Processing multiple users sequentially (BatchSize = 1) ---")
    all_users_data = [
        {
            'S_payment': [0.92], 'S_util': [0.25], 'S_length': [0.72],
            'S_creditmix': [0.65], 'S_inquiries': [0.05], 
            'S_behavioral': [0.88], 'S_incomestability': [0.75]
        },
        {
            'S_payment': [0.85], 'S_util': [0.15], 'S_length': [0.45],
            'S_creditmix': [0.70], 'S_inquiries': [0.02],
            'S_behavioral': [0.95], 'S_incomestability': [0.80]
        },
        {
            'S_payment': [0.78], 'S_util': [0.40], 'S_length': [0.90],
            'S_creditmix': [0.55], 'S_inquiries': [0.08],
            'S_behavioral': [0.82], 'S_incomestability': [0.65]
        }
    ]

    all_credit_scores = []
    for i, user_data in enumerate(all_users_data):
        print(f"\nProcessing user {i+1}:")
        try:
            # Encrypt user data
            encrypted_params = {k: encrypt_data(cc, keys.publicKey, v) 
                              for k, v in user_data.items()}
            
            # Compute encrypted score
            encrypted_result = homomorphic_credit_score(cc, weights, encrypted_params)
            
            # Decrypt and convert to credit score range
            result_ptxt = cc.Decrypt(keys.secretKey, encrypted_result)
            result_ptxt.SetLength(1)
            raw_score = result_ptxt.GetRealPackedValue()[0]
            credit_score = 300 + (raw_score * 550)
            
            all_credit_scores.append(np.round(credit_score, 2))
            print(f"Credit Score for user {i+1}: {np.round(credit_score, 2)}")
            
        except Exception as e:
            print(f"Error processing user {i+1}: {str(e)}")

    print("\nAll users' credit scores:", all_credit_scores)
    print("\nProcessing complete!")
    try:
        from PoC_numpy import calculate_credit_score_numpy
        print("\n=== Comparison with NumPy Implementation ===")
        numpy_score = calculate_credit_score_numpy(single_user_data, weights)
        print(f"Credit Score (Homomorphic): {np.round(credit_score, 2)}")
        print(f"Credit Score (NumPy): {numpy_score}")
        print(f"Difference: {abs(credit_score - numpy_score)}")
        print("\nComparison for all users:")
        for i, (homo_score, user_data) in enumerate(zip(all_credit_scores, all_users_data), 1):
            numpy_score = calculate_credit_score_numpy(user_data, weights)
            print(f"\nUser {i}:")
            print(f"Homomorphic: {homo_score}")
            print(f"NumPy: {numpy_score}")
            print(f"Difference: {abs(homo_score - numpy_score)}")
    except ImportError:
        print("NumPy comparison implementation not found")