import numpy as np
import openfhe as fhe
import time
from datetime import datetime
import os

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

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
    
    final_score = weighted_scores[0]
    for score in weighted_scores[1:]:
        final_score = crypto_context.EvalAdd(final_score, score)
    
    A_plus = crypto_context.EvalAdd(A, crypto_context.MakeCKKSPackedPlaintext([1.0]))
    A_plus_inverse = crypto_context.EvalChebyshevFunction(lambda x: 1/x, A_plus, 1, 3, 5)
    final_score = crypto_context.EvalMult(final_score, A_plus_inverse)
    return final_score

def plaintext_credit_score(weights, params):
    A = params['S_util'] + params['S_inquiries']**2
    B = np.sqrt(params['S_creditmix'] + params['S_incomestability'] + 1.0)
    p1 = (params['S_payment'] * weights['w1'])**2
    p2 = np.sqrt(params['S_util'] * weights['w2'] + 3 * (params['S_behavioral'] * weights['w7'])**2)
    p3 = (params['S_length'] * weights['w3'] + (params['S_creditmix'] * weights['w4'])**2) / (B + 1)
    p4 = np.log(params['S_inquiries'] * weights['w5'] + params['S_incomestability'] * weights['w6'] + 1)
    raw_score = (p1 + p2 + p3 + p4) / (A + 1)
    return raw_score

def generate_test_cases(num_cases=10):
    test_cases = []
    for _ in range(num_cases):
        case = {
            'S_payment': [np.random.uniform(0.5, 1.0)],
            'S_util': [np.random.uniform(0.1, 0.9)],
            'S_length': [np.random.uniform(0.3, 1.0)],
            'S_creditmix': [np.random.uniform(0.3, 0.9)],
            'S_inquiries': [np.random.uniform(0.0, 0.2)],
            'S_behavioral': [np.random.uniform(0.5, 1.0)],
            'S_incomestability': [np.random.uniform(0.3, 0.9)]
        }
        test_cases.append(case)
    return test_cases

def run_benchmark():
    print("=== Starting FHE Credit Score Benchmark ===")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Create results directory
    results_dir = "benchmark_results"
    ensure_dir(results_dir)
    
    # Initialize FHE parameters
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

    # Generate keys
    print("\nGenerating keys...")
    keys = [cc.KeyGen() for _ in range(5)]
    for i in range(1, 5):
        keys[i] = cc.MultipartyKeyGen(keys[i-1].publicKey)
    joint_public_key = keys[4].publicKey

    # Generate evaluation keys
    eval_mult_keys = []
    eval_mult_keys.append(cc.KeySwitchGen(keys[0].secretKey, keys[0].secretKey))
    for i in range(1, 5):
        new_key_part = cc.MultiKeySwitchGen(keys[i].secretKey, keys[i].secretKey, eval_mult_keys[i-1])
        accumulated_key = cc.MultiAddEvalKeys(eval_mult_keys[i-1], new_key_part, keys[i].publicKey.GetKeyTag())
        eval_mult_keys.append(accumulated_key)
    
    eval_mult_ab = eval_mult_keys[-1]
    final_key_parts = []
    for i in range(5):
        part = cc.MultiMultEvalKey(keys[i].secretKey, eval_mult_ab, joint_public_key.GetKeyTag())
        final_key_parts.append(part)
    
    eval_mult_final = final_key_parts[0]
    for i in range(1, 5):
        eval_mult_final = cc.MultiAddEvalMultKeys(eval_mult_final, final_key_parts[i], eval_mult_final.GetKeyTag())
    cc.InsertEvalMultKey([eval_mult_final])

    # Generate test cases
    test_cases = generate_test_cases(10)
    weights = {'w1': 0.35, 'w2': 0.30, 'w3': 0.20, 'w4': 0.10, 'w5': 0.05, 'w6': 0.03, 'w7': 0.02}
    
    # Initialize results storage
    results = []
    
    # Run benchmark for each test case
    for i, test_case in enumerate(test_cases, 1):
        print(f"\nRunning test case {i}/10...")
        
        # Time encryption
        encrypt_start = time.time()
        encrypted_params = {}
        for key, value in test_case.items():
            encrypted_params[key] = cc.Encrypt(joint_public_key, cc.MakeCKKSPackedPlaintext(value))
        encrypt_time = time.time() - encrypt_start
        
        # Time computation
        compute_start = time.time()
        encrypted_result = homomorphic_credit_score(cc, weights, encrypted_params)
        compute_time = time.time() - compute_start
        
        # Time decryption
        decrypt_start = time.time()
        partial_decryptions = []
        partial_decryptions.append(cc.MultipartyDecryptLead([encrypted_result], keys[0].secretKey)[0])
        for j in range(1, 5):
            partial_decryptions.append(cc.MultipartyDecryptMain([encrypted_result], keys[j].secretKey)[0])
        result_ptxt = cc.MultipartyDecryptFusion(partial_decryptions)
        result_ptxt.SetLength(1)
        decrypt_time = time.time() - decrypt_start
        
        # Get FHE result
        raw_score = result_ptxt.GetRealPackedValue()[0]
        fhe_credit_score = 300 + (raw_score * 550)
        
        # Get plaintext result
        plaintext_raw_score = plaintext_credit_score(weights, {k: v[0] for k, v in test_case.items()})
        plaintext_credit_score_value = 300 + (plaintext_raw_score * 550)
        
        # Calculate difference
        difference = abs(fhe_credit_score - plaintext_credit_score_value)
        
        # Store results
        results.append({
            'case': i,
            'encrypt_time': encrypt_time,
            'compute_time': compute_time,
            'decrypt_time': decrypt_time,
            'fhe_score': fhe_credit_score,
            'plaintext_score': plaintext_credit_score_value,
            'difference': difference
        })
        
        print(f"  Encryption time: {encrypt_time:.3f}s")
        print(f"  Computation time: {compute_time:.3f}s")
        print(f"  Decryption time: {decrypt_time:.3f}s")
        print(f"  FHE Score: {fhe_credit_score:.2f}")
        print(f"  Plaintext Score: {plaintext_credit_score_value:.2f}")
        print(f"  Difference: {difference:.6f}")
    
    # Calculate and print summary statistics
    print("\n=== Benchmark Summary ===")
    avg_encrypt = np.mean([r['encrypt_time'] for r in results])
    avg_compute = np.mean([r['compute_time'] for r in results])
    avg_decrypt = np.mean([r['decrypt_time'] for r in results])
    avg_diff = np.mean([r['difference'] for r in results])
    max_diff = max([r['difference'] for r in results])
    
    print(f"Average Encryption Time: {avg_encrypt:.3f}s")
    print(f"Average Computation Time: {avg_compute:.3f}s")
    print(f"Average Decryption Time: {avg_decrypt:.3f}s")
    print(f"Average Difference: {avg_diff:.6f}")
    print(f"Maximum Difference: {max_diff:.6f}")
    
    # Save results to file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    results_file = os.path.join(results_dir, f'benchmark_results_{timestamp}.txt')
    
    with open(results_file, 'w') as f:
        f.write("=== FHE Credit Score Benchmark Results ===\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        for result in results:
            f.write(f"Test Case {result['case']}:\n")
            f.write(f"  Encryption time: {result['encrypt_time']:.3f}s\n")
            f.write(f"  Computation time: {result['compute_time']:.3f}s\n")
            f.write(f"  Decryption time: {result['decrypt_time']:.3f}s\n")
            f.write(f"  FHE Score: {result['fhe_score']:.2f}\n")
            f.write(f"  Plaintext Score: {result['plaintext_score']:.2f}\n")
            f.write(f"  Difference: {result['difference']:.6f}\n\n")
        
        f.write("=== Summary Statistics ===\n")
        f.write(f"Average Encryption Time: {avg_encrypt:.3f}s\n")
        f.write(f"Average Computation Time: {avg_compute:.3f}s\n")
        f.write(f"Average Decryption Time: {avg_decrypt:.3f}s\n")
        f.write(f"Average Difference: {avg_diff:.6f}\n")
        f.write(f"Maximum Difference: {max_diff:.6f}\n")
    
    print(f"\nResults saved to: {results_file}")

if __name__ == "__main__":
    run_benchmark() 