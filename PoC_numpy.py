import numpy as np

def calculate_credit_score_numpy(user_data, weights):
    """
    Calculate credit score using regular numpy operations
    Formula: FICO_Sum = (1/(A+1)) * [
        (S_payment * W1)^2 + 
        sqrt(S_util * W2 + 3*(S_behavioral * W7)^2) + 
        ((S_length * W3 + (S_creditmix * W4)^2)/(B+1)) + 
        log(1 + S_inquiries * W5 + S_income_stability * W6)
    ]
    where:
    A = S_util + S_inquiries^2
    B = sqrt(S_creditmix + S_income_stability + 1)
    """
    # Extract values (removing list wrapper)
    S_payment = user_data['S_payment'][0]
    S_util = user_data['S_util'][0]
    S_length = user_data['S_length'][0]
    S_creditmix = user_data['S_creditmix'][0]
    S_inquiries = user_data['S_inquiries'][0]
    S_behavioral = user_data['S_behavioral'][0]
    S_incomestability = user_data['S_incomestability'][0]

    # Calculate A
    A = S_util + (S_inquiries ** 2)
    
    # Calculate B
    B = np.sqrt(S_creditmix + S_incomestability + 1)

    # Calculate each component
    first_param = (S_payment * weights['w1']) ** 2
    
    second_param = np.sqrt(
        S_util * weights['w2'] + 
        3 * (S_behavioral * weights['w7']) ** 2
    )
    
    third_param = (
        S_length * weights['w3'] + 
        (S_creditmix * weights['w4']) ** 2
    ) / (B + 1)
    
    fourth_param = np.log(
        1 + 
        S_inquiries * weights['w5'] + 
        S_incomestability * weights['w6']
    )

    # Combine all parameters
    numerator = first_param + second_param + third_param + fourth_param
    denominator = A + 1
    
    raw_score = numerator / denominator
    
    # Convert to credit score range (300-850)
    credit_score = 300 + (raw_score * 550)
    
    return np.round(credit_score, 2)

# Test with the same data
if __name__ == "__main__":
    # Single user test
    single_user_data = {
        'S_payment': [0.92],
        'S_util': [0.25],
        'S_length': [0.72],
        'S_creditmix': [0.65],
        'S_inquiries': [0.05],
        'S_behavioral': [0.88],
        'S_incomestability': [0.75]
    }

    weights = {
        'w1': 0.35,
        'w2': 0.30,
        'w3': 0.20,
        'w4': 0.10,
        'w5': 0.05,
        'w6': 0.03,
        'w7': 0.02
    }

    print("\n=== Regular NumPy Calculation ===")
    numpy_score = calculate_credit_score_numpy(single_user_data, weights)
    print(f"Credit Score (NumPy): {numpy_score}")

    # Test with multiple users
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

    print("\n=== Processing Multiple Users ===")
    numpy_scores = []
    for i, user_data in enumerate(all_users_data, 1):
        score = calculate_credit_score_numpy(user_data, weights)
        numpy_scores.append(score)
        print(f"User {i} Credit Score (NumPy): {score}")

    print("\nAll NumPy credit scores:", numpy_scores)