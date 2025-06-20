import requests

files = {
    'public_key': open('keys_TCB/TCB_publicKey.txt', 'rb'),
    'eval_mult_key': open('keys_TCB/evalMultKey_merged.txt', 'rb'),
    'S_payment': open('ciphertext_ACB_S_payment.txt', 'rb'),
    'S_util': open('ciphertext_ACB_S_util.txt', 'rb'),
    'S_length': open('ciphertext_MSB_S_length.txt', 'rb'),
    'S_creditmix': open('ciphertext_MSB_S_creditmix.txt', 'rb'),
    'S_inquiries': open('ciphertext_TCB_S_inquiries.txt', 'rb'),
    'S_behavioral': open('ciphertext_TCB_S_behavioral.txt', 'rb'),
    'S_incomestability': open('ciphertext_TCB_S_incomestability.txt', 'rb')
}

response = requests.post('http://localhost:8000/calculate-credit-score', files=files)

# Kiểm tra status code
if response.status_code == 200:
    # Lưu kết quả vào file
    with open('encrypted_result.txt', 'wb') as f:
        f.write(response.content)
    print("Kết quả đã được lưu vào file 'encrypted_result.txt'")
else:
    print(f"Lỗi: {response.status_code}")
    print(response.text)