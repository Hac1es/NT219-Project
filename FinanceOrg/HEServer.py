import os
import json
import base64
import shutil
import tempfile
import logging
import traceback
from pathlib import Path
from typing import Dict, List, Any

from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import Response, JSONResponse

import openfhe as fhe
import numpy as np
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

# --- CONFIGURATION ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Secure Homomorphic Credit Score Server")

CUSTOM_CA_PATH = "./Certificate/RootCA.crt" 
if not os.path.exists(CUSTOM_CA_PATH):
    raise FileNotFoundError(f"RootCA file not found at: {CUSTOM_CA_PATH}")

# --- SECURITY VERIFICATION FUNCTIONS ---
def verify_certificate_signed_by_root(cert: x509.Certificate, root_cert: x509.Certificate) -> bool:
    try:
        root_pubkey = root_cert.public_key()
        root_pubkey.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm)
        )
        return True
    except Exception:
        return False

# --- HOMOMORPHIC COMPUTATION FUNCTIONS (Không thay đổi) ---
# ... (Giữ nguyên toàn bộ các hàm get_A, get_B, get_first_param, etc.)
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

def init_crypto_context():
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
    return cc

# --- MAIN API ENDPOINT ---
@app.post("/calculate-credit-score")
async def calculate_credit_score(
    public_key: UploadFile = File(...), eval_mult_key: UploadFile = File(...),
    S_payment: UploadFile = File(...), S_util: UploadFile = File(...), S_length: UploadFile = File(...),
    S_creditmix: UploadFile = File(...), S_inquiries: UploadFile = File(...),
    S_behavioral: UploadFile = File(...), S_incomestability: UploadFile = File(...),
    certificate: UploadFile = File(...),
    signature: str = Form(...),
    metadata: str = Form("{}")
):
    logger.info("Received request for credit score calculation.")
    
    # Gom tất cả các file dữ liệu FHE vào một dict riêng
    fhe_data_files = {
        'public_key': public_key, 'eval_mult_key': eval_mult_key,
        'S_payment': S_payment, 'S_util': S_util, 'S_length': S_length,
        'S_creditmix': S_creditmix, 'S_inquiries': S_inquiries,
        'S_behavioral': S_behavioral, 'S_incomestability': S_incomestability
    }

    # Đọc nội dung file
    file_contents: Dict[str, bytes] = {}
    try:
        # Đọc các file dữ liệu FHE
        for key, upload_file in fhe_data_files.items():
            file_contents[key] = await upload_file.read()
        
        # Đọc riêng file certificate và metadata
        cert_pem_bytes = await certificate.read()
        metadata_dict = json.loads(metadata)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid file or metadata format.")

    # === LỚP BẢO VỆ 1: XÁC THỰC CERTIFICATE ===
    logger.info("Verifying sender's certificate...")
    try:
        cert = x509.load_pem_x509_certificate(cert_pem_bytes)
        client_public_key = cert.public_key()

        if not isinstance(client_public_key, ec.EllipticCurvePublicKey):
            raise HTTPException(status_code=400, detail="Certificate must use an Elliptic Curve key.")

        with open(CUSTOM_CA_PATH, "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())

        if not verify_certificate_signed_by_root(cert, root_cert):
            logger.warning("Certificate verification failed: Not signed by trusted RootCA.")
            raise HTTPException(status_code=403, detail="Certificate not signed by the trusted RootCA.")
        
        logger.info("Certificate is valid and trusted.")
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error processing certificate: {e}")
        raise HTTPException(status_code=400, detail=f"Certificate processing error: {e}")

    # === LỚP BẢO VỆ 2: XÁC MINH CHỮ KÝ SỐ (ĐÃ SỬA LẠI LOGIC) ===
    logger.info("Verifying digital signature...")
    try:
        # SỬA ĐỔI CHÍNH Ở ĐÂY
        # Tái tạo dữ liệu đã ký, chỉ bao gồm các file dữ liệu FHE, KHÔNG BAO GỒM certificate.
        data_to_verify = b''
        # Sắp xếp các key của file dữ liệu để đảm bảo thứ tự nhất quán
        for key in sorted(file_contents.keys()):
            data_to_verify += file_contents[key]
        
        # Thêm metadata đã được chuẩn hóa vào cuối
        data_to_verify += json.dumps(metadata_dict, sort_keys=True).encode('utf-8')
        
        decoded_sig = base64.b64decode(signature)

        client_public_key.verify( # Dùng public key từ certificate đã được xác thực
            decoded_sig,
            data_to_verify,
            ec.ECDSA(hashes.SHA256())
        )
        logger.info("Digital signature is valid.")
    except InvalidSignature:
        logger.warning("Signature verification failed: Invalid signature.")
        raise HTTPException(status_code=403, detail="Invalid digital signature.")
    except Exception as e:
        logger.error(f"Error verifying signature: {e}")
        raise HTTPException(status_code=400, detail=f"Error during signature verification: {e}")

    # === BẮT ĐẦU XỬ LÝ FHE (SAU KHI ĐÃ AN TOÀN) ===
    logger.info("Security checks passed. Starting homomorphic computation.")
    try:
        cc = init_crypto_context()
        fhe_pk, success = fhe.DeserializePublicKeyString(file_contents['public_key'], fhe.BINARY)
        if not success: raise ValueError("Invalid FHE public key")
        
        eval_mult_key = fhe.DeserializeEvalKeyString(file_contents['eval_mult_key'], fhe.BINARY)
        if not isinstance(eval_mult_key, fhe.EvalKey): raise ValueError("Invalid FHE evaluation key")
        cc.InsertEvalMultKey([eval_mult_key])
        
        encrypted_params: Dict[str, Any] = {}
        for key in [k for k in file_contents.keys() if k.startswith('S_')]:
            param = fhe.DeserializeCiphertextString(file_contents[key], fhe.BINARY)
            if not isinstance(param, fhe.Ciphertext): raise ValueError(f"Invalid ciphertext for {key}")
            encrypted_params[key] = param

        weights = {
            'w1': 0.35, 'w2': 0.30, 'w3': 0.20, 'w4': 0.10, 
            'w5': 0.05, 'w6': 0.03, 'w7': 0.02
        }

        logger.info("Calculating final encrypted score...")
        encrypted_result = homomorphic_credit_score(cc, weights, encrypted_params)

        result_data = fhe.Serialize(encrypted_result, fhe.BINARY)
        if not result_data:
            raise HTTPException(status_code=500, detail="Failed to serialize FHE result.")
        
        logger.info("Computation successful. Returning encrypted result.")
        return Response(
            content=result_data,
            media_type="application/octet-stream",
            headers={"Content-Disposition": "attachment; filename=encrypted_result.bin"}
        )

    except Exception as e:
        logger.error(f"Error during FHE processing: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"An error occurred during homomorphic computation: {e}")

# --- KHỞI CHẠY SERVER VỚI HTTPS ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000, 
        log_level="info",
        ssl_keyfile="./Certificate/FECREDIT.key",
        ssl_certfile="./Certificate/FECREDIT.crt"
    )