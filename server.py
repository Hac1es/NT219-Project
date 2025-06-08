from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
import openfhe as fhe
import numpy as np
from typing import Dict, List
import base64
import json
import os
from fastapi.responses import Response
import tempfile
import traceback
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = FastAPI(title="Homomorphic Credit Score Server")

# Import homomorphic computation functions from PoC_new.py
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

# Initialize crypto context
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

# Pydantic models for request validation
class Weights(BaseModel):
    w1: float = 0.35
    w2: float = 0.30
    w3: float = 0.20
    w4: float = 0.10
    w5: float = 0.05
    w6: float = 0.03
    w7: float = 0.02

@app.post("/calculate-credit-score")
async def calculate_credit_score(
    public_key: UploadFile = File(...),
    eval_mult_key: UploadFile = File(...),
    S_payment: UploadFile = File(...),
    S_util: UploadFile = File(...),
    S_length: UploadFile = File(...),
    S_creditmix: UploadFile = File(...),
    S_inquiries: UploadFile = File(...),
    S_behavioral: UploadFile = File(...),
    S_incomestability: UploadFile = File(...),
    weights: str = Form(...)
):
    temp_dir = tempfile.mkdtemp()
    try:
        logger.debug("Starting credit score calculation...")
        logger.debug(f"Created temp directory: {temp_dir}")
        
        # Save uploaded files
        public_key_path = os.path.join(temp_dir, "public_key.txt")
        eval_mult_key_path = os.path.join(temp_dir, "eval_mult_key.txt")
        
        # Save main files
        logger.debug("Saving public key and eval mult key...")
        with open(public_key_path, "wb") as f:
            f.write(await public_key.read())
        with open(eval_mult_key_path, "wb") as f:
            f.write(await eval_mult_key.read())

        # Initialize crypto context
        logger.debug("Initializing crypto context...")
        cc = init_crypto_context()

        # Load public key
        logger.debug("Loading public key...")
        public_key, success = fhe.DeserializePublicKey(public_key_path, fhe.BINARY)
        if not success:
            raise HTTPException(status_code=400, detail="Invalid public key")

        # Load evaluation multiplication key
        logger.debug("Loading evaluation multiplication key...")
        with open(eval_mult_key_path, 'rb') as f:
            eval_key_str = f.read()
        eval_mult_key = fhe.DeserializeEvalKeyString(eval_key_str, fhe.BINARY)
        if not isinstance(eval_mult_key, fhe.EvalKey):
            raise HTTPException(status_code=400, detail="Invalid evaluation multiplication key")

        # Insert evaluation key into context
        logger.debug("Inserting evaluation key into context...")
        cc.InsertEvalMultKey([eval_mult_key])

        # Load encrypted parameters
        logger.debug("Loading encrypted parameters...")
        encrypted_params = {}
        param_files = {
            'S_payment': S_payment,
            'S_util': S_util,
            'S_length': S_length,
            'S_creditmix': S_creditmix,
            'S_inquiries': S_inquiries,
            'S_behavioral': S_behavioral,
            'S_incomestability': S_incomestability
        }

        for key, file in param_files.items():
            logger.debug(f"Processing parameter: {key}")
            param_data = await file.read()
            param = fhe.DeserializeCiphertextString(param_data, fhe.BINARY)
            if not isinstance(param, fhe.Ciphertext):
                raise HTTPException(status_code=400, detail="Invalid ciphertext format.")
            encrypted_params[key] = param

        # Parse weights
        logger.debug("Parsing weights...")
        try:
            weights_dict = json.loads(weights)
            weights_obj = Weights(**weights_dict)
        except Exception as e:
            logger.error(f"Error parsing weights: {str(e)}")
            raise HTTPException(status_code=400, detail=f"Invalid weights format: {str(e)}")

        # Calculate homomorphic credit score
        logger.debug("Calculating homomorphic credit score...")
        encrypted_result = homomorphic_credit_score(cc, weights_obj.model_dump(), encrypted_params)

        # Save result to temporary file
        logger.debug("Saving result...")
        result_path = os.path.join(temp_dir, "result.bin")
        logger.debug(f"Result path: {result_path}")
        
        try:
            result_data = fhe.Serialize(encrypted_result, fhe.BINARY)
            if not result_data:
                logger.error("Failed to serialize result - result_data is None")
                raise HTTPException(status_code=500, detail="Failed to serialize result")
            
            logger.debug(f"Writing {len(result_data)} bytes to result file")
            with open(result_path, "wb") as f:
                f.write(result_data)
            
            if not os.path.exists(result_path):
                logger.error(f"Result file was not created at {result_path}")
                raise HTTPException(status_code=500, detail="Failed to create result file")
            
            logger.debug(f"Result file created successfully at {result_path}")
            
            # Read the file content
            with open(result_path, "rb") as f:
                content = f.read()
            
            # Return the content directly
            logger.debug("Returning result content...")
            return Response(
                content=content,
                media_type="application/octet-stream",
                headers={
                    "Content-Disposition": "attachment; filename=encrypted_result.bin"
                }
            )

        except Exception as e:
            logger.error(f"Error during result serialization/saving: {str(e)}")
            logger.error(traceback.format_exc())
            raise HTTPException(status_code=500, detail=f"Error processing result: {str(e)}")

    except Exception as e:
        logger.error(f"Error in calculate_credit_score: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Clean up temp directory
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="debug") 