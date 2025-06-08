import pickle
import base64
import openfhe as fhe
import os

def serialize_object(obj):
    """Serialize an object to a base64-encoded string using pickle"""
    serialized = pickle.dumps(obj)
    return base64.b64encode(serialized).decode('utf-8')

def deserialize_object(serialized_str):
    """Deserialize a base64-encoded string back to an object using pickle"""
    return pickle.loads(base64.b64decode(serialized_str.encode('utf-8')))

def serialize_to_file(obj, file_path, format_type=fhe.BINARY):
    """Save an OpenFHE object to a file"""
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory)
        
    if isinstance(obj, fhe.PublicKey):
        success = fhe.SerializeToFile(file_path, obj, format_type)
        return success
    elif isinstance(obj, fhe.PrivateKey):

        success = fhe.SerializeToFile(file_path, obj, format_type)
        return success
    elif isinstance(obj, fhe.Ciphertext):
        # Use SerializeCiphertextToFile from OpenFHE Python bindings
        with open(file_path, 'wb') as f:
            serialized_data = fhe.SerializeCiphertext(obj, format_type)
            f.write(serialized_data)
        return True
    elif isinstance(obj, fhe.EvalKey):
        success = fhe.SerializeToFile(file_path, obj, format_type)
        return success
    else:
        with open(file_path, 'wb') as f:
            pickle.dump(obj, f)
        return True

def deserialize_from_file(file_path, obj_type, format_type=fhe.BINARY):
    """Load an OpenFHE object from a file"""
    if not os.path.exists(file_path):
        return None, False
        
    try:
        if obj_type == 'public_key':
            # Use DeserializePublicKeyFromFile from OpenFHE Python bindings
            public_key, success = fhe.DeserializeFromFile(file_path, format_type)
            return public_key, success
            
        elif obj_type == 'private_key':
            # Use DeserializePrivateKeyFromFile from OpenFHE Python bindings
            private_key, success = fhe.DeserializeFromFile(file_path, format_type)
            return private_key, success
            
        elif obj_type == 'ciphertext':
            # Use DeserializeCiphertextFromFile from OpenFHE Python bindings
            with open(file_path, 'rb') as f:
                ct_bytes = f.read()
            return fhe.DeserializeCiphertext(ct_bytes, format_type)
            
        elif obj_type == 'eval_key':
            # Use DeserializeEvalKeyFromFile from OpenFHE Python bindings
            eval_key, success = fhe.DeserializeFromFile(file_path, format_type)
            return eval_key, success
            
        else:
            with open(file_path, 'rb') as f:
                return pickle.load(f), True
    except Exception as e:
        print(f"Error during deserialization: {str(e)}")
        return None, False