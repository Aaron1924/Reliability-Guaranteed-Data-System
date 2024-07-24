from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import hashlib

# Step 1: DP uses make_proc function and procedure :≡ to produce MD in digital form.
def make_proc(raw_data):
    return raw_data.encode('utf-8')

# Step 2: DP creates the identifier of MD using a cryptographic hash function
def create_identifier(md):
    return hashlib.sha256(md).hexdigest()

# Step 3: DP performs Rand_Key to generate a key
def generate_random_key():
    return get_random_bytes(32)  # 256-bit key

# Step 4: DP encrypts MD using K and an encryption algorithm
def encrypt_md(md, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(md)
    return cipher.nonce, ciphertext, tag

# Step 5: DP encrypts DP’s IdDP and K using PKDO and PCS
def encrypt_with_public_key(data, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(data)

# Step 6: DP encrypts DPInfo and IdMD using PKRM and PCS
def encrypt_dp_info(dp_info, id_md, public_key):
    combined_data = dp_info + id_md.encode('utf-8')
    encrypted_data = b""
    max_chunk_size = 190  # Adjusted for RSA encryption limit

    for i in range(0, len(combined_data), max_chunk_size):
        chunk = combined_data[i:i + max_chunk_size]
        encrypted_data += encrypt_with_public_key(chunk, public_key)

    return encrypted_data

# Step 7: DP generates a signature on EMD
def sign_data(data, private_key):
    h = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

# Main function to simulate the Data Producing Scheme
def data_producing_scheme(raw_data, dp_id, dp_private_key, do_public_key, rm_public_key):
    # Step 1: Produce MD from RD
    md = make_proc(raw_data)
    
    # Step 2: Create an identifier for MD
    id_md = create_identifier(md)
    
    # Step 3: Generate a random key K
    k = generate_random_key()
    
    # Step 4: Encrypt MD using K
    nonce, encrypted_md, tag = encrypt_md(md, k)
    
    # Step 5: Encrypt DP’s IdDP and K using PKDO and PCS
    dp_info = encrypt_with_public_key(dp_id.encode('utf-8') + k, do_public_key)
    
    # Step 6: Encrypt DPInfo and IdMD using PKRM and PCS
    encrypted_id_md = encrypt_dp_info(dp_info, id_md, rm_public_key)
    
    # Step 7: Sign on EMD using the private key of DP
    signature = sign_data(encrypted_md, dp_private_key)
    
    # Certificate includes (SD, EId)
    cert = (signature, encrypted_id_md)
    
    # Output EMD, CERT, and DPInfo
    return nonce, encrypted_md, tag, cert, dp_info

# Example usage
if __name__ == "__main__":
    raw_data = "This is some raw data."
    dp_id = "DP1"
    
    # Generate keys for demonstration purposes
    dp_private_key = RSA.generate(2048)
    dp_public_key = dp_private_key.publickey()
    
    do_private_key = RSA.generate(2048)
    do_public_key = do_private_key.publickey()
    
    rm_private_key = RSA.generate(2048)
    rm_public_key = rm_private_key.publickey()
    
    nonce, encrypted_md, tag, cert, dp_info = data_producing_scheme(raw_data, dp_id, dp_private_key, do_public_key, rm_public_key)
    
    print(f"Nonce: {nonce}")
    print(f"Encrypted MD: {encrypted_md}")
    print(f"Tag: {tag}")
    print(f"Certificate: {cert}")
    print(f"DP Info: {dp_info}")
