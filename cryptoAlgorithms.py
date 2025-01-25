from flask import Flask, render_template, request
from Crypto.Cipher import AES,ChaCha20, Blowfish
from Crypto.Random import get_random_bytes
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.hmac import HMAC
from Crypto.Hash import HMAC, SHA512
import os
import hmac
import hashlib
import traceback


app = Flask(__name__)
# Generate RSA keys for Advanced and Admin
rsa_key = RSA.generate(2048)
public_key = rsa_key.publickey()
rsa_cipher = PKCS1_OAEP.new(public_key)
# rsa_key = RSA.generate(2048) generates an RSA key pair (private and public keys).
# public_key = rsa_key.publickey() extracts the public key from the generated RSA key pair.
# rsa_cipher = PKCS1_OAEP.new(public_key) creates an RSA cipher using the public key. This object is now capable of encrypting data using the RSA public key.
# Generate shared secret for ECC (Curve25519)
def shared_secret():
    return get_random_bytes(32)  # Simulated shared secret for ECC

# Utility function to generate data packets of a given size
def generate_packet(size):
    return get_random_bytes(size)


# Encryption and decryption functions
def aes_128_ccm_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CCM)
    nonce = cipher.nonce
    start = time.time()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    end = time.time()
    return nonce, ciphertext, tag, end - start

def aes_128_ccm_decrypt(ciphertext, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
    start = time.time()
    plain = cipher.decrypt_and_verify(ciphertext, tag)
    end = time.time()
    return plain, end - start
# AES-192-CCM Encryption and Decryption
def aes_192_ccm_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CCM)
    nonce = cipher.nonce
    start = time.time()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    end = time.time()
    return nonce, ciphertext, tag, end - start

def aes_192_ccm_decrypt(ciphertext, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
    start = time.time()
    plain = cipher.decrypt_and_verify(ciphertext, tag)
    end = time.time()
    return plain, end - start

# AES-256-CCM Encryption and Decryption
def aes_256_ccm_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CCM)
    nonce = cipher.nonce
    start = time.time()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    end = time.time()
    return nonce, ciphertext, tag, end - start

def aes_256_ccm_decrypt(ciphertext, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
    start = time.time()
    plain = cipher.decrypt_and_verify(ciphertext, tag)
    end = time.time()
    return plain, end - start

def aes_256_gcm_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    start = time.time()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    end = time.time()
    return nonce, ciphertext, tag, end - start

def aes_256_gcm_decrypt(ciphertext, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    start = time.time()
    plain = cipher.decrypt_and_verify(ciphertext, tag)
    end = time.time()
    return plain, end - start

# AES-128-CTR Encryption
def aes_128_ctr_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CTR)
    nonce = cipher.nonce
    start = time.time()
    ciphertext = cipher.encrypt(data)  # CTR mode does not use a tag
    end = time.time()
    return nonce, ciphertext, end - start  # No tag is generated for CTR mode

# AES-128-CTR Decryption
def aes_128_ctr_decrypt(ciphertext, key, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    start = time.time()
    plaintext = cipher.decrypt(ciphertext)  # CTR mode simply decrypts the ciphertext
    end = time.time()
    return plaintext, end - start
# AES-256-CTR Encryption and Decryption
def aes_192_ctr_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CTR)
    nonce = cipher.nonce
    start = time.time()
    ciphertext = cipher.encrypt(data)  # CTR mode does not use a tag
    end = time.time()
    return nonce, ciphertext, end - start  # No tag is generated for CTR mode  

def aes_192_ctr_decrypt(ciphertext, key, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    start = time.time()
    plaintext = cipher.decrypt(ciphertext)  # CTR mode simply decrypts the ciphertext
    end = time.time()
    return plaintext, end - start

# AES-256-CTR Encryption and Decryption
def aes_256_ctr_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CTR)
    nonce = cipher.nonce
    start = time.time()
    ciphertext = cipher.encrypt(data)  # CTR mode does not use a tag
    end = time.time()
    return nonce, ciphertext, end - start  # No tag is generated for CTR mode  

def aes_256_ctr_decrypt(ciphertext, key, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    start = time.time()
    plaintext = cipher.decrypt(ciphertext)  # CTR mode simply decrypts the ciphertext
    end = time.time()
    return plaintext, end - start
# blowfish_encrypt
def blowfish_encrypt(data, key):
    """Encrypt data using Blowfish."""
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    padded_data = pad(data, Blowfish.block_size)
    start = time.time()
    ciphertext = cipher.encrypt(padded_data)
    end = time.time()
    return cipher.iv, ciphertext, end - start
# blowfish_decrypt
def blowfish_decrypt(ciphertext, key, iv):
    """Decrypt data using Blowfish."""
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
    start = time.time()
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, Blowfish.block_size)
    end = time.time()
    return plaintext, end - start


# ECC encryption and decryption using ECDH for key exchange and AES for encryption
def generate_ecc_keypair():
    """Generate ECC key pair for encryption"""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def ecdh_shared_secret(private_key, peer_public_key):
    """Generate shared secret using ECDH key exchange"""
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

def ecc_encrypt_with_shared_secret(data, shared_secret):
    """Encrypt data using AES-GCM and the shared secret"""
    key = shared_secret[:32]  # Use first 32 bytes for AES key
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    start = time.time()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    end = time.time()
    return nonce, ciphertext, tag,end - start

def ecc_decrypt_with_shared_secret(ciphertext, shared_secret, nonce, tag):
    """Decrypt data using AES-GCM and the shared secret"""
    key = shared_secret[:32]  # Use first 32 bytes for AES key
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    start = time.time()
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    end = time.time()
    return decrypted_data,end - start

def chacha20_encrypt(data, key):
    nonce = get_random_bytes(8)  # 8-byte nonce for ChaCha20
    cipher = ChaCha20.new(key=key, nonce=nonce)
    start = time.time()
    ciphertext = cipher.encrypt(data)
    end = time.time()
    return nonce, ciphertext, end - start

    # cipher = AES.new(key, AES.MODE_CTR)
    # nonce = cipher.nonce
    # start = time.time()
    # ciphertext = cipher.encrypt(data)
    # end = time.time()
    # return nonce, ciphertext, end - start

def chacha20_decrypt(ciphertext, key, nonce):
    cipher = ChaCha20.new(key=key, nonce=nonce)
    start = time.time()
    data = cipher.decrypt(ciphertext)
    end = time.time()
    return data, end - start
    # cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    # start = time.time()
    # plain = cipher.decrypt(ciphertext)
    # end = time.time()
    # return plain, end - start

# RSA encryption and decryption
def rsa_encrypt(data):
    start = time.time()
    ciphertext = rsa_cipher.encrypt(data)
    end = time.time()
    return ciphertext, end - start

def rsa_decrypt(ciphertext):
    rsa_decipher = PKCS1_OAEP.new(rsa_key)
    start = time.time()
    plaintext = rsa_decipher.decrypt(ciphertext)
    end = time.time()
    return plaintext, end - start
# ChaCha20-Poly1305 Encryption
def chacha20_poly1305_encrypt(data, key):
    """
    Encrypts data using ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data).
    Args:
        data (bytes): The plaintext data to encrypt.
        key (bytes): A 256-bit encryption key (32 bytes).
    Returns:
        tuple: (nonce, ciphertext, tag, encryption_time)
    """
    cipher = ChaCha20_Poly1305.new(key=key)
    nonce = cipher.nonce
    start = time.time()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    end = time.time()
    return nonce, ciphertext, tag, end - start

# ChaCha20-Poly1305 Decryption
def chacha20_poly1305_decrypt(ciphertext, key, nonce, tag):
    """
    Decrypts data using ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data).
    Args:
        ciphertext (bytes): The encrypted data.
        key (bytes): A 256-bit encryption key (32 bytes).
        nonce (bytes): The nonce used during encryption.
        tag (bytes): The authentication tag for verifying the integrity of the ciphertext.
    Returns:
        tuple: (decrypted_data, decryption_time)
    """
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    start = time.time()
    try:
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        end = time.time()
        return decrypted_data, end - start
    except ValueError:
        end = time.time()
        return None, end - start  # Return None if the tag verification fails

def xchacha20_encrypt(data, key):
    start = time.time()
    cipher = ChaCha20.new(key=key)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(data)
    end = time.time()
    enc_time = end - start
    return nonce, ciphertext, enc_time

def xchacha20_decrypt(ciphertext, key, nonce):
    start = time.time()
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    end = time.time()
    dec_time = end - start
    return plaintext, dec_time
# HMAC-SHA512 Authentication
def hmac_sha512(key, data):
    """Generate HMAC-SHA512 of the given data."""
    hmac_obj = HMAC.new(key, data, SHA512)
    start = time.time()
    hmac_result = hmac_obj.digest()
    end = time.time()
    return hmac_result, end - start
def hmac_sha512_verify(key, message, provided_hmac):
    """
    Verifies the HMAC-SHA512 digest for a given message.

    :param key: The secret key used for the HMAC (bytes)
    :param message: The message to authenticate (bytes)
    :param provided_hmac: The HMAC to compare against (bytes)
    :return: True if the HMAC matches, False otherwise
    """
    # Generate the HMAC-SHA512 for the message
    calculated_hmac = hmac.new(key, message, hashlib.sha512).digest()
    print(calculated_hmac, provided_hmac)
    # Compare the calculated HMAC with the provided HMAC securely
    return hmac.compare_digest(calculated_hmac, provided_hmac)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    try:
        # Extract form data
        level = int(request.form["level"])
        method = request.form["method"]
        algorithm = request.form["algorithm"]
        size = int(request.form["size"]) * 1024 * 1024  # Convert MB to bytes

        # Validate size
        # if size < 1 * 1024 * 1024 or size > 1 * 1024 * 1024 * 1024:
        #  return render_template("index.html", error="Invalid size. Please choose between 1MB and 1GB.")
        if size < 1 * 1024 * 1024 or size > 100 * 1024 * 1024:
         return render_template("index.html", error="Invalid size. Please choose between 1MB and 100MB.")



        # Generate packet and keys
        packet = generate_packet(size)
        key_128 = get_random_bytes(16)
        key_192 = get_random_bytes(24)
        key_256 = get_random_bytes(32)
        key_blowfish = get_random_bytes(16)  # Blowfish key
        hmac_key = get_random_bytes(64)
        # Key generation
        
        
       

        result = {
            "level": level,
            "method": method,
            "algorithm":algorithm,
            "size": size,
            "encryption_time": None,
            "decryption_time": None,
        }

        # Handle levels and methods
                # Handle levels and methods
               # Handle levels and methods
        if level == 1:
            encryption_time = 0
            decryption_time = 0
            print("algorithm",algorithm)
            # Guest: Use ChaCha20 encryption
            if method == "Guest":
                if algorithm == "AES-256-gcm + RSA":
                    enc_time_256 = enc_time_rsa = 0
                    dec_time_256 = dec_time_rsa = 0

                    # AES-256 encryption
                    nonce1, ciphertext1, tag1, enc_time_256 = aes_256_gcm_encrypt(packet, key_256)

                    # RSA encryption (only encrypt the AES-256 symmetric key)
                    rsa_encrypted_key, enc_time_rsa = rsa_encrypt(key_256)

                    # RSA decryption
                    rsa_decrypted_key, dec_time_rsa = rsa_decrypt(rsa_encrypted_key)

                    # Ensure the decrypted key matches the original key
                    assert rsa_decrypted_key == key_256, "RSA key mismatch!"

                    # Decrypt AES-256
                    plaintext, dec_time_256 = aes_256_gcm_decrypt(ciphertext1, rsa_decrypted_key, nonce1, tag1)

                    # Sum up encryption and decryption times
                    encryption_time += enc_time_256 + enc_time_rsa
                    decryption_time += dec_time_rsa + dec_time_256
                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time

                elif algorithm == "ChaCha20 + ECC (Curve25519)":
                        """Admin process with ECC encryption/decryption"""

                        # Initialize variables to avoid unassigned references
                        enc_time_chacha = enc_time_ecc = 0
                        dec_time_ecc = dec_time_chacha = 0

                        # Generate key pair for ECC
                        private_key, public_key = generate_ecc_keypair()

                        # Encrypt the packet using ChaCha20
                        nonce1, ciphertext1, enc_time_chacha = chacha20_encrypt(packet, key_256)

                        # Simulate ECC encryption using ECDH key exchange
                       
                        peer_private_key, peer_public_key = generate_ecc_keypair()  # Assume peer's public key for this example
                        shared_secret = ecdh_shared_secret(private_key, peer_public_key)
                        # Simulate ECC encryption using ECDH key exchange
                       
                        # Use the shared secret for AES encryption and decryption
                        nonce_ecc, ciphertext_ecc, tag_ecc,enc_time_ecc = ecc_encrypt_with_shared_secret(ciphertext1, shared_secret)
                       

                        # Decrypt the ECC-encrypted data
                        # start_dec_ecc = time.time()  # Start timing for ECC decryption
                        decrypted_data,dec_time_ecc = ecc_decrypt_with_shared_secret(ciphertext_ecc, shared_secret, nonce_ecc, tag_ecc)
                        # Continue the decryption process with ChaCha20
                        plaintext, dec_time_chacha = chacha20_decrypt(decrypted_data, key_256, nonce1)
           
                        # Sum up encryption and decryption times
                        encryption_time = enc_time_chacha + enc_time_ecc
                        decryption_time = dec_time_chacha + dec_time_ecc

                        # Output total encryption and decryption time
                        print(f"Total Encryption Time: {enc_time_ecc:.6f} seconds")
                        print(f"Total Decryption Time: {dec_time_ecc:.6f} seconds")
                        result["encryption_time"] = encryption_time
                        result["decryption_time"] = decryption_time

            # Basic: AES-128 -> AES-256 -> ChaCha20
            elif method == "Basic":
                if algorithm == "AES-128-ccm + ChaCha20 + ECC (Curve25519)":
                    # Initialize variables for encryption and decryption
                    enc_time_128 = enc_time_chacha = enc_time_ecc = 0
                    dec_time_128 = dec_time_chacha = dec_time_ecc = 0

                    # AES-128 encryption in CCM mode
                    nonce1, ciphertext1, tag1, enc_time_128 = aes_128_ccm_encrypt(packet, key_128)

                    # ChaCha20 encryption
                    nonce2, ciphertext2, enc_time_chacha = chacha20_encrypt(ciphertext1, key_256)

                    # ECC encryption (ECDH for key exchange)
                    private_key, public_key = generate_ecc_keypair()
                    peer_private_key, peer_public_key = generate_ecc_keypair()
                    shared_secret = ecdh_shared_secret(private_key, peer_public_key)

                    # Simulate ECC encryption using the shared secret
                    nonce_ecc, ciphertext_ecc, tag_ecc, enc_time_ecc = ecc_encrypt_with_shared_secret(ciphertext2, shared_secret)

                    # Decrypt ECC-encrypted data
                    decrypted_data, dec_time_ecc = ecc_decrypt_with_shared_secret(ciphertext_ecc, shared_secret, nonce_ecc, tag_ecc)

                    # Continue decryption with ChaCha20
                    plaintext_chacha, dec_time_chacha = chacha20_decrypt(decrypted_data, key_256, nonce2)

                    # AES-128 decryption
                    final_plaintext, dec_time_128 = aes_128_ccm_decrypt(plaintext_chacha, key_128, nonce1, tag1)

                    # Sum up encryption and decryption times
                    encryption_time = enc_time_128 + enc_time_chacha + enc_time_ecc  # Total encryption time
                    decryption_time = dec_time_128 + dec_time_chacha + dec_time_ecc  # Total decryption time

                    # Output total encryption and decryption times
                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    # Store the encryption and decryption times in the result
                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time

                elif algorithm == "AES-256-gcm + ChaCha20 + RSA":
                    # Initialize variables for encryption and decryption times
                    enc_time_256 = enc_time_rsa = enc_time_chacha = 0
                    dec_time_256 = dec_time_rsa = dec_time_chacha = 0

                    # AES-256 encryption in GCM mode
                    nonce1, ciphertext1, tag1, enc_time_256 = aes_256_gcm_encrypt(packet, key_256)

                    # Encrypt the AES-256 ciphertext using ChaCha20
                    nonce_chacha, ciphertext_chacha, enc_time_chacha = chacha20_encrypt(ciphertext1, key_256)

                    # RSA encryption (encrypt the AES-256 key)
                    rsa_encrypted_key, enc_time_rsa = rsa_encrypt(key_256)

                    # Now the encryption times:
                    encryption_time = enc_time_256 + enc_time_rsa + enc_time_chacha  # Total encryption time

                    # Decryption steps:
                    # RSA decryption to get the AES key
                    rsa_decrypted_key, dec_time_rsa = rsa_decrypt(rsa_encrypted_key)

                    # Ensure the decrypted key matches the original AES key
                    assert rsa_decrypted_key == key_256, "RSA key mismatch!"

                    # Decrypt the ChaCha20 encrypted data
                    decrypted_chacha, dec_time_chacha = chacha20_decrypt(ciphertext_chacha, key_256, nonce_chacha)

                    # Decrypt AES-256 using the RSA-decrypted key
                    plaintext, dec_time_256 = aes_256_gcm_decrypt(decrypted_chacha, rsa_decrypted_key, nonce1, tag1)

                    # Now the decryption times:
                    decryption_time = dec_time_rsa + dec_time_chacha + dec_time_256  # Total decryption time

                    # Output total encryption and decryption times
                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    # Store the encryption and decryption times in the result
                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
            # Advanced: AES-128 -> AES-256 -> ChaCha20 -> RSA
            elif method == "Advanced":
                # 5. ChaCha20 + AES-256-GCM
                if algorithm == "ChaCha20 + AES-256-gcm":
                    enc_time_chacha = enc_time_256 = 0
                    dec_time_chacha = dec_time_256 = 0

                    # Encrypt data with ChaCha20
                    nonce_chacha, ciphertext_chacha, enc_time_chacha = chacha20_encrypt(packet, key_256)

                    # Encrypt the ChaCha20 ciphertext with AES-256-GCM
                    nonce_aes, ciphertext_aes, tag_aes, enc_time_256 = aes_256_gcm_encrypt(ciphertext_chacha, key_256)

                    # Decrypt AES-256-GCM
                    decrypted_aes, dec_time_256 = aes_256_gcm_decrypt(ciphertext_aes, key_256, nonce_aes, tag_aes)

                    # Decrypt ChaCha20
                    decrypted_data, dec_time_chacha = chacha20_decrypt(decrypted_aes, key_256, nonce_chacha)

                    encryption_time = enc_time_chacha + enc_time_256
                    decryption_time = dec_time_256 + dec_time_chacha

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
                # 6. AES-128-CCM + RSA
                elif algorithm == "AES-128-ccm + RSA":
                    enc_time_128 = enc_time_rsa = 0
                    dec_time_128 = dec_time_rsa = 0

                    # AES-128 encryption in CCM mode
                    nonce1, ciphertext1, tag1, enc_time_128 = aes_128_ccm_encrypt(packet, key_128)

                    # RSA encryption (only encrypt the AES-128 key)
                    rsa_encrypted_key, enc_time_rsa = rsa_encrypt(key_128)

                    # RSA decryption
                    rsa_decrypted_key, dec_time_rsa = rsa_decrypt(rsa_encrypted_key)

                    # Ensure the decrypted key matches the original AES key
                    assert rsa_decrypted_key == key_128, "RSA key mismatch!"

                    # Decrypt AES-128
                    final_plaintext, dec_time_128 = aes_128_ccm_decrypt(ciphertext1, rsa_decrypted_key, nonce1, tag1)

                    encryption_time = enc_time_128 + enc_time_rsa
                    decryption_time = dec_time_rsa + dec_time_128

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
                # 7. AES-128-CCM + AES-256-GCM + ECC (Curve25519)
                elif algorithm == "AES-128-ccm + AES-256-gcm + ECC (Curve25519)":
                    enc_time_128 = enc_time_256 = enc_time_ecc = 0
                    dec_time_128 = dec_time_256 = dec_time_ecc = 0

                    # AES-128 encryption in CCM mode
                    nonce1, ciphertext1, tag1, enc_time_128 = aes_128_ccm_encrypt(packet, key_128)

                    # AES-256 encryption in GCM mode
                    nonce2, ciphertext2, tag2, enc_time_256 = aes_256_gcm_encrypt(ciphertext1, key_256)

                    # ECC key pair generation and shared secret calculation
                    private_key, public_key = generate_ecc_keypair()
                    peer_private_key, peer_public_key = generate_ecc_keypair()
                    shared_secret = ecdh_shared_secret(private_key, peer_public_key)

                    # Encrypt the AES-256 ciphertext using the ECC shared secret
                    nonce_ecc, ciphertext_ecc, tag_ecc, enc_time_ecc = ecc_encrypt_with_shared_secret(ciphertext2, shared_secret)

                    # Decrypt the ECC-encrypted data
                    decrypted_ecc, dec_time_ecc = ecc_decrypt_with_shared_secret(ciphertext_ecc, shared_secret, nonce_ecc, tag_ecc)

                    # Decrypt AES-256
                    decrypted_aes, dec_time_256 = aes_256_gcm_decrypt(decrypted_ecc, key_256, nonce2, tag2)

                    # Decrypt AES-128
                    final_plaintext, dec_time_128 = aes_128_ccm_decrypt(decrypted_aes, key_128, nonce1, tag1)

                    encryption_time = enc_time_128 + enc_time_256 + enc_time_ecc
                    decryption_time = dec_time_128 + dec_time_256 + dec_time_ecc

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
            # Admin: AES-128 -> AES-256 -> ChaCha20 -> ECC
            elif method == "Admin":
                """Admin process with ECC encryption/decryption"""
                # 8. AES-256-GCM + ChaCha20 + ECC (Curve25519)
                if algorithm == "AES-256-gcm + ChaCha20 + ECC (Curve25519)":
                    enc_time_256 = enc_time_chacha = enc_time_ecc = 0
                    dec_time_256 = dec_time_chacha = dec_time_ecc = 0

                    # AES-256 encryption in GCM mode
                    nonce1, ciphertext1, tag1, enc_time_256 = aes_256_gcm_encrypt(packet, key_256)

                    # Encrypt the AES-256 ciphertext with ChaCha20
                    nonce_chacha, ciphertext_chacha, enc_time_chacha = chacha20_encrypt(ciphertext1, key_256)

                    # ECC key pair generation and shared secret calculation
                    private_key, public_key = generate_ecc_keypair()
                    peer_private_key, peer_public_key = generate_ecc_keypair()
                    shared_secret = ecdh_shared_secret(private_key, peer_public_key)

                    # Encrypt the ChaCha20 ciphertext using the ECC shared secret
                    nonce_ecc, ciphertext_ecc, tag_ecc, enc_time_ecc = ecc_encrypt_with_shared_secret(ciphertext_chacha, shared_secret)

                    # Decrypt the ECC-encrypted data
                    decrypted_data, dec_time_ecc = ecc_decrypt_with_shared_secret(ciphertext_ecc, shared_secret, nonce_ecc, tag_ecc)

                    # Decrypt ChaCha20
                    decrypted_chacha, dec_time_chacha = chacha20_decrypt(decrypted_data, key_256, nonce_chacha)

                    # Decrypt AES-256-GCM
                    plaintext, dec_time_256 = aes_256_gcm_decrypt(decrypted_chacha, key_256, nonce1, tag1)

                    encryption_time = enc_time_256 + enc_time_chacha + enc_time_ecc
                    decryption_time = dec_time_256 + dec_time_chacha + dec_time_ecc

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
                # 9. AES-128-CCM + ChaCha20 + RSA
                elif algorithm == "AES-128-ccm + ChaCha20 + RSA":
                    enc_time_128 = enc_time_chacha = enc_time_rsa = 0
                    dec_time_128 = dec_time_chacha = dec_time_rsa = 0

                    # AES-128 encryption in CCM mode
                    nonce1, ciphertext1, tag1, enc_time_128 = aes_128_ccm_encrypt(packet, key_128)

                    # Encrypt the AES-128 ciphertext with ChaCha20
                    nonce_chacha, ciphertext_chacha, enc_time_chacha = chacha20_encrypt(ciphertext1, key_256)

                    # RSA encryption (only encrypt the AES-128 key)
                    rsa_encrypted_key, enc_time_rsa = rsa_encrypt(key_128)

                    # RSA decryption
                    rsa_decrypted_key, dec_time_rsa = rsa_decrypt(rsa_encrypted_key)

                    # Ensure the decrypted key matches the original AES key
                    assert rsa_decrypted_key == key_128, "RSA key mismatch!"

                    # Decrypt the ChaCha20-encrypted data
                    decrypted_chacha, dec_time_chacha = chacha20_decrypt(ciphertext_chacha, key_256, nonce_chacha)

                    # Decrypt AES-128
                    final_plaintext, dec_time_128 = aes_128_ccm_decrypt(decrypted_chacha, rsa_decrypted_key, nonce1, tag1)

                    encryption_time = enc_time_128 + enc_time_chacha + enc_time_rsa
                    decryption_time = dec_time_128 + dec_time_chacha + dec_time_rsa

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time

                # 10. ChaCha20 + ECC (Curve25519) + RSA
                elif algorithm == "ChaCha20 + ECC (Curve25519) + RSA":
                    enc_time_chacha = enc_time_ecc = enc_time_rsa = 0
                    dec_time_chacha = dec_time_ecc = dec_time_rsa = 0

                    # Encrypt data with ChaCha20
                    nonce_chacha, ciphertext_chacha, enc_time_chacha = chacha20_encrypt(packet, key_256)

                    # ECC key pair generation and shared secret calculation
                    private_key, public_key = generate_ecc_keypair()
                    peer_private_key, peer_public_key = generate_ecc_keypair()
                    shared_secret = ecdh_shared_secret(private_key, peer_public_key)

                    # Encrypt the ChaCha20 ciphertext using the ECC shared secret
                    nonce_ecc, ciphertext_ecc, tag_ecc, enc_time_ecc = ecc_encrypt_with_shared_secret(ciphertext_chacha, shared_secret)

                    # RSA encryption (only encrypt the ECC shared secret)
                    rsa_encrypted_key, enc_time_rsa = rsa_encrypt(shared_secret)

                    # Decrypt RSA-encrypted key (ECC shared secret)
                    rsa_decrypted_key, dec_time_rsa = rsa_decrypt(rsa_encrypted_key)

                    # Ensure the decrypted key matches the original ECC shared secret
                    assert rsa_decrypted_key == shared_secret, "RSA key mismatch!"

                    # Decrypt ECC-encrypted data
                    decrypted_ecc, dec_time_ecc = ecc_decrypt_with_shared_secret(ciphertext_ecc, rsa_decrypted_key, nonce_ecc, tag_ecc)

                    # Decrypt ChaCha20
                    decrypted_data, dec_time_chacha = chacha20_decrypt(decrypted_ecc, key_256, nonce_chacha)

                    encryption_time = enc_time_chacha + enc_time_ecc + enc_time_rsa
                    decryption_time = dec_time_chacha + dec_time_ecc + dec_time_rsa

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time

        elif level == 2:
            encryption_time = 0
            decryption_time = 0
            print("algorithm",algorithm)
            # Guest: Use AES-128-CCM + ChaCha20
            if method == "Guest":
                if algorithm == "AES-128-CCM + ChaCha20":
                    enc_time_128 = enc_time_chacha = 0
                    dec_time_chacha = dec_time_128 = 0
                    # Encrypt using AES-128-CCM
                    nonce1, ciphertext1, tag1, enc_time_128 = aes_128_ccm_encrypt(packet, key_128)

                    # Encrypt using ChaCha20
                    nonce2, ciphertext2, enc_time_chacha = chacha20_encrypt(ciphertext1, key_256)

                    # Decrypt ChaCha20 ciphertext
                    decrypted_chacha, dec_time_chacha = chacha20_decrypt(ciphertext2, key_256, nonce2)

                    # Decrypt AES-128-CCM ciphertext
                    final_plaintext, dec_time_128 = aes_128_ccm_decrypt(decrypted_chacha, key_128, nonce1, tag1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_128 + enc_time_chacha
                    decryption_time = dec_time_128 + dec_time_chacha

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")
                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time

                elif algorithm == "AES-128-CCM + AES-192-CCM":
                        # Encrypt using AES-128-CCM
                        nonce1, ciphertext1, tag1, enc_time_128 = aes_128_ccm_encrypt(packet, key_128)

                        # Encrypt using AES-192-CCM
                        nonce2, ciphertext2, tag2, enc_time_192 = aes_192_ccm_encrypt(ciphertext1, key_192)

                        # Decrypt AES-192-CCM ciphertext
                        decrypted_aes_192, dec_time_192 = aes_192_ccm_decrypt(ciphertext2, key_192, nonce2, tag2)

                        # Decrypt AES-128-CCM ciphertext
                        final_plaintext, dec_time_128 = aes_128_ccm_decrypt(decrypted_aes_192, key_128, nonce1, tag1)

                        # Total encryption and decryption times
                        encryption_time = enc_time_128 + enc_time_192
                        decryption_time = dec_time_128 + dec_time_192

                        print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                        print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                        # Store the encryption and decryption times in the result
                        result["encryption_time"] = encryption_time
                        result["decryption_time"] = decryption_time
            # Basic: AES-128 -> AES-256 -> ChaCha20
            elif method == "Basic":
                if algorithm == "AES-256-CCM + ChaCha20-Poly1305":
                    enc_time_256 = enc_time_poly1305 = 0
                    dec_time_poly1305 = dec_time_256 = 0
                   # Encrypt using AES-256-CCM
                    nonce1, ciphertext1, tag1, enc_time_256 = aes_256_ccm_encrypt(packet, key_256)

                    # Encrypt using ChaCha20-Poly1305
                    nonce2, ciphertext2, tag2, enc_time_poly1305 = chacha20_poly1305_encrypt(ciphertext1, key_256)

                    # Decrypt ChaCha20-Poly1305 ciphertext
                    decrypted_poly1305, dec_time_poly1305 = chacha20_poly1305_decrypt(ciphertext2, key_256, nonce2, tag2)

                    # Decrypt AES-256-CCM ciphertext
                    final_plaintext, dec_time_256 = aes_256_ccm_decrypt(decrypted_poly1305, key_256, nonce1, tag1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_256 + enc_time_poly1305
                    decryption_time = dec_time_256 + dec_time_poly1305

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")
                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time

                elif algorithm == "AES-128-CCM + AES-192-CCM + XChaCha20":
                    enc_time_128 = enc_time_192 = enc_time_xchacha = 0
                    dec_time_xchacha = dec_time_192 = dec_time_192 = 0
                    # Encrypt using AES-128-CCM
                    nonce1, ciphertext1, tag1, enc_time_128 = aes_128_ccm_encrypt(packet, key_128)

                    # Encrypt using AES-192-CCM
                    nonce2, ciphertext2, tag2, enc_time_192 = aes_192_ccm_encrypt(ciphertext1, key_192)

                    # Encrypt using XChaCha20
                    nonce3, ciphertext3, enc_time_xchacha = xchacha20_encrypt(ciphertext2, key_256)

                    # Decrypt XChaCha20 ciphertext
                    decrypted_xchacha, dec_time_xchacha = xchacha20_decrypt(ciphertext3, key_256, nonce3)

                    # Decrypt AES-192-CCM ciphertext
                    decrypted_aes_192, dec_time_192 = aes_192_ccm_decrypt(decrypted_xchacha, key_192, nonce2, tag2)

                    # Decrypt AES-128-CCM ciphertext
                    final_plaintext, dec_time_128 = aes_128_ccm_decrypt(decrypted_aes_192, key_128, nonce1, tag1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_128 + enc_time_192 + enc_time_xchacha
                    decryption_time = dec_time_128 + dec_time_192 + dec_time_xchacha

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")
                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
           
            elif method == "Advanced":
                # 5. AES-128-CCM + AES-256-CCM + ChaCha20
                if algorithm == "AES-128-CCM + AES-256-CCM + ChaCha20":
                    enc_time_128 = enc_time_256 = enc_time_chacha = 0
                    dec_time_chacha = dec_time_256 =  dec_time_128 = 0
                    # Encrypt using AES-128-CCM
                    nonce1, ciphertext1, tag1, enc_time_128 = aes_128_ccm_encrypt(packet, key_128)

                    # Encrypt using AES-256-CCM
                    nonce2, ciphertext2, tag2, enc_time_256 = aes_256_ccm_encrypt(ciphertext1, key_256)

                    # Encrypt using ChaCha20
                    nonce3, ciphertext3, enc_time_chacha = chacha20_encrypt(ciphertext2, key_256)

                    # Decrypt ChaCha20 ciphertext
                    decrypted_chacha, dec_time_chacha = chacha20_decrypt(ciphertext3, key_256, nonce3)

                    # Decrypt AES-256-CCM ciphertext
                    decrypted_aes_256, dec_time_256 = aes_256_ccm_decrypt(decrypted_chacha, key_256, nonce2, tag2)

                    # Decrypt AES-128-CCM ciphertext
                    final_plaintext, dec_time_128 = aes_128_ccm_decrypt(decrypted_aes_256, key_128, nonce1, tag1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_128 + enc_time_256 + enc_time_chacha
                    decryption_time = dec_time_128 + dec_time_256 + dec_time_chacha

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
                # 6. AES-256-CCM + XChaCha20 + ChaCha20
                elif algorithm == "AES-256-CCM + XChaCha20 + ChaCha20":
                    enc_time_256 = enc_time_xchacha =  enc_time_chacha = 0
                    dec_time_chacha = dec_time_xchacha = dec_time_256 = 0

                   # Encrypt using AES-256-CCM
                    nonce1, ciphertext1, tag1, enc_time_256 = aes_256_ccm_encrypt(packet, key_256)

                    # Encrypt using XChaCha20
                    nonce2, ciphertext2, enc_time_xchacha = xchacha20_encrypt(ciphertext1, key_256)

                    # Encrypt using ChaCha20
                    nonce3, ciphertext3, enc_time_chacha = chacha20_encrypt(ciphertext2, key_256)

                    # Decrypt ChaCha20 ciphertext
                    decrypted_chacha, dec_time_chacha = chacha20_decrypt(ciphertext3, key_256, nonce3)

                    # Decrypt XChaCha20 ciphertext
                    decrypted_xchacha, dec_time_xchacha = xchacha20_decrypt(decrypted_chacha, key_256, nonce2)

                    # Decrypt AES-256-CCM ciphertext
                    final_plaintext, dec_time_256 = aes_256_ccm_decrypt(decrypted_xchacha, key_256, nonce1, tag1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_256 + enc_time_xchacha + enc_time_chacha
                    decryption_time = dec_time_256 + dec_time_xchacha + dec_time_chacha

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
                # 7. AES-192-CCM + XChaCha20
                elif algorithm == "AES-192-CCM + XChaCha20":
                    enc_time_192 = enc_time_xchacha = 0
                    dec_time_xchacha = dec_time_192 = 0
                    # Encrypt using AES-192-CCM
                    nonce1, ciphertext1, tag1, enc_time_192 = aes_192_ccm_encrypt(packet, key_192)

                    # Encrypt using XChaCha20
                    nonce2, ciphertext2, enc_time_xchacha = xchacha20_encrypt(ciphertext1, key_256)

                    # Decrypt XChaCha20 ciphertext
                    decrypted_xchacha, dec_time_xchacha = xchacha20_decrypt(ciphertext2, key_256, nonce2)

                    # Decrypt AES-192-CCM ciphertext
                    final_plaintext, dec_time_192 = aes_192_ccm_decrypt(decrypted_xchacha, key_192, nonce1, tag1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_192 + enc_time_xchacha
                    decryption_time = dec_time_192 + dec_time_xchacha

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
            # Admin
            elif method == "Admin":
                """Admin process with ECC encryption/decryption"""
                # 8. AES-256-CCM + AES-128-CCM + ChaCha20
                if algorithm == "AES-256-CCM + AES-128-CCM + ChaCha20":
                    enc_time_256 = enc_time_128 = enc_time_chacha = 0
                    dec_time_chacha = dec_time_128 = dec_time_256 = 0
                   # Encrypt using AES-256-CCM
                    nonce1, ciphertext1, tag1, enc_time_256 = aes_256_ccm_encrypt(packet, key_256)

                    # Encrypt using AES-128-CCM
                    nonce2, ciphertext2, tag2, enc_time_128 = aes_128_ccm_encrypt(ciphertext1, key_128)

                    # Encrypt using ChaCha20
                    nonce3, ciphertext3, enc_time_chacha = chacha20_encrypt(ciphertext2, key_256)

                    # Decrypt ChaCha20 ciphertext
                    decrypted_chacha, dec_time_chacha = chacha20_decrypt(ciphertext3, key_256, nonce3)

                    # Decrypt AES-128-CCM ciphertext
                    decrypted_aes_128, dec_time_128 = aes_128_ccm_decrypt(decrypted_chacha, key_128, nonce2, tag2)

                    # Decrypt AES-256-CCM ciphertext
                    final_plaintext, dec_time_256 = aes_256_ccm_decrypt(decrypted_aes_128, key_256, nonce1, tag1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_256 + enc_time_128 + enc_time_chacha
                    decryption_time = dec_time_256 + dec_time_128 + dec_time_chacha

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")
                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
                # 9. AES-192-CCM + AES-256-CCM + XChaCha20
                elif algorithm == "AES-192-CCM + AES-256-CCM + XChaCha20":
                    enc_time_192 = enc_time_256 = enc_time_xchacha = 0
                    dec_time_xchacha = dec_time_256 = dec_time_192 = 0
                    # Encrypt using AES-192-CCM
                    nonce1, ciphertext1, tag1, enc_time_192 = aes_192_ccm_encrypt(packet, key_192)

                    # Encrypt using AES-256-CCM
                    nonce2, ciphertext2, tag2, enc_time_256 = aes_256_ccm_encrypt(ciphertext1, key_256)

                    # Encrypt using XChaCha20
                    nonce3, ciphertext3, enc_time_xchacha = xchacha20_encrypt(ciphertext2, key_256)

                    # Decrypt XChaCha20 ciphertext
                    decrypted_xchacha, dec_time_xchacha = xchacha20_decrypt(ciphertext3, key_256, nonce3)

                    # Decrypt AES-256-CCM ciphertext
                    decrypted_aes_256, dec_time_256 = aes_256_ccm_decrypt(decrypted_xchacha, key_256, nonce2, tag2)

                    # Decrypt AES-192-CCM ciphertext
                    final_plaintext, dec_time_192 = aes_192_ccm_decrypt(decrypted_aes_256, key_192, nonce1, tag1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_192 + enc_time_256 + enc_time_xchacha
                    decryption_time = dec_time_192 + dec_time_256 + dec_time_xchacha

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")
                    

                   

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time

                # 10. AES-128-CCM + ChaCha20-Poly1305 + XChaCha20
                elif algorithm == "AES-128-CCM + ChaCha20-Poly1305 + XChaCha20":
                    enc_time_128 = enc_time_poly1305 = enc_time_xchacha = 0
                    dec_time_xchacha = dec_time_poly1305 = dec_time_128 = 0
                    # Encrypt using AES-128-CCM
                    nonce1, ciphertext1, tag1, enc_time_128 = aes_128_ccm_encrypt(packet, key_128)

                    # Encrypt using ChaCha20-Poly1305
                    nonce2, ciphertext2, tag2, enc_time_poly1305 = chacha20_poly1305_encrypt(ciphertext1, key_256)

                    # Encrypt using XChaCha20
                    nonce3, ciphertext3, enc_time_xchacha = xchacha20_encrypt(ciphertext2, key_256)

                    # Decrypt XChaCha20 ciphertext
                    decrypted_xchacha, dec_time_xchacha = xchacha20_decrypt(ciphertext3, key_256, nonce3)

                    # Decrypt ChaCha20-Poly1305 ciphertext
                    decrypted_poly1305, dec_time_poly1305 = chacha20_poly1305_decrypt(decrypted_xchacha, key_256, nonce2, tag2)

                    # Decrypt AES-128-CCM ciphertext
                    final_plaintext, dec_time_128 = aes_128_ccm_decrypt(decrypted_poly1305, key_128, nonce1, tag1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_128 + enc_time_poly1305 + enc_time_xchacha
                    decryption_time = dec_time_128 + dec_time_poly1305 + dec_time_xchacha

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time

            

        elif level == 3:
            encryption_time = 0
            decryption_time = 0
            print("algorithm",algorithm)
            # Guest
            if method == "Guest":
                # : Use AES-128-CTR combined algorithm
                if algorithm == "AES-128-CTR":
                    # Encrypt using AES-128-CTR
                    enc_time_128 = 0
                    dec_time_128 = 0
                    nonce1, ciphertext1, enc_time_128 = aes_128_ctr_encrypt(packet, key_128)
                    # Decrypt AES-128-CTR ciphertext
                    final_plaintext, dec_time_128 = aes_128_ctr_decrypt(ciphertext1, key_128, nonce1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_128 
                    decryption_time = dec_time_128 

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")
                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
                    
            # Basic:
            elif method == "Basic":
                #  AES-128 -> AES-256 -> ChaCha20
                if algorithm == "AES-128-CTR + ChaCha20":
                    enc_time_128 = enc_time_chacha = 0
                    dec_time_chacha = dec_time_128 = 0
                    # Encrypt using AES-128-CTR
                    nonce1, ciphertext1, enc_time_128 = aes_128_ctr_encrypt(packet, key_128)

                    # Encrypt using ChaCha20
                    nonce2, ciphertext2, enc_time_chacha = chacha20_encrypt(ciphertext1, key_256)

                    # Decrypt ChaCha20 ciphertext
                    decrypted_chacha, dec_time_chacha = chacha20_decrypt(ciphertext2, key_256, nonce2)

                    # Decrypt AES-128-CTR ciphertext
                    final_plaintext, dec_time_128 = aes_128_ctr_decrypt(decrypted_chacha, key_128, nonce1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_128 + enc_time_chacha
                    decryption_time = dec_time_128 + dec_time_chacha

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")
                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
                # AES-192-CTR + Blowfish
                elif algorithm == "AES-192-CTR + Blowfish":
                    enc_time_192 = enc_time_blowfish = 0
                    dec_time_blowfish = dec_time_192 = 0
                    # Encrypt using AES-192-CTR
                    nonce1, ciphertext1, enc_time_192 = aes_192_ctr_encrypt(packet, key_192)

                    # Encrypt using Blowfish
                    iv, ciphertext2, enc_time_blowfish = blowfish_encrypt(ciphertext1, key_blowfish)

                    # Decrypt Blowfish ciphertext
                    decrypted_blowfish, dec_time_blowfish = blowfish_decrypt(ciphertext2, key_blowfish, iv)

                    # Decrypt AES-192-CTR ciphertext
                    final_plaintext, dec_time_192 = aes_192_ctr_decrypt(decrypted_blowfish, key_192, nonce1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_192 + enc_time_blowfish
                    decryption_time = dec_time_192 + dec_time_blowfish

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
            # Advanced
            elif method == "Advanced":
                # 4. AES-256-CTR + ChaCha20
                if algorithm == "AES-256-CTR + ChaCha20":
                    enc_time_256 = enc_time_chacha = 0
                    dec_time_256  =  dec_time_chacha = 0 
                    # Encrypt using AES-256-CTR
                    nonce1, ciphertext1, enc_time_256 = aes_256_ctr_encrypt(packet, key_256)

                    # Encrypt using ChaCha20
                    nonce2, ciphertext2, enc_time_chacha = chacha20_encrypt(ciphertext1, key_256)

                    # Decrypt ChaCha20 ciphertext
                    decrypted_chacha, dec_time_chacha = chacha20_decrypt(ciphertext2, key_256, nonce2)

                    # Decrypt AES-256-CTR ciphertext
                    final_plaintext, dec_time_256 = aes_256_ctr_decrypt(decrypted_chacha, key_256, nonce1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_256 + enc_time_chacha
                    decryption_time = dec_time_256 + dec_time_chacha

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
                # 5. AES-128-CTR + Blowfish + ChaCha20
                elif algorithm == "AES-128-CTR + Blowfish + ChaCha20":
                    enc_time_128 = enc_time_blowfish = enc_time_chacha = 0
                    dec_time_128 = dec_time_blowfish = dec_time_chacha = 0
                   # Encrypt using AES-128-CTR
                    nonce1, ciphertext1, enc_time_128 = aes_128_ctr_encrypt(packet, key_128)

                    # Encrypt using Blowfish
                    iv, ciphertext2, enc_time_blowfish = blowfish_encrypt(ciphertext1, key_blowfish)

                    # Encrypt using ChaCha20
                    nonce2, ciphertext3, enc_time_chacha = chacha20_encrypt(ciphertext2, key_256)

                    # Decrypt ChaCha20 ciphertext
                    decrypted_chacha, dec_time_chacha = chacha20_decrypt(ciphertext3, key_256, nonce2)

                    # Decrypt Blowfish ciphertext
                    decrypted_blowfish, dec_time_blowfish = blowfish_decrypt(decrypted_chacha, key_blowfish, iv)

                    # Decrypt AES-128-CTR ciphertext
                    final_plaintext, dec_time_128 = aes_128_ctr_decrypt(decrypted_blowfish, key_128, nonce1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_128 + enc_time_blowfish + enc_time_chacha
                    decryption_time = dec_time_128 + dec_time_blowfish + dec_time_chacha

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")


                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
                # 6. AES-192-CTR + ChaCha20 + ECC (Curve25519)
                elif algorithm == "AES-192-CTR + ChaCha20 + ECC (Curve25519)":
                    enc_time_192 = enc_time_chacha = enc_time_ecc = 0
                    dec_time_192 = dec_time_chacha = dec_time_ecc = 0
                    # Encrypt using AES-192-CTR
                    nonce1, ciphertext1, enc_time_192 = aes_192_ctr_encrypt(packet, key_192)

                    # Encrypt using ChaCha20
                    nonce2, ciphertext2, enc_time_chacha = chacha20_encrypt(ciphertext1, key_256)

                    # ECC encryption (ECDH for key exchange)
                    private_key, public_key = generate_ecc_keypair()
                    peer_private_key, peer_public_key = generate_ecc_keypair()
                    shared_secret = ecdh_shared_secret(private_key, peer_public_key)
                    
                    # Simulate ECC encryption using the shared secret
                    nonce_ecc, ciphertext_ecc, tag_ecc,enc_time_ecc = ecc_encrypt_with_shared_secret(ciphertext2, shared_secret)

                    # Decrypt ECC-encrypted data
                    decrypted_data,dec_time_ecc = ecc_decrypt_with_shared_secret(ciphertext_ecc, shared_secret, nonce_ecc, tag_ecc)

                    # Decrypt ChaCha20 ciphertext
                    decrypted_chacha, dec_time_chacha = chacha20_decrypt(decrypted_data, key_256, nonce2)

                    # Decrypt AES-192-CTR ciphertext
                    final_plaintext, dec_time_192 = aes_192_ctr_decrypt(decrypted_chacha, key_192, nonce1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_192 + enc_time_chacha + enc_time_ecc
                    decryption_time = dec_time_192 + dec_time_chacha + dec_time_ecc

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
            # Admin
            elif method == "Admin":
                """Admin process with ECC encryption/decryption"""
               
                # 7. AES-256-CTR + ChaCha20 + ECC (Curve25519)
                if algorithm == "AES-256-CTR + ChaCha20 + ECC (Curve25519)":

                    enc_time_256 = enc_time_chacha = enc_time_ecc = 0
                    dec_time_256 = dec_time_chacha = dec_time_ecc = 0
                    # Encrypt using AES-192-CTR
                    nonce1, ciphertext1, enc_time_192 = aes_256_ctr_encrypt(packet, key_256)

                    # Encrypt using ChaCha20
                    nonce2, ciphertext2, enc_time_chacha = chacha20_encrypt(ciphertext1, key_256)

                    # ECC encryption (ECDH for key exchange)
                    private_key, public_key = generate_ecc_keypair()
                    peer_private_key, peer_public_key = generate_ecc_keypair()
                    shared_secret = ecdh_shared_secret(private_key, peer_public_key)
                    
                    # Simulate ECC encryption using the shared secret
                    nonce_ecc, ciphertext_ecc, tag_ecc,enc_time_ecc = ecc_encrypt_with_shared_secret(ciphertext2, shared_secret)

                    # Decrypt ECC-encrypted data
                    decrypted_data,dec_time_ecc = ecc_decrypt_with_shared_secret(ciphertext_ecc, shared_secret, nonce_ecc, tag_ecc)

                    # Decrypt ChaCha20 ciphertext
                    decrypted_chacha, dec_time_chacha = chacha20_decrypt(decrypted_data, key_256, nonce2)

                    # Decrypt AES-192-CTR ciphertext
                    final_plaintext, dec_time_256 = aes_256_ctr_decrypt(decrypted_chacha, key_256, nonce1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_256 + enc_time_chacha + enc_time_ecc
                    decryption_time = dec_time_256 + dec_time_chacha + dec_time_ecc

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")
                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
                
                # 8. AES-128-CTR + Blowfish
                elif algorithm == "AES-128-CTR + Blowfish":
                        enc_time_128 = enc_time_blowfish = 0
                        dec_time_blowfish = dec_time_128 = 0
                        # Encrypt using AES-192-CTR
                        nonce1, ciphertext1, enc_time_128 = aes_128_ctr_encrypt(packet, key_128)

                        # Encrypt using Blowfish
                        iv, ciphertext2, enc_time_blowfish = blowfish_encrypt(ciphertext1, key_blowfish)

                        # Decrypt Blowfish ciphertext
                        decrypted_blowfish, dec_time_blowfish = blowfish_decrypt(ciphertext2, key_blowfish, iv)

                        # Decrypt AES-192-CTR ciphertext
                        final_plaintext, dec_time_192 = aes_128_ctr_decrypt(decrypted_blowfish, key_128, nonce1)

                        # Total encryption and decryption times
                        encryption_time = enc_time_128 + enc_time_blowfish
                        decryption_time = dec_time_192 + dec_time_blowfish

                        print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                        print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                        result["encryption_time"] = encryption_time
                        result["decryption_time"] = decryption_time
                    
                # 9. AES-256-CTR + Blowfish
                elif algorithm == "AES-256-CTR + Blowfish":
                        enc_time_256 = enc_time_blowfish = 0
                        dec_time_blowfish = dec_time_256 = 0
                        # Encrypt using AES-192-CTR
                        nonce1, ciphertext1, enc_time_256 = aes_256_ctr_encrypt(packet, key_256)

                        # Encrypt using Blowfish
                        iv, ciphertext2, enc_time_blowfish = blowfish_encrypt(ciphertext1, key_blowfish)

                        # Decrypt Blowfish ciphertext
                        decrypted_blowfish, dec_time_blowfish = blowfish_decrypt(ciphertext2, key_blowfish, iv)

                        # Decrypt AES-192-CTR ciphertext
                        final_plaintext, dec_time_256 = aes_256_ctr_decrypt(decrypted_blowfish, key_256, nonce1)

                        # Total encryption and decryption times
                        encryption_time = enc_time_256 + enc_time_blowfish
                        decryption_time = dec_time_256 + dec_time_blowfish

                        print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                        print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                        result["encryption_time"] = encryption_time
                        result["decryption_time"] = decryption_time

                # 10 AES-128-CTR + Blowfish + ChaCha20 + ECC (Curve25519)
                elif algorithm == "AES-128-CTR + Blowfish + ChaCha20 + ECC (Curve25519)":
                     # AES-128-CTR Encryption
                    nonce1, ciphertext1, enc_time_128 = aes_128_ctr_encrypt(packet, key_128)

                    # ChaCha20 Encryption
                    nonce2, ciphertext2, enc_time_chacha20 = chacha20_encrypt(ciphertext1, key_256)

                    # Blowfish Encryption
                    iv3, ciphertext3, enc_time_blowfish = blowfish_encrypt(ciphertext2, key_blowfish)

                    # ECC Encryption (Curve25519 ECDH for shared secret)
                    
                    private_key, public_key = generate_ecc_keypair()
                    peer_private_key, peer_public_key = generate_ecc_keypair()
                    shared_secret = ecdh_shared_secret(private_key, peer_public_key)
                    nonce_ecc, ciphertext_ecc,tag_ecc,enc_time_ecc = ecc_encrypt_with_shared_secret(ciphertext3, shared_secret)
                    

                    # Decryption process
                    # ECC Decryption
                    decrypted_data_ecc,dec_time_ecc = ecc_decrypt_with_shared_secret(ciphertext_ecc, shared_secret, nonce_ecc,tag_ecc)
                    # Blowfish Decryption
                    plaintext3, dec_time_blowfish = blowfish_decrypt(decrypted_data_ecc, key_blowfish, iv3)

                    # ChaCha20 Decryption
                    plaintext2, dec_time_chacha20 = chacha20_decrypt(plaintext3, key_256, nonce2)

                    # AES-128-CTR Decryption
                    final_plaintext, dec_time_128 = aes_128_ctr_decrypt(plaintext2, key_128, nonce1)

                    # Sum up encryption and decryption times
                    encryption_time = enc_time_128 + enc_time_chacha20 + enc_time_blowfish + enc_time_ecc
                    decryption_time = dec_time_ecc + dec_time_blowfish + dec_time_chacha20 + dec_time_128

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time

        elif level == 4:
            encryption_time = 0
            decryption_time = 0
            encryption_time = 0
            decryption_time = 0
            print("algorithm",algorithm)
            # Guest
            if method == "Guest":
                # Blowfish + AES-128-CTR
                if algorithm == "Blowfish + AES-128-CTR":
                    enc_time_blowfish = enc_time_aes = 0
                    dec_time_blowfish = dec_time_aes = 0
                    # Encrypt using Blowfish
                    iv_blowfish, ciphertext_blowfish, enc_time_blowfish = blowfish_encrypt(packet, key_blowfish)

                    # Encrypt using AES-128-CTR
                    nonce_aes, ciphertext_aes, enc_time_aes = aes_128_ctr_encrypt(ciphertext_blowfish, key_128)

                    # Decrypt AES-128-CTR ciphertext
                    decrypted_aes, dec_time_aes = aes_128_ctr_decrypt(ciphertext_aes, key_128, nonce_aes)

                    # Decrypt Blowfish ciphertext
                    plaintext, dec_time_blowfish = blowfish_decrypt(decrypted_aes, key_blowfish, iv_blowfish)

                    # Total times
                    encryption_time = enc_time_blowfish + enc_time_aes
                    decryption_time = dec_time_blowfish + dec_time_aes

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")
                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time

               
            # Basic
            elif method == "Basic":
                # AES-192-CTR + ChaCha20
                if algorithm == "AES-192-CTR + ChaCha20":
                    enc_time_aes = enc_time_chacha = 0
                    dec_time_aes = dec_time_chacha = 0
                    # Encrypt using AES-192-CTR
                    nonce_aes, ciphertext_aes, enc_time_aes = aes_192_ctr_encrypt(packet, key_192)

                    # Encrypt using ChaCha20
                    nonce_chacha, ciphertext_chacha, enc_time_chacha = chacha20_encrypt(ciphertext_aes, key_256)

                    # Decrypt ChaCha20 ciphertext
                    decrypted_chacha, dec_time_chacha = chacha20_decrypt(ciphertext_chacha, key_256, nonce_chacha)

                    # Decrypt AES-192-CTR ciphertext
                    plaintext, dec_time_aes = aes_192_ctr_decrypt(decrypted_chacha, key_192, nonce_aes)

                    # Total times
                    encryption_time = enc_time_aes + enc_time_chacha
                    decryption_time = dec_time_aes + dec_time_chacha

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")
                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time

                elif algorithm == "AES-128-CTR + HMAC-SHA512":
                        try:
                            # Encryption Process
                            # AES-128-CTR Encryption
                            enc_time_128 = enc_time_hmac = 0
                            dec_time_128 = dec_time_hmac = 0
                            nonce1, ciphertext1, enc_time_128 = aes_128_ctr_encrypt(packet, key_128)  # Corrected to AES-128 key
                            print(f"AES-128-CTR Encryption Time: {enc_time_128:.6f} seconds")

                            # HMAC-SHA512 Authentication
                            start_hmac_enc = time.time()
                            hmac_result, hmac_time = hmac_sha512(hmac_key, ciphertext1)  # Generate HMAC
                            end_hmac_enc = time.time()
                            enc_time_hmac = end_hmac_enc - start_hmac_enc
                            print(f"HMAC-SHA512 Generation Time: {enc_time_hmac:.6f} seconds")

                            # Decryption Process
                            # HMAC-SHA512 Verification
                            start_hmac_dec = time.time()
                            hmac_valid = hmac_sha512_verify(hmac_key, ciphertext1, hmac_result)  # Verify HMAC
                            end_hmac_dec = time.time()
                            dec_time_hmac = end_hmac_dec - start_hmac_dec
                            print(f"HMAC-SHA512 Verification Time: {dec_time_hmac:.6f} seconds")

                            if not hmac_valid:
                                raise ValueError("HMAC verification failed!")

                            # AES-128-CTR Decryption
                            final_plaintext, dec_time_128 = aes_128_ctr_decrypt(ciphertext1, key_128, nonce1)  # Corrected ciphertext1
                            print(f"AES-128-CTR Decryption Time: {dec_time_128:.6f} seconds")

                            # Sum up encryption and decryption times
                            encryption_time = enc_time_128 + enc_time_hmac
                            decryption_time = dec_time_128 + dec_time_hmac

                            print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                            print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                        except Exception as e:
                            traceback.print_exc()


                   
                        result["encryption_time"] = encryption_time
                        result["decryption_time"] = decryption_time
           
            elif method == "Advanced":
                # 4. AES-192-CTR + AES-256-CTR + ChaCha20 + HMAC-SHA512
                if algorithm == "AES-192-CTR + AES-256-CTR + ChaCha20 + HMAC-SHA512":
                    try:
                        # AES-192-CTR Encryption
                        nonce1, ciphertext1, enc_time_192 = aes_192_ctr_encrypt(packet, key_192)
                        print(f"AES-192-CTR Encryption Time: {enc_time_192:.6f} seconds")

                        # AES-256-CTR Encryption
                        nonce2, ciphertext2, enc_time_256 = aes_256_ctr_encrypt(ciphertext1, key_256)
                        print(f"AES-256-CTR Encryption Time: {enc_time_256:.6f} seconds")

                        # ChaCha20 Encryption
                        nonce3, ciphertext3, enc_time_chacha = chacha20_encrypt(ciphertext2, key_256)
                        print(f"ChaCha20 Encryption Time: {enc_time_chacha:.6f} seconds")

                        # HMAC-SHA512 Authentication
                        start_hmac_enc = time.time()
                        hmac_result, hmac_time = hmac_sha512(hmac_key, ciphertext3)
                        end_hmac_enc = time.time()
                        enc_time_hmac = end_hmac_enc - start_hmac_enc
                        print(f"HMAC-SHA512 Authentication Time: {enc_time_hmac:.6f} seconds")

                        # HMAC-SHA512 Verification
                        start_hmac_dec = time.time()
                        hmac_valid = hmac_sha512_verify(hmac_key, ciphertext3, hmac_result)
                        end_hmac_dec = time.time()
                        dec_time_hmac = end_hmac_dec - start_hmac_dec
                        print(f"HMAC-SHA512 Verification Time: {dec_time_hmac:.6f} seconds")

                        if not hmac_valid:
                            raise ValueError("HMAC verification failed!")

                        # Decryption Process
                        # ChaCha20 Decryption
                        decrypted_chacha, dec_time_chacha = chacha20_decrypt(ciphertext3, key_256, nonce3)
                        print(f"ChaCha20 Decryption Time: {dec_time_chacha:.6f} seconds")

                        # AES-256-CTR Decryption
                        decrypted_aes_256, dec_time_256 = aes_256_ctr_decrypt(decrypted_chacha, key_256, nonce2)
                        print(f"AES-256-CTR Decryption Time: {dec_time_256:.6f} seconds")

                        # AES-192-CTR Decryption
                        final_plaintext, dec_time_192 = aes_192_ctr_decrypt(decrypted_aes_256, key_192, nonce1)
                        print(f"AES-192-CTR Decryption Time: {dec_time_192:.6f} seconds")

                        # Sum up encryption and decryption times
                        encryption_time = enc_time_192 + enc_time_256 + enc_time_chacha + enc_time_hmac
                        decryption_time = dec_time_192 + dec_time_256 + dec_time_chacha + dec_time_hmac

                        print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                        print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    except Exception as e:
                        traceback.print_exc()

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
                    # AES-256-CTR + Blowfish
                elif algorithm == "AES-256-CTR + Blowfish":
                    try:
                        # AES-256-CTR Encryption
                        nonce1, ciphertext1, enc_time_256 = aes_256_ctr_encrypt(packet, key_256)
                        print(f"AES-256-CTR Encryption Time: {enc_time_256:.6f} seconds")

                        # Blowfish Encryption
                        iv, ciphertext2, enc_time_blowfish = blowfish_encrypt(ciphertext1, key_256)
                        print(f"Blowfish Encryption Time: {enc_time_blowfish:.6f} seconds")

                        # Blowfish Decryption
                        decrypted_blowfish, dec_time_blowfish = blowfish_decrypt(ciphertext2, key_256, iv)
                        print(f"Blowfish Decryption Time: {dec_time_blowfish:.6f} seconds")

                        # AES-256-CTR Decryption
                        final_plaintext, dec_time_256 = aes_256_ctr_decrypt(decrypted_blowfish, key_256, nonce1)
                        print(f"AES-256-CTR Decryption Time: {dec_time_256:.6f} seconds")

                        # Sum up encryption and decryption times
                        encryption_time = enc_time_256 + enc_time_blowfish
                        decryption_time = dec_time_256 + dec_time_blowfish

                        print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                        print(f"Total Decryption Time: {decryption_time:.6f} seconds")
                        result["encryption_time"] = encryption_time
                        result["decryption_time"] = decryption_time

                    except Exception as e:
                        traceback.print_exc()
                # AES-128-CTR + AES-256-CTR + ChaCha20
                elif algorithm == "AES-128-CTR + AES-256-CTR + ChaCha20":
                    try:
                        # AES-128-CTR Encryption
                        nonce1, ciphertext1, enc_time_128 = aes_128_ctr_encrypt(packet, key_128)
                        print(f"AES-128-CTR Encryption Time: {enc_time_128:.6f} seconds")

                        # AES-256-CTR Encryption
                        nonce2, ciphertext2, enc_time_256 = aes_256_ctr_encrypt(ciphertext1, key_256)
                        print(f"AES-256-CTR Encryption Time: {enc_time_256:.6f} seconds")

                        # ChaCha20 Encryption
                        nonce3, ciphertext3, enc_time_chacha = chacha20_encrypt(ciphertext2, key_256)
                        print(f"ChaCha20 Encryption Time: {enc_time_chacha:.6f} seconds")

                        # ChaCha20 Decryption
                        decrypted_chacha, dec_time_chacha = chacha20_decrypt(ciphertext3, key_256, nonce3)
                        print(f"ChaCha20 Decryption Time: {dec_time_chacha:.6f} seconds")

                        # AES-256-CTR Decryption
                        decrypted_aes_256, dec_time_256 = aes_256_ctr_decrypt(decrypted_chacha, key_256, nonce2)
                        print(f"AES-256-CTR Decryption Time: {dec_time_256:.6f} seconds")

                        # AES-128-CTR Decryption
                        final_plaintext, dec_time_128 = aes_128_ctr_decrypt(decrypted_aes_256, key_128, nonce1)
                        print(f"AES-128-CTR Decryption Time: {dec_time_128:.6f} seconds")

                        # Sum up encryption and decryption times
                        encryption_time = enc_time_128 + enc_time_256 + enc_time_chacha
                        decryption_time = dec_time_128 + dec_time_256 + dec_time_chacha

                        print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                        print(f"Total Decryption Time: {decryption_time:.6f} seconds")
                        result["encryption_time"] = encryption_time
                        result["decryption_time"] = decryption_time

                    except Exception as e:
                        traceback.print_exc()


            # Admin
            elif method == "Admin":
            #  AES-192-CTR + AES-256-CTR + ChaCha20 + HMAC-SHA512 + ECC (Curve25519)
             if algorithm == "AES-192-CTR + AES-256-CTR + ChaCha20 + HMAC-SHA512 + ECC (Curve25519)":
                
                    enc_time_192 = enc_time_256 = enc_time_chacha20 = enc_time_hmac = enc_time_ecc = 0
                    dec_time_192 = dec_time_256 = dec_time_chacha20 = dec_time_hmac = dec_time_ecc = 0
                    # Encryption Process
                    # AES-192-CTR Encryption
                    nonce1, ciphertext1, enc_time_192 = aes_192_ctr_encrypt(packet, key_192)
                    print(f"AES-192-CTR Encryption Time: {enc_time_192}")

                    # AES-256-CTR Encryption
                    nonce2, ciphertext2, enc_time_256 = aes_256_ctr_encrypt(ciphertext1, key_256)
                    print(f"AES-256-CTR Encryption Time: {enc_time_256}")

                    # ChaCha20 Encryption
                    nonce3, ciphertext3, enc_time_chacha20 = chacha20_encrypt(ciphertext2, key_256)
                    print(f"ChaCha20 Encryption Time: {enc_time_chacha20}")

                    # HMAC-SHA512 Authentication
                    start_hmac_enc = time.time()
                    hmac_result, hmac_time = hmac_sha512(hmac_key, ciphertext3)
                    end_hmac_enc = time.time()
                    enc_time_hmac = end_hmac_enc - start_hmac_enc
                    print(f"HMAC-SHA512 Encryption Time: {enc_time_hmac}")

                    # ECC Encryption (Curve25519)
                   
                    # Generate ECC key pairs for sender and recipient
                    private_key, public_key = generate_ecc_keypair()
                    peer_private_key, peer_public_key = generate_ecc_keypair()
                    # Derive shared secret using ECDH
                    shared_secret = ecdh_shared_secret(private_key, peer_public_key)
                    # Encrypt ChaCha20 ciphertext with the shared secret
                    nonce_ecc, ciphertext_ecc, tag_ecc,enc_time_ecc = ecc_encrypt_with_shared_secret(ciphertext3, shared_secret)
                    # Decryption Process
                    # ECC Decryption
                    decrypted_data_ecc, dec_time_ecc = ecc_decrypt_with_shared_secret(ciphertext_ecc, shared_secret, nonce_ecc, tag_ecc)
                    # HMAC-SHA512 Verification
                    start_hmac_dec = time.time()
                    hmac_valid = hmac_sha512_verify(hmac_key, decrypted_data_ecc, hmac_result)
                    end_hmac_dec = time.time()
                    dec_time_hmac = end_hmac_dec - start_hmac_dec
                    print(f"HMAC-SHA512 Decryption Time: {dec_time_hmac}")

                    if not hmac_valid:
                        raise ValueError("HMAC verification failed!")

                    # ChaCha20 Decryption
                    plaintext2, dec_time_chacha20 = chacha20_decrypt(decrypted_data_ecc, key_256, nonce3)
                    print(f"ChaCha20 Decryption Time: {dec_time_chacha20}")

                    # AES-256-CTR Decryption
                    plaintext1, dec_time_256 = aes_256_ctr_decrypt(plaintext2, key_256, nonce2)
                    print(f"AES-256-CTR Decryption Time: {dec_time_256}")

                    # AES-192-CTR Decryption
                    final_plaintext, dec_time_192 = aes_192_ctr_decrypt(plaintext1, key_192, nonce1)
                    print(f"AES-192-CTR Decryption Time: {dec_time_192}")

                    # Sum up encryption and decryption times
                    encryption_time = enc_time_192 + enc_time_256 + enc_time_chacha20 + enc_time_hmac + enc_time_ecc
                    decryption_time = dec_time_192 + dec_time_256 + dec_time_chacha20 + dec_time_hmac + dec_time_ecc

                    print(f"Total Encryption Time: {encryption_time}")
                    print(f"Total Decryption Time: {decryption_time}")

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
              # 6. AES-256-CTR + ChaCha20 + ECC (Curve25519)
            #  AES-256-CTR + ChaCha20 + ECC (Curve25519)
             elif algorithm == "AES-256-CTR + ChaCha20 + ECC (Curve25519)":
                    enc_time_256 = enc_time_chacha = enc_time_ecc = 0
                    dec_time_256 = dec_time_chacha = dec_time_ecc = 0
                    # Encrypt using AES-192-CTR
                    nonce1, ciphertext1, enc_time_256 = aes_256_ctr_encrypt(packet, key_256)

                    # Encrypt using ChaCha20
                    nonce2, ciphertext2, enc_time_chacha = chacha20_encrypt(ciphertext1, key_256)

                    # ECC encryption (ECDH for key exchange)
                    private_key, public_key = generate_ecc_keypair()
                    peer_private_key, peer_public_key = generate_ecc_keypair()
                    shared_secret = ecdh_shared_secret(private_key, peer_public_key)
                    
                    # Simulate ECC encryption using the shared secret
                    nonce_ecc, ciphertext_ecc, tag_ecc,enc_time_ecc = ecc_encrypt_with_shared_secret(ciphertext2, shared_secret)

                    # Decrypt ECC-encrypted data
                    decrypted_data,dec_time_ecc = ecc_decrypt_with_shared_secret(ciphertext_ecc, shared_secret, nonce_ecc, tag_ecc)

                    # Decrypt ChaCha20 ciphertext
                    decrypted_chacha, dec_time_chacha = chacha20_decrypt(decrypted_data, key_256, nonce2)

                    # Decrypt AES-192-CTR ciphertext
                    final_plaintext, dec_time_256 = aes_256_ctr_decrypt(decrypted_chacha, key_256, nonce1)

                    # Total encryption and decryption times
                    encryption_time = enc_time_256 + enc_time_chacha + enc_time_ecc
                    decryption_time = dec_time_256 + dec_time_chacha + dec_time_ecc

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")

                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
            # AES-128-CTR + Blowfish + ChaCha20 + HMAC-SHA512
             elif algorithm == "AES-128-CTR + Blowfish + ChaCha20 + HMAC-SHA512":

                try:
                    enc_time_128 = enc_time_blowfish = enc_time_chacha = enc_time_hmac = 0
                    dec_time_128 = dec_time_blowfish = dec_time_chacha = dec_time_hmac = 0
                    # AES-128-CTR Encryption
                    nonce1, ciphertext1, enc_time_128 = aes_128_ctr_encrypt(packet, key_128)
                    print(f"AES-128-CTR Encryption Time: {enc_time_128:.6f} seconds")

                    # Blowfish Encryption
                    iv, ciphertext2, enc_time_blowfish = blowfish_encrypt(ciphertext1, key_256)
                    print(f"Blowfish Encryption Time: {enc_time_blowfish:.6f} seconds")

                    # ChaCha20 Encryption
                    nonce2, ciphertext3, enc_time_chacha = chacha20_encrypt(ciphertext2, key_256)
                    print(f"ChaCha20 Encryption Time: {enc_time_chacha:.6f} seconds")

                    # HMAC-SHA512 Authentication
                    start_hmac_enc = time.time()
                    hmac_result, hmac_time = hmac_sha512(hmac_key, ciphertext3)
                    end_hmac_enc = time.time()
                    enc_time_hmac = end_hmac_enc - start_hmac_enc
                    print(f"HMAC-SHA512 Authentication Time: {enc_time_hmac:.6f} seconds")

                    # HMAC-SHA512 Verification
                    start_hmac_dec = time.time()
                    hmac_valid = hmac_sha512_verify(hmac_key, ciphertext3, hmac_result)
                    end_hmac_dec = time.time()
                    dec_time_hmac = end_hmac_dec - start_hmac_dec
                    print(f"HMAC-SHA512 Verification Time: {dec_time_hmac:.6f} seconds")

                    if not hmac_valid:
                        raise ValueError("HMAC verification failed!")

                    # ChaCha20 Decryption
                    decrypted_chacha, dec_time_chacha = chacha20_decrypt(ciphertext3, key_256, nonce2)
                    print(f"ChaCha20 Decryption Time: {dec_time_chacha:.6f} seconds")

                    # Blowfish Decryption
                    decrypted_blowfish, dec_time_blowfish = blowfish_decrypt(decrypted_chacha, key_256, iv)
                    print(f"Blowfish Decryption Time: {dec_time_blowfish:.6f} seconds")

                    # AES-128-CTR Decryption
                    final_plaintext, dec_time_128 = aes_128_ctr_decrypt(decrypted_blowfish, key_128, nonce1)
                    print(f"AES-128-CTR Decryption Time: {dec_time_128:.6f} seconds")

                    # Sum up encryption and decryption times
                    encryption_time = enc_time_128 + enc_time_blowfish + enc_time_chacha + enc_time_hmac
                    decryption_time = dec_time_128 + dec_time_blowfish + dec_time_chacha + dec_time_hmac

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")
                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time

                except Exception as e:
                    traceback.print_exc()
                    
            
            # AES-128-CTR + Blowfish + ChaCha20 + HMAC-SHA512
             elif algorithm == "AES-256-CTR + Blowfish + ECC (Curve25519)":

                try:
                    enc_time_256 = enc_time_blowfish  = enc_time_ecc = 0
                    dec_time_256 = dec_time_blowfish  = dec_time_ecc = 0
                    # AES-128-CTR Encryption
                    nonce1, ciphertext1, enc_time_256 = aes_256_ctr_encrypt(packet, key_256)
                    print(f"AES-128-CTR Encryption Time: {enc_time_256:.6f} seconds")

                    # Blowfish Encryption
                    iv, ciphertext2, enc_time_blowfish = blowfish_encrypt(ciphertext1, key_256)
                    print(f"Blowfish Encryption Time: {enc_time_blowfish:.6f} seconds")
                    # Generate ECC key pairs for sender and recipient
                    private_key, public_key = generate_ecc_keypair()
                    peer_private_key, peer_public_key = generate_ecc_keypair()
                    # Derive shared secret using ECDH
                    shared_secret = ecdh_shared_secret(private_key, peer_public_key)
                    # Encrypt ChaCha20 ciphertext with the shared secret
                    nonce_ecc, ciphertext_ecc, tag_ecc,enc_time_ecc = ecc_encrypt_with_shared_secret(ciphertext2, shared_secret)
                    # Decryption Process
                    # ECC Decryption
                    decrypted_data_ecc, dec_time_ecc = ecc_decrypt_with_shared_secret(ciphertext_ecc, shared_secret, nonce_ecc, tag_ecc)

                    

                    # Blowfish Decryption
                    decrypted_blowfish, dec_time_blowfish = blowfish_decrypt(decrypted_data_ecc, key_256, iv)
                    print(f"Blowfish Decryption Time: {dec_time_blowfish:.6f} seconds")

                    # AES-128-CTR Decryption
                    final_plaintext, dec_time_256 = aes_256_ctr_decrypt(decrypted_blowfish, key_256, nonce1)
                    print(f"AES-128-CTR Decryption Time: {dec_time_256:.6f} seconds")

                    # Sum up encryption and decryption times
                    encryption_time = enc_time_256 + enc_time_blowfish  + enc_time_ecc
                    decryption_time = dec_time_256 + dec_time_blowfish  + dec_time_ecc

                    print(f"Total Encryption Time: {encryption_time:.6f} seconds")
                    print(f"Total Decryption Time: {decryption_time:.6f} seconds")
                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
                except Exception as e:
                    traceback.print_exc()
                    result["encryption_time"] = encryption_time
                    result["decryption_time"] = decryption_time
        return render_template("index.html", result=result)

    except Exception as e:
        return render_template("index.html", error=str(e))

if __name__ == "__main__":
    app.run(debug=True)
