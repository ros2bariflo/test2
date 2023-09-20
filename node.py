import os
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Simulated device information
devEUI = "0011223344556677"
appKey = "00112233445566778899AABBCCDDEEFF"  # Application Key

# Generate NwkSKey and AppSKey using AppKey
def generate_session_keys(app_key, dev_eui):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=16 * 2,  # 16 bytes for NwkSKey + 16 bytes for AppSKey
    )
    key_material = kdf.derive(app_key.encode() + dev_eui.encode())
    nwk_skey = key_material[:16]
    app_skey = key_material[16:]
    return nwk_skey, app_skey

# Encrypt message using AppSKey with PKCS7 padding
def encrypt_message(app_skey, message):
    cipher = AES.new(app_skey, AES.MODE_ECB)
    padded_message = pad(message, AES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    return ciphertext

# Calculate LoRaWAN MIC using CMAC
def calculate_mic(nwk_skey, app_skey, dev_eui, message):
    print(message)
    # Frame counter and direction
    direction_uplink = True  # Replace with your direction flag
    frame_counter = 1  # Replace with your frame counter
    # Prepare data for MIC calculation
    data = struct.pack(">BQ", 0x49, frame_counter) + dev_eui.encode() + message
    if direction_uplink:
        data += bytes([0x00, 0x00, 0x00, 0x00])  # Append 4 zero bytes for uplink

    # Ensure data length is a multiple of block size (16 bytes)
    remaining_bytes = len(data) % AES.block_size
    if remaining_bytes > 0:
        padding_bytes = AES.block_size - remaining_bytes
        data += bytes([padding_bytes] * padding_bytes)

    # Perform MIC calculation using NwkSKey
    mic_cipher = AES.new(nwk_skey, AES.MODE_ECB)
    mic = mic_cipher.encrypt(data)[-4:]

    return mic

if __name__ == "__main__":
    nwkSKey, appSKey = generate_session_keys(appKey, devEUI)
    # Original message
    message = b"This is a secret message!"

    # Encrypt the message using AppSKey
    encrypted_message = encrypt_message(appSKey, message)
 

    # Calculate MIC
    mic = calculate_mic(nwkSKey, appSKey, devEUI, encrypted_message)

    # Save keys, encrypted message, and MIC to a file
    with open("node_data.txt", "wb") as file:
        file.write(appSKey)
        file.write(nwkSKey)
        
    with open("mic.txt","w") as f:
        f.write(str(mic))
        
    with open("enc.txt","wb") as f:
        f.write(encrypted_message)

