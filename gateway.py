from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import struct

# Simulated device information (replace with your actual devEUI)
devEUI = "0011223344556677"

# Read keys, encrypted message, and MIC from the node
with open("node_data.txt", "rb") as file:
    appSKey = file.read(16)
    nwkSKey = file.read(16)
    # Adjust this based on your message size
received_mic = open("mic.txt","r").read()
encrypted_message =  open("enc.txt","rb").read()




# Decrypt the message using AppSKey
def decrypt_message(app_skey, encrypted_message):
    cipher = AES.new(app_skey, AES.MODE_ECB)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message

# Verify MIC for the received message
def verify_mic(nwk_skey, dev_eui, message,received_mic):
    # Frame counter and direction
    direction_uplink = True  # Replace with your direction flag
    frame_counter = 2  # Replace with your frame counter
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
    return (str(received_mic) == str(mic))

if __name__ == "__main__":
    # Decrypt the message using AppSKey
    decrypted_message = decrypt_message(appSKey,encrypted_message)

    # Verify MIC
    mic_valid = verify_mic(nwkSKey,  devEUI, encrypted_message,received_mic)
    

    if mic_valid:
        print("MIC is valid. Message integrity confirmed.")
        # Optionally, unpad the decrypted message if PKCS7 padding was applied
        unpadded_message = unpad(decrypted_message, AES.block_size)
        print("Decrypted Message:", unpadded_message.decode())
    else:
        print("MIC is not valid. Message may have been tampered with.")
