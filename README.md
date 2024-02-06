from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes
from Crypto import Random

# Secret Key
key = b'MySuperSecretKey'

# Generate a random initialization vector (IV)
iv = Random.new().read(16)

# Create an AES cipher object in CTR mode
cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
encryptor = cipher.encryptor()

# Get user input for plaintext
plaintext = 'General Kenobi: Years ago, you served my father in the Clone Wars... The rebellion is alright. Bye Obi-Wan Kenobi!'

# Pad the plaintext
padder = padding.PKCS7(algorithms.AES.block_size).padder()
padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()

# Encrypt and print ciphertext
ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
print(ciphertext)
print()

# Decryption steps

# Create an AES cipher object in CTR mode for decryption
decryptor = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend()).decryptor()

# Decrypt and unpad the decoded text
decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
unpadded_text = unpadder.update(decrypted_text) + unpadder.finalize()

print(unpadded_text.decode('utf-8'))
