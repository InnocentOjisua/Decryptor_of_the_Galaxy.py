from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random

# Secret Key
key = b'MySuperSecretKey'

# Generate a random initialization vector (IV)
iv = Random.new().read(16)

# Create a counter for CTR mode
ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))

# Create an AES cipher object in CTR mode
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

# Get user input for plaintext
plaintext = 'General Kenobi: Years ago, you served my father in the Clone Wars... The rebellion is alright. Bye Obi-Wan Kenobi!'

# Encrypt and print ciphertext
ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
print(ciphertext)
print()

# Decryption steps

# Create a counter for the decryptor using the same IV
ctr_decrypt = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))

# Create the AES cipher object in CTR mode for decryption
decipher = AES.new(key, AES.MODE_CTR, counter=ctr_decrypt)

# Decrypt and print the decoded text
decoded_text = decipher.decrypt(ciphertext).decode('utf-8')
print(decoded_text)
