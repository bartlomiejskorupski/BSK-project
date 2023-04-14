from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from hashlib import sha256

def pwd_to_hash(pwd: str) -> bytes:
  pwd_hash = sha256(pwd.encode('utf-8'))
  local_key = pwd_hash.digest()
  return local_key

def load_encrypted_private_key() -> bytes:
  with open('./keys/private/A.key', 'r') as pk_file:
    return b64decode(pk_file.read())

def is_password_valid(pwd: str) -> bool:
  pwd_hash = pwd_to_hash(pwd)

  encrypted_private_key = load_encrypted_private_key()
  init_vector, data = encrypted_private_key[:AES.block_size], encrypted_private_key[AES.block_size:]

  try:
    cipher = AES.new(pwd_hash, AES.MODE_CBC, init_vector)
    decrypted_bytes = unpad(cipher.decrypt(data), AES.block_size)
    decrypted_private_key = decrypted_bytes.decode('utf-8')
    return True
  except ValueError:
    return False


