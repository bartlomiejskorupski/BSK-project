from Crypto.Cipher import PKCS1_OAEP
from encryption import load_public_key, decrypt_private_key, generate_session_key, encrypt_session_key, decrypt_session_key
from base64 import b64encode, b64decode



def main():
  public_key = load_public_key('A.pub')
  session_key = generate_session_key(50)
  private_key = decrypt_private_key('admin', 'A.key')

  encrypted_session_key = encrypt_session_key(session_key, public_key)
  decrypted_session_key = decrypt_session_key(encrypted_session_key, private_key)

  print(session_key)
  print(decrypted_session_key)





if __name__ == '__main__':
  main()