from queue import Empty, Queue
from guizero import App, TextBox, Text, PushButton, Box, error, Combo
from encryption import decrypt_private_key, decrypt_session_key, encrypt_session_key, generate_session_key, load_public_key
from env import APP_INSTANCES
from connection.receive_socket import ReceiveSocket
from connection.send_socket import SendSocket
from Crypto.PublicKey import RSA

import logging
logging.basicConfig()
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)

def process_receive_queue():
  global other_public_key, session_key, send_socket, private_key, receive_queue
  while not receive_queue.empty():
    try:
      data: bytes = receive_queue.get_nowait()
      first_byte = data[0].to_bytes(1, "big")
      if first_byte == b'p':
        other_public_key = RSA.import_key(data[1:])
        LOG.info('Received other public key')
        if instance['name'] == 'A':
          encrypted_session_key = encrypt_session_key(session_key, other_public_key)
          LOG.info(f'Sending session key to B')
          send_socket.send_message(b's' + encrypted_session_key)
      if first_byte == b's':
        encrypted_session_key = data[1:]
        session_key = decrypt_session_key(encrypted_session_key, private_key)
        LOG.info(f'Received session key: {session_key}')
    except Empty:
      pass
    


def initialize_connection():
  global receive_socket, send_socket, instance, receive_queue, session_key
  receive_socket = ReceiveSocket(instance, receive_queue)
  session_key = None
  if instance['name'] == 'A':
    session_key = generate_session_key(50)
  send_socket = SendSocket(instance, session_key)
  receive_socket.start()
  send_socket.start()

def send_public_key():
  send_socket.send_message(b'AAAAUUUUUUUGH')

def create_main_screen():
  global app, instance
  main_box = Box(app)
  Text(main_box, f'Instance: {instance["name"]}')
  Text(main_box, f'Port: {instance["port"]}')
  PushButton(main_box, send_public_key, [], 'Send public key')

def log_in():
  global pwd_tb, pwd_box, instance_combo
  entered_pwd = pwd_tb.value
  pwd_tb.value = ''

  selected_instance = APP_INSTANCES[instance_combo.value]
  decrypted_private_key = decrypt_private_key(entered_pwd, selected_instance['private_name'])
  if decrypted_private_key:
    LOG.info('Password accepted')
    LOG.debug('Closing password screen')
    pwd_box.disable()
    pwd_box.visible = False
    LOG.debug('Saving private key to memory')
    global instance, private_key, public_key
    instance = selected_instance
    private_key = decrypted_private_key
    public_key = load_public_key(instance['public_name'])
    LOG.debug('Initializing main screen')
    create_main_screen()
    initialize_connection()

  else:
    LOG.info('Invalid password')
    error('Error', 'Invalid password. Try again.')

def on_key_press(event_data):
  global pwd_box
  if event_data.key == '\r' and pwd_box.visible == True:
    log_in()

def create_password_screen():
  global app, pwd_box, pwd_tb, instance_combo
  pwd_box = Box(app)
  pwd_box.text_size = 20
  Box(pwd_box, width='fill', height=150)
  instance_box = Box(pwd_box)
  instance_label = Text(instance_box, 'App Instance: ', align='left')
  instance_combo = Combo(instance_box, ['A', 'B'], align='left')
  pwd_label = Text(pwd_box, 'Enter password:')
  pwd_tb = TextBox(pwd_box, '' ,hide_text=True)
  pwd_button = PushButton(pwd_box, log_in, text='Ok')
  pwd_tb.focus()

def main():
  global app
  app = App('BSK', 400, 400)
  app.font = 'Ubuntu'

  global receive_queue
  receive_queue = Queue()

  create_password_screen()

  global instance, private_key
  instance = None
  private_key = None

  app.repeat(100, process_receive_queue)
  app.when_key_pressed = on_key_press
  app.display()

  # Cleanup
  global send_socket, receive_socket
  if send_socket:
    send_socket.stop()
  if receive_socket:
    receive_socket.stop()


if __name__ == '__main__':
  main()
