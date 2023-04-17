from queue import Empty, Queue
from guizero import App, TextBox, Text, PushButton, Box, error, Combo
from encryption import decrypt_private_key, decrypt_session_key, decrypt_text_message, encrypt_session_key, encrypt_text_message, generate_session_key, load_public_key
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
      message_bytes = data[1:]
      if first_byte == b'p':
        other_public_key = RSA.import_key(message_bytes)
        LOG.info('Received other public key')
        if instance['name'] == 'A':
          encrypted_session_key = encrypt_session_key(session_key, other_public_key)
          LOG.info(f'Sending session key to B')
          send_socket.send_message(b's' + encrypted_session_key)
      if first_byte == b's':
        encrypted_session_key = message_bytes
        session_key = decrypt_session_key(encrypted_session_key, private_key)
        LOG.info(f'Received session key: {session_key}')
      if first_byte == b'm':
        global msg_tb
        decrypted_message = decrypt_text_message(message_bytes, session_key)
        if decrypted_message:
          LOG.info(f'Received message: {decrypted_message}')
          msg_tb.value += decrypted_message
          msg_tb.tk.see('end')
    except Empty:
      pass
    
def initialize_connection():
  global receive_socket, send_socket, instance, receive_queue, session_key
  receive_socket = ReceiveSocket(instance, receive_queue)
  session_key = None
  if instance['name'] == 'A':
    session_key = generate_session_key(32)
  send_socket = SendSocket(instance, session_key)
  receive_socket.start()
  send_socket.start()

def enter_msg_key_pressed(event_data):
  global enter_msg_tb, session_key
  if event_data.key == '\r' and enter_msg_tb.value:
    message = enter_msg_tb.value
    enter_msg_tb.value = ''
    encrypted_message = encrypt_text_message(message, session_key)
    send_socket.send_message(b'm'+encrypted_message)
  
def test_clicked():
  send_socket.send_message(b'mAUUUUUUGHHHH')


def create_main_screen():
  global app, instance, send_socket, enter_msg_tb, msg_tb
  main_box = Box(app, width='fill', height='fill')
  padding = 10
  Box(main_box, align='top', width='fill', height=padding)
  Box(main_box, align='bottom', width='fill', height=padding)
  Box(main_box, align='left', width=padding, height='fill')
  Box(main_box, align='right', width=padding, height='fill')
  main_box.text_size = 14
  Text(main_box, f'Instance: {instance["name"]}')
  Text(main_box, f'Port: {instance["port"]}')
  PushButton(main_box, test_clicked, (), 'Test')
  enter_msg_tb = TextBox(main_box, '', width='fill', align='bottom')
  enter_msg_tb.focus()
  enter_msg_tb.when_key_pressed = enter_msg_key_pressed
  msg_tb = TextBox(main_box, '', width='fill', align='bottom',
    height=10, multiline=True, scrollbar=True, enabled=False)

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
    initialize_connection()
    create_main_screen()

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
  Box(pwd_box, width='fill', height=100)
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
  try:
    send_socket.stop()
    receive_socket.stop()
  except:
    pass


if __name__ == '__main__':
  main()
