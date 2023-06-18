from queue import Empty, Queue
from guizero import App, TextBox, Text, PushButton, Box, error, Combo
from encryption import decrypt_private_key, decrypt_session_key, decrypt_text_message, encrypt_session_key, encrypt_text_message_cbc, encrypt_text_message_ecb, generate_session_key, load_public_key
from env import APP_INSTANCES
from connection.receive_socket import ReceiveSocket
from connection.send_socket import SendSocket
from Crypto.PublicKey import RSA
from datetime import datetime
from messages import data_to_messages, Message, MessageType, AesMode

import logging
logging.basicConfig()
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)

def process_message(message: Message):
  global other_public_key, session_key, send_socket, private_key

  msg_type = message.type

  if msg_type.value == MessageType.PUBLIC_KEY.value:
    other_public_key = RSA.import_key(message.data)
    LOG.info('Received other public key')
    if instance['name'] == 'A':
      encrypted_session_key = encrypt_session_key(session_key, other_public_key)
      LOG.info(f'Sending session key to B')
      session_key_message = Message(AesMode.NONE, MessageType.SESSION_KEY, encrypted_session_key)
      send_socket.send_message(session_key_message.to_bytes())

  if msg_type.value == MessageType.SESSION_KEY.value:
    encrypted_session_key = message.data
    session_key = decrypt_session_key(encrypted_session_key, private_key)
    LOG.info(f'Received session key: {session_key}')

  if msg_type.value == MessageType.MESSAGE.value:
    global msg_tb
    decrypted_message = decrypt_text_message(message, session_key)
    if decrypted_message:
      LOG.info(f'Received message: {decrypted_message}')
      append_message_to_textbox(instance['other'], decrypted_message)

def process_receive_queue():
  global receive_queue
  while not receive_queue.empty():
    try:
      data: bytes = receive_queue.get_nowait()

      messages = data_to_messages(data)
      for message in messages:
        process_message(message)

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
  global enter_msg_tb, session_key, aes_mode_combo
  if event_data.key == '\r' and enter_msg_tb.value:
    message = enter_msg_tb.value
    enter_msg_tb.value = ''
    # Check chosen aes mode
    encrypted_message = None
    if aes_mode_combo.value == 'CBC':
      encrypted_message = encrypt_text_message_cbc(message, session_key)
    else: 
      encrypted_message = encrypt_text_message_ecb(message, session_key)
    send_socket.send_message(encrypted_message.to_bytes())
    append_message_to_textbox(instance['name'], message)
  
def test_clicked():
  pass

def append_message_to_textbox(author: str, msg: str):
  time_string = datetime.now().strftime("%H:%M:%S")
  msg_tb.value += f'[{time_string}] {author}: {msg}'
  msg_tb.tk.see('end')

def create_main_screen():
  global app, instance, send_socket, enter_msg_tb, msg_tb, aes_mode_combo
  main_box = Box(app, width='fill', height='fill')
  padding = 10
  Box(main_box, align='top', width='fill', height=padding)
  Box(main_box, align='bottom', width='fill', height=padding)
  Box(main_box, align='left', width=padding, height='fill')
  Box(main_box, align='right', width=padding, height='fill')
  main_box.text_size = 14
  top_box = Box(main_box, align='top', width='fill', height='fill')
  bottom_box = Box(main_box, align='top', width='fill', height=260)
  left_box = Box(top_box, align='left', width=100, height='fill', border=True)
  Text(left_box, f'Instance: {instance["name"]}')
  Text(left_box, f'Port: {instance["port"]}')
  # PushButton(left_box, test_clicked, (), 'Test')
  Text(left_box, 'Aes mode:')
  aes_mode_combo = Combo(left_box, ['CBC', 'ECB'], 'CBC')
  enter_msg_tb = TextBox(bottom_box, '', width='fill', align='bottom')
  enter_msg_tb.focus()
  enter_msg_tb.when_key_pressed = enter_msg_key_pressed
  msg_tb = TextBox(bottom_box, '', width='fill', align='bottom',
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
