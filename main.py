from guizero import App, TextBox, Text, PushButton, Box, error, Combo
from encryption import decrypt_private_key
from env import APP_INSTANCES
from connection.receive_socket import ReceiveSocket
from connection.send_socket import SendSocket

import logging
logging.basicConfig()
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)

def initialize_connection():
  global receive_socket, send_socket, instance
  receive_socket = ReceiveSocket(instance['address'], instance['port'])
  send_socket = SendSocket(instance['send_address'], instance['send_port'])
  receive_socket.start()
  send_socket.start()

def create_main_screen():
  global app, instance
  main_box = Box(app)
  Text(main_box, f'Instance: {instance["name"]}')
  Text(main_box, f'Port: {instance["port"]}')

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
    global instance, private_key
    instance = selected_instance
    private_key = decrypted_private_key
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

  create_password_screen()

  global instance, private_key
  instance = None
  private_key = None

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
