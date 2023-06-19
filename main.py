from queue import Empty, Queue
import threading
from guizero import App, TextBox, Text, PushButton, Box, error, Combo, select_file
from tkinter.ttk import Progressbar
from encryption import decrypt_private_key, decrypt_session_key, decrypt_message_data, encrypt_session_key, encrypt_message_data, generate_session_key, load_public_key
from env import APP_INSTANCES
from connection.receive_socket import ReceiveSocket
from connection.send_socket import SendSocket
from Crypto.PublicKey import RSA
from datetime import datetime
from file_sender import FileSender
from messages import data_to_messages, Message, MessageType, AesMode
from pathlib import Path
import os

import logging

from queue_processor import QueueProcessor
logging.basicConfig()
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)

def process_ui_message(message: Message):
  global other_public_key, session_key, send_socket, private_key, reciv_progressbar,\
    reciv_percent_text, reciv_filename_text, received_filename, msg_tb,\
    received_file_total_size, received_file_current_size, send_progressbar,\
    send_filename_text, send_percent_text, file_sender

  if message.type.value == MessageType.PUBLIC_KEY.value:
    other_public_key = RSA.import_key(message.data)
    if instance['name'] == 'A':
      encrypted_session_key = encrypt_session_key(session_key, other_public_key)
      LOG.info(f'Sending session key to B')
      session_key_message = Message(AesMode.NONE, MessageType.SESSION_KEY, encrypted_session_key)
      send_socket.send_message(session_key_message.to_bytes())
      # Instances are connected
      change_connection_status_connected()

  if message.type.value == MessageType.SESSION_KEY.value:
    session_key = message.data.decode()
    LOG.info(f'Received session key: {session_key}')
    file_sender.set_session_key(session_key)
    change_connection_status_connected()

  if message.type.value == MessageType.MESSAGE.value:
    text_message = message.data.decode()
    LOG.info(f'Received message: {text_message}')
    append_message_to_textbox(instance['other'], text_message)

  if message.type.value == MessageType.FILE_BEGIN.value:
    message_text = message.data.decode()
    LOG.debug(f'Received file begin message: {message_text}')
    try:
      split_text = message_text.split(',')
      received_filename = split_text[0]
      received_file_total_size = int(split_text[1])
      received_file_current_size = 0
      set_progressbar_percent(reciv_progressbar, reciv_percent_text, 0, received_file_total_size)
      reciv_filename_text.value = received_filename
    except:
      LOG.error('File begin message is incorrect')

  if message.type.value == MessageType.FILE_CHUNK.value:
    received_file_current_size += int(message.data.decode())
    set_progressbar_percent(reciv_progressbar, reciv_percent_text, received_file_current_size, received_file_total_size)
  
  if message.type.value == MessageType.UI_FILE_BEGIN.value:
    send_filename_text.value = message.data.decode()

  if message.type.value == MessageType.UI_FILE_CHUNK.value:
    set_progressbar_percent(send_progressbar, send_percent_text, int(message.data.decode()), 100)


def process_ui_queue():
  global ui_queue
  ui_msgs: list[Message] = []
  last_chunk_msg = None
  while not ui_queue.empty():
    try:
      message: Message = ui_queue.get_nowait()
      ui_msgs.append(message)
      if message.type.value == MessageType.UI_FILE_CHUNK.value:
        last_chunk_msg = message
    except Empty:
        pass
  filtered = list(filter(lambda msg: msg.type.value != MessageType.UI_FILE_CHUNK.value, ui_msgs))
  # LOG.debug(f'Messages: {len(ui_msgs)}, Filtered: {len(filtered)}')
  for msg in filtered:
    process_ui_message(msg)
  if last_chunk_msg:
    process_ui_message(last_chunk_msg)
  app.after(200, process_ui_queue)

def initialize_connection():
  global receive_socket, send_socket, instance, receive_queue, session_key, send_queue
  receive_socket = ReceiveSocket(instance, receive_queue)
  session_key = None
  if instance['name'] == 'A':
    session_key = generate_session_key(32)
  send_queue = Queue()
  send_socket = SendSocket(instance, session_key, change_connection_status_not_connected, send_queue)
  receive_socket.start()
  send_socket.start()

def start_file_sender():
  global file_sender, file_queue, ui_queue, session_key, send_queue

  file_sender = FileSender(file_queue, ui_queue, send_queue)
  file_sender.start()
  file_sender.set_session_key(session_key)


def start_queue_processor():
  global queue_processor, receive_queue, private_key, session_key

  queue_processor = QueueProcessor(receive_queue, ui_queue)
  queue_processor.start()
  queue_processor.set_private_key(private_key)
  queue_processor.set_session_key(session_key)

def enter_msg_key_pressed(event_data):
  global enter_msg_tb, session_key, aes_mode_combo
  if event_data.key == '\r' and enter_msg_tb.value:
    message = enter_msg_tb.value
    enter_msg_tb.value = ''
    # Check chosen aes mode
    encrypted_data = None
    mode = AesMode.CBC if aes_mode_combo.value == 'CBC' else AesMode.ECB
    encrypted_data = encrypt_message_data(message.encode(), session_key, mode)
    encrypted_message = Message(mode, MessageType.MESSAGE, encrypted_data)
    send_socket.send_message(encrypted_message.to_bytes())
    append_message_to_textbox(instance['name'], message)

def send_file_button_clicked():
  selected = select_file('Select file to send')
  if not selected:
    LOG.debug('No file selected')
    return
  LOG.debug(f'Selected file: {selected}')
  selected_path = Path(selected)
  mode = AesMode.CBC if aes_mode_combo.value == 'CBC' else AesMode.ECB
  file_queue.put_nowait((selected_path, mode))

def append_message_to_textbox(author: str, msg: str):
  time_string = datetime.now().strftime("%H:%M:%S")
  msg_tb.value += f'[{time_string}] {author}: {msg}'
  msg_tb.tk.see('end')

def set_progressbar_percent(progressbar: Progressbar, progressbar_percent_text: Text, count: int, out_of: int):
  progressbar['value'] = count*100.0/out_of
  percent = min(int(count*100.0/out_of), 100)
  progressbar_percent_text.value = f'{percent}%'

def change_connection_status_connected():
  global connection_text, chat_box, file_box
  connection_text.value = 'Connected'
  connection_text.text_color = 'green'
  chat_box.enable()
  file_box.enable()
  aes_mode_combo.enable()

def change_connection_status_not_connected():
  global connection_text, chat_box, file_box, msg_tb
  connection_text.value = 'Not connected'
  connection_text.text_color = 'red'
  chat_box.disable()
  file_box.disable()
  aes_mode_combo.disable()
  msg_tb.value = ''

def create_main_screen():
  global app, instance, send_socket, enter_msg_tb, msg_tb, aes_mode_combo,\
    send_progressbar, connection_text, chat_box, file_box, send_file_button,\
    send_filename_text, send_percent_text, reciv_filename_text, reciv_progressbar,\
    reciv_percent_text
  main_box = Box(app, width='fill', height='fill')
  padding = 10
  Box(main_box, align='top', width='fill', height=padding)
  Box(main_box, align='bottom', width='fill', height=padding)
  Box(main_box, align='left', width=padding, height='fill')
  Box(main_box, align='right', width=padding, height='fill')
  main_box.text_size = 12
  top_box = Box(main_box, align='top', width='fill', height='fill')
  chat_box = Box(main_box, align='top', width='fill', height=230)
  chat_box.disable()
  left_box = Box(top_box, align='left', width=120, height='fill')
  Text(left_box, f'Instance: {instance["name"]}')
  Text(left_box, 'Status:')
  connection_text = Text(left_box, 'Not connected', color='red')
  # Text(left_box, f'Port: {instance["port"]}')
  aes_mode_combo = Combo(left_box, ['CBC', 'ECB'], 'CBC', align='bottom')
  aes_mode_combo.disable()
  Text(left_box, 'Aes mode:', align='bottom')
  file_box = Box(top_box, align='left', width='fill', height='fill')
  file_box.disable()
  send_box = Box(file_box, align='top', width='fill', height=70)
  reciv_box = Box(file_box, align='top', width='fill', height=70)
  # PushButton(send_box, test_clicked, (), 'Test', align='left')
  send_file_button = PushButton(send_box, send_file_button_clicked, (), 'Send file', align='left')
  send_pb_box = Box(send_box, width='fill', height='fill', align='left')
  send_filename_text = Text(send_pb_box, '', align='top')
  send_percent_text = Text(send_pb_box, '0%', align='right')
  send_progressbar = Progressbar(send_pb_box.tk, orient='horizontal', length=130, mode='determinate')
  send_progressbar.pack()
  open_downloads_button = PushButton(reciv_box, os.system, ['xdg-open ./download'], 'Folder', align='left')
  reciv_pb_box = Box(reciv_box, width='fill', height='fill', align='left')
  reciv_filename_text = Text(reciv_pb_box, '', align='top')
  reciv_percent_text = Text(reciv_pb_box, '0%', align='right')
  reciv_progressbar = Progressbar(reciv_pb_box.tk, orient='horizontal', length=130, mode='determinate')
  reciv_progressbar.pack()
  enter_msg_tb = TextBox(chat_box, '', width='fill', align='bottom')
  enter_msg_tb.focus()
  enter_msg_tb.when_key_pressed = enter_msg_key_pressed
  msg_tb = TextBox(chat_box, '', width='fill', align='bottom',
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
    start_queue_processor()
    start_file_sender()
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

  global receive_queue, ui_queue, file_queue
  receive_queue = Queue()
  ui_queue = Queue()
  file_queue = Queue()

  create_password_screen()

  global instance, private_key
  instance = None
  private_key = None

  app.after(100, process_ui_queue)
  app.when_key_pressed = on_key_press
  app.display()

  # Cleanup
  try:
    send_socket.stop()
  except:
    pass
  try:
    receive_socket.stop()
  except:
    pass
  try:
    queue_processor.stop()
  except:
    pass
  try:
    file_sender.stop()
  except:
    pass

if __name__ == '__main__':
  main()
