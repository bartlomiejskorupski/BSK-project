from queue import Empty, Queue
import socket as sock
from threading import Thread, Event
from time import sleep
import select
import selectors
sel = selectors.DefaultSelector()
from messages import Message, MessageType, AesMode

import logging

from encryption import encrypt_session_key, load_public_key
logging.basicConfig()
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)

class SendSocket(Thread):

  def __init__(self, instance, session_key: str, close_callback):
    Thread.__init__(self)
    self.instance = instance
    self.address = instance['send_address']
    self.port = instance['send_port']
    self.int_event = Event()
    self.running = True
    self.message_q: Queue[bytes] = Queue()
    self.public_key = load_public_key(instance['public_name'])
    self.session_key = session_key
    self.close_callback = close_callback

  def __del__(self):
    LOG.debug('Send socket thread stopped')

  def run_old(self):
    LOG.info('Send socket thread started')
    with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as s:
      while self.running:
        try:
          s.connect((self.address, self.port))
          s.sendall(b'p' + self.public_key.export_key('PEM'))
          while self.running:
            while not self.message_q.empty():
              try:
                message_bytes = self.message_q.get()
                # LOG.debug('Im in a toilet sending: ' + message_bytes)
                s.sendall(message_bytes)
              except Empty:
                LOG.debug('Empty queue')
        except Exception as e:
          LOG.info(str(e) + '.\tRetrying in 5s...')
          self.int_event.wait(5)

  def run(self):
    LOG.info('Send socket thread started')
    s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    s.setblocking(False)
    while self.running:
      ret = s.connect_ex((self.address, self.port))
      if ret:
        continue
      # On connection send public key
      pk_message = Message(AesMode.NONE, MessageType.PUBLIC_KEY, self.public_key.export_key('PEM'))
      self.message_q.put_nowait(pk_message.to_bytes())
      LOG.info(f'Connected to {(self.address, self.port)}')
      sel.register(s, selectors.EVENT_READ | selectors.EVENT_WRITE)
      connected = True
      while self.running and connected:
        for key, mask in sel.select(1):
          conn = key.fileobj
          if mask & selectors.EVENT_WRITE:
            while not self.message_q.empty():
              try:
                message_bytes = self.message_q.get()
                # LOG.debug('Im in a toilet sending: ' + message_bytes)
                s.sendall(message_bytes)
              except Empty:
                LOG.debug('Empty queue')
          if mask & selectors.EVENT_READ:
            data = conn.recv(1024)
            LOG.info(f'Socket responded with: {data}')
            if not data:
              LOG.info('Socket closed')
              connected = False
              # Inform main thread the connection was broken
              self.close_callback()
              break
              

  def send_message(self, msg_bytes: bytes):
    self.message_q.put_nowait(msg_bytes)

  def stop(self):
    self.running = False
    self.int_event.set()
