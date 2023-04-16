import socket as sock
from threading import Thread, Event
from time import sleep

import logging
logging.basicConfig()
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)

class SendSocket(Thread):

  def __init__(self, address: str, port: int):
    Thread.__init__(self)
    self.address = address
    self.port = port
    self.int_event = Event()
    self.running = True

  def run(self):
    LOG.info('Send socket thread started')
    with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as s:
      while self.running:
        try:
          s.connect((self.address, self.port))
          while self.running:
            self.int_event.wait(1)
            s.sendall(b'Hello socket')
        except Exception as e:
          LOG.info(str(e) + '.\tRetrying in 5s...')
          self.int_event.wait(5)
    LOG.info('Send socket thread stopped.')

  def stop(self):
    self.running = False
    self.int_event.set()
