from guizero import App, TextBox, Text, PushButton, Box, error
from encryption import is_password_valid

def validate_password():
  global pwd_tb
  entered_pwd = pwd_tb.value
  pwd_tb.value = ''

  if is_password_valid(entered_pwd):
    global pwd_box
    pwd_box.disable()
    pwd_box.visible = False
  else:
    error('Error', 'Invalid password. Try again.')


def on_key_press(event_data):
  global app, pwd_tb, pwd_box
  if event_data.key == '\r' and pwd_box.visible == True:
    validate_password()


def main():
  global app, pwd_box, pwd_tb
  app = App('BSK', 400, 400)
  app.text_size = 20

  pwd_box = Box(app)
  Box(pwd_box, width='fill', height=150)
  pwd_label = Text(pwd_box, 'Enter password:')
  pwd_tb = TextBox(pwd_box, '' ,hide_text=True)
  pwd_button = PushButton(pwd_box, validate_password, text='Ok')
  pwd_tb.focus()
  
  app.when_key_pressed = on_key_press
  app.display()


if __name__ == '__main__':
  main()
