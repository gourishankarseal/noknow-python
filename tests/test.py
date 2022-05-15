import getpass
try:
    p = getpass.getpass(prompt='Enter password')
except:
    raise Exception('entered password incorrect')
print('Password entered:', p)