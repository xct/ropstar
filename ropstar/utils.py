import string
from itertools import cycle
from pwn import *

# Author: xct

def rot13(x):
    x = x.decode()
    rot13 = str.maketrans( 
        "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz", 
        "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")
    return str.translate(x, rot13)


def xor(x, key):
    enc = [ chr(ord(a) ^ ord(b)) for (a,b) in zip(x, cycle(key)) ]
    return ''.join(enc)
    

def save(name, content):
    with open('./'+name+'.txt','wb') as f:
        f.write(content)
    log.info('Saved '+name)

def decode(x):
    if isinstance(x, bytes):
        x = x.decode()
    return x