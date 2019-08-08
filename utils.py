import string
from itertools import cycle
from pwn import *

# Author: xct

def rot13(x):
	rot13 = string.maketrans( 
	    "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz", 
	    "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")
	return string.translate(x, rot13)


def xor(x, key):
	enc = [ chr(ord(a) ^ ord(b)) for (a,b) in zip(x, cycle(key)) ]
	return ''.join(enc)
	

def save(name, content):
	with open('./'+name+'.txt','wb') as f:
		f.write(content)
	log.info('Saved '+name)


def fix_pie(chain, base, args):
    fixed = []
    for i in chain:
        if i not in args:
            try:
                i += base
            except TypeError:
                pass
        fixed.append(i)
    log.info("Chain:")
    for i in fixed:
        try:
            print(hex(i))
        except TypeError:
            print(i)
            pass
    return fixed