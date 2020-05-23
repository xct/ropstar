# Ropstar

Exploits *simple* linux bof challenges involving alsr, nx and to some extend format strings. You can let it get you a shell or specify a win function that is called.

[![asciicast](https://asciinema.org/a/4i9lnxaPirZ6LXygmd1cRQOzT.png)](https://asciinema.org/a/4i9lnxaPirZ6LXygmd1cRQOzT)

## Install

```
mkvirtualenv sploit
pip install -r requirements.txt
```

* Requires python3
* Expects local installation of [libcdatabase](https://github.com/niklasb/libc-database) in /home/user/tools/libcdatabase. To run local exploits make sure you add your local libc to libcdatabase (32-bit & 64-bit versions). Also in \~/tools you need a clone of [ROPgadget](https://github.com/JonathanSalwan/ROPgadget.git) (used for static binary exploitation).


## Examples

Exploit local binary:
```bash
python ropstar.py <name>
```

Run remote:
```bash
python ropstar.py <name> -rhost <address> -rport <port>
```

## Limitations

* a lot, this a just a PoC, expect it to crash on most targets
* we assume we can write enough bytes to put our payload after the return pointer overwrite - when this is not then case ropstar fails

## Tested on

* Bof (https://github.com/TechSecCTF/pwn_challs)
* Rop (https://github.com/TechSecCTF/pwn_challs)
* gimme-your-shell 32-bit & 64-bit (https://github.com/InsecurityAsso/inshack-2019)
* pwn1, pwn2, pwn3 (https://github.com/mishrasunny174/encrypt-ctf)
* speedrun-002 (defcon quals 2019, oooverflow.io)
* ropeasy_updated (https://hackable.ca/)
* buffer-overflow-1, buffer-overflow-2, gets (https://tcode2k16.github.io/blog/posts/picoctf-2018-writeup/binary-exploitation/#authenticate)
* Ropemporium: ret2win32
* various others

Help on this project is welcome! Contact me on twitter: @xct_de.