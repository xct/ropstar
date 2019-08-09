# Ropstar

Exploits *simple* linux bof challenges involving alsr, nx and to some extend format strings. You can let it get you a shell or specify a win function that is called.

[![asciicast](https://asciinema.org/a/RHa8VWAP1ub0h5o8YC0DVokqE.png)](https://asciinema.org/a/RHa8VWAP1ub0h5o8YC0DVokqE)

## Install

* The program expects a local installation of [libcdatabase](https://github.com/niklasb/libc-database) in /home/user/tools/libcdatabase. To run local exploits make sure you add your local libc to libcdatabase (32-bit & 64-bit versions). Also in \~/tools you need a clone of [ROPgadget](https://github.com/JonathanSalwan/ROPgadget.git) (used for static binary exploitation).

* In order to run challenges from hackthebox directly you have to have a '.api_key' file in your home directory containing your api key.

## Examples

The examples assume you create a 'work' subdirectory in the project folder where you copy the target binary into and run the program from.

Exploit local binary:
```bash
python ../ropstar.py ropme
```

Run hackthebox challenge (this required a '.api_key' file in your home directory containing the api key in order to submit the flag)
```bash
python ../ropstar.py ropme -rhost docker.hackthebox.eu -rport 47184 -cid 8
```

## Limitations

* a lot, this a just a PoC
* we assume we can write enough bytes to put our payload after the return pointer overwrite - this is not always the case, so we fail on binaries like oldbridge (hackthebox)


## Tested on

* myapp (hackthebox)
* Ropme (hackthebox)
* Ropmev2 (hackthebox)
* Garbage (hackthebox)
* Bof (https://github.com/TechSecCTF/pwn_challs)
* Rop (https://github.com/TechSecCTF/pwn_challs)
* gimme-your-shell 32-bit & 64-bit (https://github.com/InsecurityAsso/inshack-2019)
* pwn1, pwn2, pwn3 (https://github.com/mishrasunny174/encrypt-ctf)
* speedrun-002 (defcon quals 2019, oooverflow.io)
* ropeasy_updated (https://hackable.ca/)
* buffer-overflow-1, buffer-overflow-2, gets (https://tcode2k16.github.io/blog/posts/picoctf-2018-writeup/binary-exploitation/#authenticate)
* Ropemporium: ret2win32