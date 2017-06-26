#!/usr/bin/python3

import base64,string,random
import socket,struct,fcntl,rsa,signal
import sys,platform,subprocess
import pyscreenshot as ImageGrab
from multiprocessing import *
from time import *

from pynput.keyboard import Key, Controller
from pynput.mouse import Button
import pynput.mouse as hdl
from preprocessor import *
from dtype import *
from cryptography.fernet import Fernet
code 	= b'wSH^pGf[ioi; iK_Ujs*+-yu2TTPtk;p'

from Crypto import Random
from Crypto.Cipher import AES

def id_generator(size=18, chars=string.ascii_uppercase + string.digits):
	return ''.join(random.choice(chars) for _ in range(size))
	
class AESCipher:
	def __init__(self,key):
		self.bs	 = 32
		self.key = key
	def encrypt( self, raw ):
		raw = self._pad(raw)
		iv = Random.new().read( AES.block_size )
		cipher = AES.new( self.key, AES.MODE_CBC, iv )
		return base64.b64encode( iv + cipher.encrypt( raw ) )
	def decrypt( self, enc ):
		enc = base64.b64decode(enc)
		iv = enc[:AES.block_size]
		cipher = AES.new(self.key, AES.MODE_CBC, iv )
		return self._unpad(cipher.decrypt( enc[AES.block_size:] ))
	def _pad(self, s):
		return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
	@staticmethod
	def _unpad(s):
		return s[:-ord(s[len(s)-1:])]


READOUT		= '\p$read'

KEYS_SHRT	= {'\pbsp':Key.backspace,
			 '\pdel':Key.delete,
			 '\ptab':Key.tab,
			 '\palf':Key.left,
			 '\parg':Key.right,
			 '\paup':Key.up,
			 '\padw':Key.down,
			 '\pret':Key.enter,
			 '\pesc':Key.esc,
			 }

KEY_COMBO	= { '\pctrl' :Key.ctrl_l,
				'\palt'  :Key.alt_l,
				'\pshift':Key.shift_l}

DESP		= os.sep

console_break = ( '\pimmediate_stop','\pshutdown' ,'\pidle' )


if platform.system().lower() == 'windows':
	PATH = 'C{0}Program Files{1}pycro{2}'.format(DESP,DESP,DESP)
else:
	import setproctitle
	PATH = '/usr/share/pycro/'


class Processor(Process):
	def __init__(self,conn,port,keys,target):
		Process.__init__(self)
		self.chain 	 	= Chain()
		self.vchain 	= Chain()
		self.path		= PATH
		self.conn		= conn
		self.port		= port
		self.decode		= keys[0]
		self.key		= keys[1]
		self.target		= target
		self.command 	= []
		self.caps_mode	= 0
		self.keyboard	= 0
		self.cursor  	= 0
		self.size 	 	= 0
		self.mode		= 1
		self.aes		= AESCipher(code)
		self.conn.settimeout(0.005)
		self.SMAIN		= ''
		os.chdir(self.path)
		if DESP =='/':setproctitle.setproctitle("pycrocessor")

	def __readout(self):
		pico = stat('r')
		if pico != READOUT:stat('w',READOUT)
		return pico
	def __encrypt(self,plain):
		return rsa.encrypt(plain.encode(),self.target)

	def __decrypt(self,crypt):
		if crypt == b'':return ''
		return rsa.decrypt(crypt,self.key).decode()

	def __recv(self,msg):
		try:msg = self.__decrypt(msg)
		except:return False
		return msg

	def __read_script(self,file):
		try:
			with open(file, 'rb') as handle:
				unpickler = pickle.Unpickler(handle)
				self.command = unpickler.load()
			self.size = len(self.command)
			return True
		except:return False

	def __compile_script(self,file):
		Compiler = Preprocessor()
		return Compiler.compile(file)

	def __reset(self):
		self.chain 	 	= Chain()
		self.vchain 	= Chain()
		self.command 	= []
		self.cursor  	= 0
		self.ifs	 	= []
		self.elses		= []
		self.combo	 	= False
		self.switch  	= True
		self.combotank	= []

	def __set_memory(self,var,val,mq,fmt=0):			# var,ass,get,del
		if   fmt == 0:pass
		elif fmt == 'int':
			try:val = int(val)
			except:return ECR()
		elif fmt == 'float':
			try:val = float(val)
			except:return ECR()
		else:
			try:val = str(val)
			except:return ECR()
		if   mq == 0:self.chain.add(var,val)			# register
		elif mq == 1:self.chain.qick(var,val)			# replace
		elif mq == 2:return self.chain.qick(var,None)	# read
		elif mq == 3:
			if var == MESSENGER_VAR:return ECR()
			else:self.chain.rem(var)					# remove
		return ECR()

	def __set_virutal_memory(self,var,val,mq,fmt=0):	# var,ass,get,del
		if   fmt == 0:pass
		elif fmt == 'int':
			try:val = int(val)
			except:return ECR()
		elif fmt == 'float':
			try:val = float(val)
			except:return ECR()
		else:
			try:val = str(val)
			except:return ECR()
		namespace = self.command[self.cursor][-1]
		if   mq == 0:self.vchain.add([namespace,var],val)				# register
		elif mq == 1:
			if var == MESSENGER_VAR:
				tps = self.vchain.qick([namespace,val],ECR)
				if type(tps) != ECR:val = tps
				self.chain.qick(var,val)
			else:self.vchain.qick([namespace,var],val)					# replace
		elif mq == 2:return self.vchain.qick([namespace,var],None)		# read
		elif mq == 3:self.vchain.rem([namespace,var])					# remove
		return ECR()

	def __jmp(self,level,content):						# jmp code
		if self.command[self.cursor + content][1] != self.command[self.cursor][1]:return False
		self.cursor += content
		return True

	def __find_start_point(self):
		indent = self.command[-2][1]
		count  = 0 
		for i in self.command:
			if i[1] == indent:return count
			else:count+=1
		return -1

	def __input(self,keyhandle,content):
		if content.startswith('"') and content.endswith('"'):pass
		elif content.startswith("'") and content.endswith("'"):pass
		else:
			content = content.strip()
			temp 	= self.__set_virutal_memory(content,None,2,None)
			if type(temp) == ECR:
				temp = self.__set_memory(content,None,2,None)
				if type(temp) == ECR:return ECR()
			content = str(temp)
		keyhandle.type(content)

	def __isfloat(self,value):
		try:return float(value)
		except:return None

	def __test(self,boolean):							# test statement
		try:
			if bool(eval(boolean)):return True	
			else:return False
		except:pass
		obj = list(filter(None,re.split(' ',boolean)))
		ns = self.command[self.cursor][-1]
		dst = None
		hst = obj[2]
		
		if self.SMAIN == ns:
			dst = self.__set_memory(obj[0],0,2)
			if hst.startswith('"') and hst.endswith('"'):pass
			elif   self.__isfloat(hst) is not None:
				if abs(float(hst)-int(hst)) == float(0):hst = int(hst)
				else:hst = float(hst)
			else:hst = self.__set_memory(obj[2],0,2)
			if type(dst) == ECR or type(hst) == ECR:return False
		else:
			dst = self.__set_virutal_memory(obj[0],0,2)
			if hst.startswith('"') and hst.endswith('"'):pass
			elif   self.__isfloat(hst) is not None:
				if abs(float(hst)-int(hst)) == float(0):hst = int(hst)
				else:hst = float(hst)
			else:hst = self.__set_virutal_memory(obj[2],0,2)
			if type(dst)==ECR():
				dst = self.__set_memory(obj[0],0,2)			
			if type(hst)==ECR():
				hst = self.__set_memory(obj[2],0,2)
			if type(dst) == ECR or type(hst) == ECR:return False

		if   type(dst) != type(hst):return False
		elif obj[1] == '==':return bool(dst == hst)
		elif obj[1] == '>=':return bool(dst >= hst)
		elif obj[1] == '<=':return bool(dst >= hst)
		elif obj[1] == '>':return bool(dst > hst)
		elif obj[1] == '<':return bool(dst < hst)
		elif obj[1] == '!=':return bool(dst != hst)
		else:return False

	def __actuator(self,handle,data):					# mouse move action x y
		data = data.split()
		try:data = list(map(int, data))
		except:
			self.keyboard = True
			return 1
		if   data[0] == MOVE:
			if len(data)==3:					# relative
				handle.move(data[1],data[2])
			elif len(data)==4:					# absolute
				handle.position = (0, 0)
				handle.move(data[2],data[3])
			else:return 1
		elif data[0] == LEFT_SHRT and self.switch:
			handle.press(Button.left)
			handle.release(Button.left)
		elif data[0] == RGHT_SHRT and self.switch:
			handle.press(Button.right)
			handle.release(Button.right)	
		elif data[0] == LEFT_DBLE and self.switch:
			handle.click(Button.left, 2)
		elif data[0] == LEFT_LONG:
			handle.press(Button.left)
			self.switch = False
		elif data[0] == LEFT_LONGx:
			handle.release(Button.left)
			self.switch = True
		else:
			self.keyboard = True
			return 1
		return 0

	def __exit(self):									# exit (go to the end)
		self.cursor = self.size - 1

	def __key_input(self,keyhandle,content):
		keyhandle.type(content)

	def __keyboard(self,keyhandle,buffer):	
		if   buffer in KEYS_SHRT.keys():
			if self.combo:
				for i in self.combotank:keyhandle.press(i)
			keyhandle.press(KEYS_SHRT[buffer])
			keyhandle.release(KEYS_SHRT[buffer])
			if self.combo:
				for i in self.combotank:keyhandle.release(i)
				self.combo = False
				self.combotank = []
		elif buffer in KEY_COMBO.keys():
			self.combotank.append(KEY_COMBO[buffer])
			self.combo = True		
		elif buffer == '\caps':
			self.caps_mode = 0 if self.caps_mode else 1
		elif buffer == '\pmouse':
			self.keyboard = False

	def __send_dialogue(self,conn,msg):
		try:
			conn.send(self.__encrypt(msg))
			print('[*] pycro_msg : {0}'.format(msg))
		except:return False

	def __setav(self,target,dest):
		configure	= []
		with open(self.path+'.config','r') as file:
			for line in file:
				line = line.split(':=').strip()
				if len(line)==2:configure.append(line)
		for i in configure:
			if i[0] == target:i[1] = dest
		with open(self.path+'.config','w') as file:
			for i in configure:
				sentence = '{0}:={1}{2}'.format(i[0],i[1],self.n)
				file.write(sentence)
		return True

	def __password_ex(self,sock):
		password = self.__recv(sock.recv(2048))
		with open(self.path+'.usr','rb') as file:
			recorded = self.aes.decrypt(file.read().strip())
		if password.encode() == recorded and recorded is not False:
			sock.send(self.__encrypt('#240'))
			password = self.__recv(sock.recv(2048))
			if   password == False:return False
			elif password == '' or len(password)<8:
				sock.send(self.__encrypt('#240'))
				return False
			else:
				with open(self.path+'.usr','wb') as file:
					file.write(self.aes.encrypt(password.strip()))
				sock.send(self.__encrypt('#upix'))
				return True
		else:
			sock.send(self.__encrypt('#400'))
			return False

	def __port_ex(self,sock):
		try:
			new_port = self.__recv(sock.recv(2048))
			new_port = int(new_port)
			return self.__setav('port',new_port)
		except:
			sock.send(self.__encrypt('#400'))
			return False

	def __script_ex(self,sock,script):
		if os.path.isfile(script) == False:
			self.__send_dialogue(sock,conn,"#400")
			return False
		with open(self.path+'scripts'+DESP+'__default__','w') as file:
			file.write(script)

	def __screenshot(self,conn):
		name 	= self.path+'saves'+DESP+'screenshot.png'
		img 	= ImageGrab.grab()
		if os.path.exists(self.path + 'saves') == False:
			os.mkdir(self.path + 'saves')
		img.save(name)
		key = Fernet.generate_key()
		cipher_suite = Fernet(key)
		fsize = os.stat(name).st_size
		conn.send(self.__encrypt('{0}|{1}|{2}|{3}'.format(id_generator(),fsize,key.decode(),id_generator())))
		try:
			if self.__recv(conn.recv(4096))!='#200':return
			file = open(name,'rb')
			while fsize >= 0:
				buffer = file.read(8192)
				s = cipher_suite.encrypt(buffer)
				self.conn.send(s)
				fsize -= 8192
			file.close()
		except:conn.send(self.__encrypt('#400'))
	def __console(self,conn,handle,keyhandle):
		self.keyboard = True
		while True:
			pico =	self.__readout()
			if pico in console_break:return pico
			try:
				buffer = self.__recv(conn.recv(4096))
				if type(buffer) is bool:conn.send(self.__encrypt('#400'))
				else:conn.send(self.__encrypt('#200'))
			except socket.timeout:continue
			except:return pico
			if   buffer == '\psetuppswd':
				self.conn.settimeout(120)
				try:self.__password_ex(conn)
				except:pass
				self.conn.settimeout(0.005)
			elif buffer == '\psetupport':
				self.__port_ex(conn)
			elif buffer in '\psetscript':
				try:self.__script_ex(conn,buffer.split()[1])
				except:self.__keyboard(keyhandle,buffer)
			elif buffer == '\psh':
				self.__screenshot(conn)
			elif buffer == '\pexit':
				stat('w','\pidle')
			elif buffer == '\pmouse':
				if(self.keyboard):self.keyboard = False
				else:self.keyboard = True
			elif self.keyboard:self.__keyboard(keyhandle,buffer)
			else:self.__actuator(handle,buffer)

	def __scriptor(self,conn,handle,keyhandle):
		file 	= open(self.path+'scripts'+DESP+'__default__','r')
		script 	= file.read().strip()
		file.close()
		""" Load Script File """
		script = script.split('.')[0]
		try:
			if self.__read_script(script):
				print("[*] pycro : Read script file success.")
			else:
				print("[*] pycro : Compiled file is not found. compile new script...")
				self.__compile_script(script+'.tl')
				res = self.__read_script(script+'.tlc')
				if res:print("[*] pycro : Read script file success.")
				else:
					print("[*] pycro : Cannot find such [{0}] script file.".format(script))
					return False
			id_level = 0
			print("[*] pycro : Finding start point...")
			self.cursor = self.__find_start_point()
			print("[*] pycro : Found start point. Run script...")
		except:
			print("[*] pycro : [error] Something wrong")
			return False
		self.SMAIN = self.command[-1][-1]
		while self.cursor < self.size:
			pico 			= self.__readout()
			if pico in console_break:return pico
			id_level		= self.command[self.cursor][1]
			returns			= self.command[self.cursor][2]
			opcode 			= self.command[self.cursor][3]
			try:content 	= self.command[self.cursor][4]
			except:content 	= None
			#print(self.command[self.cursor])
			if   opcode	== '@end' and id_level==-1:break
			elif opcode == '@exit':break
			elif opcode == '@while':
				if self.__test(content):pass
				else:self.cursor = returns
			elif opcode == '@if':
				if self.__test(content):
					self.ifs.append([returns,True])
					self.elses.append([returns,True])
				else:
					self.cursor = returns
					self.ifs.append([returns,False])
					self.elses.append([returns,False])
			elif opcode == '@elseif':
				cur = self.ifs.pop()
				if cur[1] == False and abs(cur[0]-self.cursor)==1: 
					if self.__test(content):self.ifs.append([returns,True])
					else:
						self.cursor = returns
						self.ifs.append([returns,False])
						try:
							if self.elses[-1][1] == False:pass
							else:self.elses[-1][1] = True
						except:self.elses.append([returns,False])
				else:
					self.cursor = returns
					self.ifs.append([returns,False])
			elif opcode == '@else':
				try:
					cur = self.ifs.pop()
					elp = self.elses.pop()
					if elp[-1] == False and abs(cur[0]-self.cursor)==1:pass
					else:self.cursor = returns
				except:self.cursor = returns
			elif opcode in ('@var','@ass&','@ass','@ass*','@del','@get'):
				"""
					@del   var
					@var   int var = constant (once declare)	
					@ass   int var = constant
					@ass*  int var = var
					@ass&  str var = ctime()
				"""
				ds = list(filter(None,re.split(' ',content)))
				if   opcode == '@del':
					self.__set_memory(ds[0],None,3)
				elif len(ds)!=4:break
				elif opcode == '@var':
					self.__set_memory(ds[1],ds[3],0,ds[0])
				elif opcode == '@ass':
					self.__set_memory(ds[1],ds[3],1,ds[0])
				elif opcode == '@ass*':
					self.__set_memory(ds[1],self.__set_memory(ds[3],None,2),1,ds[0])
				elif opcode == '@ass&':
					try:self.__set_memory(ds[1],eval(ds[3]),1,ds[0])										
					except:return False
				elif opcode == '@get':
					val = self.__set_memory(ds[1],ds[3],2,ds[0])
			elif opcode in ('@let','@vass&','@vass','@vass*','@vdel'):
				ds = list(filter(None,re.split(' ',content)))
				if   opcode == '@vdel':
					self.__set_virutal_memory(ds[0],None,3)
				elif len(ds)!=4:break
				elif opcode == '@let':
					self.__set_virutal_memory(ds[1],ds[3],0,ds[0])
				elif opcode == '@vass':
					self.__set_virutal_memory(ds[1],ds[3],1,ds[0])
				elif opcode == '@vass*':
					self.__set_virutal_memory(ds[1],self.__set_virutal_memory(ds[3],None,2),1,ds[0])
				elif opcode == '@vass&':
					try:self.__set_virutal_memory(ds[1],eval(ds[3]),1,ds[0])										
					except:return False
				elif opcode == '@get':
					val = self.__set_virutal_memory(ds[1],ds[3],2,ds[0])
			elif opcode == '@jmp':self.__jmp(id_level,content)
			elif opcode == '@input':self.__input(keyhandle,content)
			elif opcode == '@console':self.__console(conn,handle,keyhandle)
			elif opcode == '@msg':self.__send_dialogue(conn,content)
			elif opcode == '@mouse':self.__actuator(handle,content)
			elif opcode == '@exec':os.system(content)							# dangerous
			elif opcode == '@wait':
				try:sleep(float(content))
				except:return False
			else:pass
			self.cursor += 1
		return True

	def __boot(self):
		if os.path.isdir(self.path):
			print("[*] pycro : Target directory exists. Keep going.")
		elif os.path.exists(self.path):
			print("[!] pycro : Already same file exists but this is not directory")
			return 1
		else:
			os.mkdir(self.path)
			print("[*] pycro : Create system directory. Keep going")
		return 0

	def run(self):
		if self.__boot():return 1
		handle 		= hdl.Controller()
		keyhandle 	= Controller()
		while True:
			self.__reset()
			status = self.__readout()
			if   status == '\pshutdown':break
			elif status == '\pkonsole':
				ret = self.__console(self.conn,handle,keyhandle)
				if ret == '\pshutdown':break
				stat('w','\pidle')
			elif status == '\psetscript':
				ret = self.__scriptor(self.conn,handle,keyhandle)
				if ret == '\pshutdown':break
				elif ret == False:
					print("[*] pycro : Error in script exiting.")
				stat('w','\pidle')
			else:sleep(0.5)
		print("[*] pycro : Terminate processor.")
		sys.exit(0)


if __name__ == '__main__':

	def signal_handler(signal,frame):
		if platform.system().lower() == 'windows':pass
		else:os.system('sudo pkill -9 "pycrocessor"')
		sys.exit(0)

	signal.signal(signal.SIGINT, signal_handler)
	signal.signal(signal.SIGPIPE,signal.SIG_DFL)

