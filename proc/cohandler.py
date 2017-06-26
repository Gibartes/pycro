#!/usr/bin/python3


from processor import *

TOKEN = '/r/n/r/n'

class Cohandler(Process):
	def __init__(self,iface,port,que):
		Process.__init__(self)
		self.host 	= self.__get_ip_address(iface)
		self.port 	= port
		self.pair 	= rsa.newkeys(1024,poolsize=4)
		self.dsep 	= os.sep
		self.n	  	= os.linesep
		self.switch = True
		self.target = None
		self.path 	= PATH
		self.usage	= 0
		self.aes	= AESCipher(code)
		self.que	= que
		os.chdir(self.path)
		if DESP =='/':
			setproctitle.setproctitle("pycrohandler")

	def __get_ip_address(self,iface):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		if platform.system().lower() == 'windows':			
			return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', iface[:15]))[20:24])
		else:
			return subprocess.getoutput("/sbin/ifconfig %s" % iface).split("\n")[1].split()[1]

	def __create_socket_as_host(self):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind((self.host,self.port))
		sock.listen(1)
		sock.settimeout(2.0)
		return sock

	def __create_socket_as_receiver(self,port):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.settimeout(2.0)
		ptime = 0	
		while ptime<20:
			try:
				sock.connect((self.host,port))
				return sock
			except:
				sleep(0.2)
				ptime+=0.2


	def __set_status(self,text):
		pico = stat('r')
		if pico == READOUT:self.__status('w',text)
		else:self.que.put(text)
		return pico

	def __retrive(self):
		pico = stat('r')
		if pico != READOUT:
			if self.que.empty():pass
			else:
				text = self.que.get()
				self.__stat('w',text)
		else:pass

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

	def __status(self,mode,data):				
		if mode == 'r':
			try:
				with open(self.path+'.stat','r') as file:
					return file.read()
			except:return False
		elif mode == 'w':
			with open(self.path+'.stat','w') as file:
				file.write(data)

	def encrypt(self,plain):
		return rsa.encrypt(plain.encode(),self.target)

	def decrypt(self,crypt):
		if crypt == b'':return ''
		return rsa.decrypt(crypt,self.pair[1]).decode()

	def recv(self,msg):
		msg = self.decrypt(msg)
		#except:return False
		return msg

		"""
			login process :

			1) get "login" -> "980" or "400"
			2) get target rsa public key -> "980" or "400"
			3) get password(encrypted) -> "980" or "400"

		"""

	def login(self,sock):
		data = sock.recv(1024)
		if data != b'login':
			sock.send('400'.encode())
			return False
		else:
			tmp = re.findall(r"\d+",str(self.pair[0]))
			tmp ='|'.join(tmp)
			sock.send(tmp.encode())						# send rsa key
		self.target = sock.recv(2048).decode()			# get target rsa public key
		self.target = self.target.split('|')
		self.target = rsa.key.PublicKey(int(self.target[0]),int(self.target[1]))
		sock.send('#980'.encode())
		data = self.recv(sock.recv(8172))
		if data != '#400':
			sock.send('#400'.encode())
			return False
		else:sock.send('#980'.encode())
		password = self.recv(sock.recv(2048))
		with open(self.path+'.usr','rb') as file:
			recorded = self.aes.decrypt(file.read().strip())
		if password.encode() == recorded and recorded is not False:
			sock.send(self.encrypt('#980'))
			port = self.recv(sock.recv(2048))
			try:
				sock.send(self.encrypt('#980'))
				conn = self.__create_socket_as_receiver(int(port))
				conn.send(self.encrypt('#lunatic'))
				return (conn,port)
			except:sock.send(self.encrypt('#400'))
		else:sock.send(self.encrypt('#400'))
		return False


	""" [Action] Controlling Processor """

	def action_Runner(self,sock):
		target_file = self.recv(sock.recv(2048))
		if os.path.isfile(target_file) == False:
			if os.path.isfile(self.path+'scripts'+self.dsep+target_file) == False:
				sock.send(self.encrypt('#400'))
				return False
		sock.send(self.encrypt('#200'))
		file = open(self.path+'scripts'+self.dsep+'__default__','r')
		if len(target_file.split(self.dsep))==1:
			target_file = self.path+'scripts'+self.dsep+target_file
		if file.read().strip() == target_file:pass
		else:
			file = open(self.path+'scripts'+self.dsep+'__default__','w')
			file.write(target_file)
		file.close()
		self.__set_status('\psetscript')
		return True

	def action_Stop(self):self.__set_status('\pimmediate_stop')	# present task down

	def action_Console(self):self.__set_status('\pkonsole')		# go to the console control mode

	def action_Shutdown(self):self.__status('w','\pshutdown')		# shutdown controller (not server host) but included

	def action_Nothing(self):self.__set_status('\pidle')		# go to the idle mode

	""" [Action] Setting """

	def action_PasswordChange(self,sock):
		password = self.recv(sock.recv(2048))
		with open(self.path+'.usr','rb') as file:
			recorded = self.aes.decrypt(file.read().strip())
		if password.encode() == recorded and recorded is not False:
			sock.send(self.encrypt('#200'))
			password = self.recv(sock.recv(2048))
			if   password is False:return False
			elif password == '' or len(password)<8:
				sock.send(self.encrypt('#240'))
				return False
			else:
				with open(self.path+'.usr','wb') as file:
					file.write(self.aes.decrypt(password.strip()))
				sock.send(self.encrypt('#200'))
				return True
		else:
			sock.send(self.encrypt('#400'))
			return False

	def action_ChangePort(self,sock):
		new_port = self.recv(sock.recv(2048))
		try:
			new_port 	= int(new_port)
			return self.__setav('port',new_port)
		except:
			sock.send(self.encrypt('#400'))
			return False

	def action_uploadScript(self,conn):
		name = self.recv(conn.recv(2048))
		if os.path.isfile(name) == False:return False
		with open(name,'rb') as file:
			conn.sendall(self.encrypted(file.readlines()))
		return True

	def action_downloadScript(self,conn):
		header = self.recv(conn.recv(2048))
		if header is False:	# fake value|file name & path|file_size
			conn.send(self.encrypt('#444'))
			return False
		header = header.split('|')
		fpath  = PATH+'scripts/'
		if len(header)!=5:
			conn.send(self.encrypt('#444'))
			return False
		elif os.path.isfile(fpath+header[1]):
			conn.send(self.encrypt('#201'))	# ask overwritten
			ret = self.recv(conn.recv(2048))
			if ret != '#210':return False
		else:conn.send(self.encrypt('#200'))
		fsize = int(header[2])
		cipher_suite = Fernet(header[3].encode())
		file = open(fpath+header[1],'wb')
		print("[!] pycro : file download : {0}".format(header[1]))
		while fsize>0:
			try:
				data = cipher_suite.decrypt(conn.recv(11020))
				if not data:break
				fsize = fsize - len(data)
				file.write(data)
			except socket.timeout:
				conn.send(self.encrypt('#440'))
				file.close()
				os.remove(header[1])
				return False
			except:
				conn.send(self.encrypt('#448'))
				file.close()
				os.remove(header[1])
				return False
		file.close()
		print('recv:{0}Bytes'.format(header[2]))
		conn.close()
		return False

	def __distrub(self,conn):
		while True:
			try:
				user_input = conn.recv(2048)
				self.__retrive()
				if user_input == b'':continue
				user_input = self.recv(user_input)
				conn.send(self.encrypt('#200'))
				if   user_input == 'l0xfff':
					self.action_Shutdown()
					return False
				elif user_input == 'l0x001':
					self.usage = 0
					self.action_Shutdown()
					return True
				elif user_input == 'l0x002':
					self.action_Runner(conn)
				elif user_input == 'l0x004':
					self.action_Stop()
				elif user_input == 'l0x008':
					self.action_Console()
				elif user_input == 'l0x011':
					self.action_Nothing()
				elif user_input == 'l0x012':
					self.action_PasswordChange(conn)
				elif user_input == 'l0x014':
					self.action_ChangePort(conn)
				elif user_input == 'l0x018':
					 self.action_downloadScript(conn)
				elif user_input == 'l0x020':
					self.action_uploadScript(conn)
				self.__retrive()
			except socket.timeout:self.__retrive()
			except:
				self.usage = 0
				self.action_Shutdown()
				break
		return True

	def run(self):
		print ("[!] pycro : launch success processor")
		try:sock = self.__create_socket_as_host()
		except:
			print ("[!] pycro : create socket error")
			self.switch = False
		while self.switch:
			try:
				print ("\r[*] connection wait...",end="")
				sys.stdout.flush()
				conn, addr	= sock.accept()
				if self.usage == 0:
					self.usage = 1
					ret = self.login(conn)
					if ret is False:
						self.usage = 0
						conn.close()
						del conn, addr
						continue
					print ('\n[*] pycro : connection success {0}'.format(addr))
					Proc = Processor(ret[0],ret[1],self.pair,self.target)
					Proc.start()
					self.__status('w','\pidle')
					self.switch = self.__distrub(conn)
					Proc.join()
				conn.close()
				del conn
			except socket.timeout:continue
			except:
				print ('\n[*] pycro : internal error....')
				self.__status('w','\pshutdown')
				break
		sys.exit(0)

