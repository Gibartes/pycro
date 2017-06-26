#!/usr/bin/python3

from cohandler import *
import shutil

class Starter:
	def __init__(self):
		self.path 	= PATH
		self.dsep 	= os.sep
		self.n	  	= os.linesep
		self.setup()
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
				file.write(self.__write_line(i[0],i[1]))
		return True
	def __write_line(self,index,content):
		return '{0}:={1}{2}'.format(index,content,self.n)
	def __default_config(self):
		file = open(self.path+'.config','w')
		file.write(self.__write_line('iface','enp2s0'))
		file.write(self.__write_line('port','10730'))
		file.close()
	def read_env(self,target):
		configure	= []
		with open(self.path+'.config','r') as file:
			for line in file:
				line = line.strip().split(':=')
				if len(line)==2:configure.append(line)
		for i in configure:
			if i[0] == target:return i[1]
		return None
	def setup(self):
		print("[*] pycro : checking whether workpath exists...")
		if os.path.exists(self.path) == False:
			os.mkdir(self.path)
		print("[*] pycro : checking whether configure file exists...")
		if os.path.isfile(self.path+'.config') == False:
			self.__default_config()
		if os.path.isfile(self.path+'.usr') == False:
			aes = AESCipher(code)
			file = open(self.path+'.usr','wb')
			file.write(aes.encrypt('pycro'))
			file.close()
		print("[*] pycro : checking whether help message file exists...")
		if os.path.isfile(self.path+'manual') == False:
			cur = os.getcwd() +self.dsep + 'manual'
			shutil.copy(cur,self.path+'manual')
		print("[*] pycro : checking whether script files are posed correctly...")
		if os.path.isdir(self.path+self.dsep+'scripts') == False:
			os.mkdir(self.path+self.dsep+'scripts')
		print("[*] pycro : checking script loader...")
		if os.path.isfile(self.path+'scripts'+DESP+'__default__') == False:
			with open(self.path+'scripts'+DESP+'__default__','w') as file:
				file.write('__default__')
		print("[*] pycro : checking up session is now completed.")
		print("----------------------------------------------------------------")

if __name__ == '__main__':

	def signal_handler(signal,frame):
		print("\n[*] pycro : Interrupted. Shutdown.")
		if platform.system().lower() == 'windows':pass
		else:os.system('sudo pkill -9 "pycro"')
		sys.exit(0)

	signal.signal(signal.SIGINT, signal_handler)
	signal.signal(signal.SIGPIPE,signal.SIG_DFL)
	
	os.system("reset")
	print("\n\t\t<< pycro >>\n\n\t\t\t\tversion 1.0.0\n\n\n")
	print("[*] pycro : loaded checking up session.")
	que 	= Queue(64)
	starter = Starter()
	iface   = starter.read_env('iface')
	port	= int(starter.read_env('port'))
	handler	= Cohandler(iface,port,que)
	handler.start()
