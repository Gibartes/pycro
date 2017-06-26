import socket,struct,fcntl,rsa
import os,platform,subprocess


TOKEN		= '/r/n/r/n'

MOVE 		= 1
SCROLL		= 2
LEFT_SHRT 	= 3
RGHT_SHRT	= 4 
LEFT_LONG	= 5
LEFT_LONGx	= 6
LEFT_DBLE	= 7
RGHT_DBLE	= 8



if platform.system().lower() == 'windows':
	PATH = 'C\\Program Files\\pycro\\'
else:
	PATH = '/usr/share/pycro/'

def stat(mode,data=''):
	if mode == 'r':
		try:
			with open(PATH+'.stat','r') as file:return file.read()
		except:return False
	elif mode == 'w':
		with open(PATH+'.stat','w') as file:file.write(data)


class Singleton(object):
	def __init__(cls,name,bases,dict):
		super(Singleton, cls).__init__(name,bases,dict)
		cls.instance = None 
	def __call__(cls,*args,**kwargs):
		if cls.instance is None:
			cls.instance = super(Singleton,cls).__call__(*args,**kwargs)
		return cls.instance

class ECR():
	def __init__(self):pass

class variable():
	def __init__(self,name,contents):
		self.name 		= name
		self.contents 	= contents
	def __del__(self):pass

class _link(object):
	def __init__(self,id,val):
		self.id 	= id
		self.val	= val
		self.prev	= None
		self.next	= None


class Chain(Singleton):
	def __init__(self):
		self.head		= None
		self.tail		= None
		self.keep		= None
	def add(self,id,val):
		new_link = _link(id,val)
		if self.head is None:
			self.head = self.tail = new_link
		else:
			new_link.prev	= self.tail
			new_link.next	= None
			self.tail.next	= new_link
			self.tail		= new_link
	def rem(self,id):
		current 		= self.head
		while current is not None:
			if current.id == id:
				if current.prev is not None:
					current.prev.next = current.next
					try:current.next.prev = current.prev
					except:current.prev.next = None
				else:
					self.head = current.next
					current.next.prev = None
			current = current.next
	def __spew(self,id,val=None):
		current 		= self.head
		while current is not None:
			if current.id == id:
				if val==None:return current.val
				else:
					current.val = val
					return ECR()
				self.keep = current
			else:current = current.next
		return ECR()
	def qick(self,did,val=None):
		if self.keep is None:
			return self.__spew(did,val)
		elif self.keep.id == did:
			if val==None:return self.keep.val
			else:return self.__spew(did,val)
		else:return self.__spew(did,val)

