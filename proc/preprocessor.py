#!/usr/bin/python

import re,os
import string
import pickle
from collections import OrderedDict 

MESSENGER_VAR = 'Messenger'

CMDS = {'@begin':('NES',False),			# o
		'@end':('NES',False),			# o
		'@loop':('LOOP',False),			# o
		'@while':('LOOP',True),			# o
		'@endloop':('LOOP',False),		# o
		'@if':('COND',True),			# o
		'@elseif':('COND',True),		# o
		'@else':('COND',False),			# o
		'@endif':('COND',False),		# o
		'@var':('DECL',True),			# o
		'@ass':('DECL',True),			# o
		'@ass*':('DECL',True),			# o
		'@ass&':('DECL',True),			# o
		'@del':('DECL',True),			# o
		'@let':('DECL',True),			# o
		'@vass':('DECL',True),			# o
		'@vass*':('DECL',True),			# o
		'@vass&':('DECL',True),			# o
		'@vdel':('DECL',True),			# o
		'@pass':('GRAM',False),			# o
		'@mouse':('EXEC',True),			# o
		'@exec':('EXEC',True),			# o
		'@jmp':('SIGHT',True),			# o
		'@exit':('SIGHT',True),			# o
		'@input':('SIGHT',True),		# o
		'@console':('SIGHT',True),		# o
		'@msg':('SIGHT',True),			# o
		'@wait':('SIGHT',True),			# o
		'@ndef':('RETURN',True),		# o		global function
		'@def':('RETURN',True),			# o		global function
		'@return':('RETURN',True),		# o
		'@call':('RETURN',True),		# o		global function call
		'@alloc':('RETURN',True),		# o		global function call
		'//':('COMMENT',False),			# o
		'#namespace':('INCLUDE',False)	# o
		}


class Preprocessor(object):
	def __init__(self):
		self.start_flag = 0
		self.indent 	= 0
		self.is_if		= 0
		self.keep		= 0	
		self.loop		= []
		self.cond		= []
		self.jmp		= []
		self.func		= []
		self.namespace	= True
		self.funcaddr	= OrderedDict()
		self.execute 	= []
	def __tokenize(self,script_path,present):
		lineno 		= 0
		self.total	= 0
		with open(script_path,'r') as file:
			for line in file:
				lineno 		+= 1
				self.total  += 1
				pvc = line.strip().split(' ',1)
				if pvc[0] == '//' or pvc == ['']:
					self.total -= 1
					continue
				elif pvc[0] == '@begin' and script_path == present:
					self.indent += 1
					self.start_flag += 1
					self.namespace	= script_path
					self.keep		= self.namespace
					self.__insert_line(lineno,pvc)
					self.__insert_line(lineno,['@var',"str {0} = null".format(MESSENGER_VAR)])
					continue
				elif pvc[0] == '@begin':
					self.indent += 1
					self.start_flag += 1
					self.namespace	= script_path
					self.keep		= self.namespace
				elif self.start_flag and pvc[0] == '#namespace':
					return [None,"{0}: namespace keyword cannot be used in body area.".format(lineno)]
				elif not self.start_flag and pvc[0] == '#namespace':
					sc = present.split(os.sep)
					sc.pop(-1)
					sc = str.join(os.sep,sc)
					if os.path.exists(pvc[1]) == True:
						ret = self.__tokenize(pvc[1],present)
						if ret[0] == None:return ret
					elif os.path.exists(sc+os.sep+pvc[1]) == True:
						ret = self.__tokenize(sc+os.sep+pvc[1],present)
						if ret[0] == None:return ret
					else:return [None,"{0}: cannot found file '{1}'.".format(lineno,pvc[1])]
					continue
				elif pvc[0] == '@end' and self.start_flag:
					self.start_flag -= 1
					if self.start_flag:continue
				elif pvc[0] in ['@loop','@while']:
					self.loop.append(self.total)
				elif pvc[0] == '@endloop':
					try:
						cur = self.loop.pop()
						pvc = ['@jmp',-self.total+cur-1]
						self.execute[cur-1][2] = self.total
					except:return [None,"{0}: cannot found loop/while statement(s) boundary area.".format(lineno)]
				elif pvc[0] in ('@if','@elseif','@else'):
					self.cond.append([pvc[0],self.total])
				elif pvc[0] == '@endif':
					try:
						cur = self.cond.pop()
						self.execute[cur[1]][2] = self.total
					except:return [None,"{0}: cannot found if statement(s) boundary area.".format(lineno)]
				elif pvc[0] == '@jmp':
					try:self.jmp.append([self.total,lineno,int(pvc[1])])
					except:return [None,"{0}: jumping out of range".format(lineno)]
				elif pvc[0] == '@ndef':
					if   len(pvc)<=1:return [None,"{0}: There is no function name.".format(lineno)]
					elif len(pvc)==2:param = None
					else:return [None,"{0}: too many parameter".format(lineno)]
					self.func.append([self.total,pvc[1],1])
					self.funcaddr.update({pvc[1]:[pvc[1],self.total,self.total,pvc[1],param]})
					self.namespace = pvc[1]
				elif pvc[0] == '@def':
					if   len(pvc)<=1:return [None,"{0}: There is no function name.".format(lineno)]
					elif len(pvc)==2:param = None
					elif len(pvc)==3:param = pvc[2]
					else:return [None,"{0}: too many parameter".format(lineno)]
					self.func.append([self.total,pvc[1],0])
					self.funcaddr.update({pvc[1]:[pvc[1],self.total,self.total,pvc[1],param]})
					self.namespace = pvc[1]
				elif pvc[0] == '@return':
					try:
						cur = self.func.pop()
						self.execute[cur[0]-1][2] = self.total
						sem = pvc[1].split(' ',1)
						cur = self.funcaddr.pop(cur[1])
						self.funcaddr.update({cur[0]:[cur[0],cur[1],self.total,cur[3],cur[4]]})
						self.namespace = self.keep
						if sem[0] == 'void':self.__insert_line(lineno,['@pass'])	
						else:self.__insert_line(lineno,['@vass*',"{0} {1} = {2}".format(sem[0],MESSENGER_VAR,sem[1])])
						continue
					except:return [None,lineno]
				elif pvc[0] == '@call':
					try:
						pointer = self.funcaddr.get(pvc[1])
						cursor	= pointer[1]
						while True:
							if pointer[2]-cursor<0:break
							self.execute.append(self.execute[cursor])
							cursor 		+= 1
							self.total  += 1
						self.keep = self.namespace
						continue
					except:return [None,lineno]
				elif pvc[0] == '@alloc':
					pvc = pvc[1].strip().split('=')
					if len(pvc)!=2:return [None,lineno]
					try:
						pointer = self.funcaddr.get(pvc[1].strip())
						cursor	= pointer[1]
						while True:
							if pointer[2]-cursor<=0:
								val = self.execute[cursor-1][4]
								val = val.split(' ',1)
								self.__insert_line(lineno,['@ass*',"{0} {1} = {2}".format(val[0],pvc[0].strip(),MESSENGER_VAR)])
								break
							self.execute.append(self.execute[cursor])
							cursor 		+= 1
							self.total  += 1
						self.keep = self.namespace
						continue
					except:return [None,lineno]	
				elif pvc[0] == '@del':
					if pvc[1].strip() == MESSENGER_VAR:
						return [None,"{0}: It is not allowed removing '{1}' variable .".format(lineno,MESSENGER_VAR)]
				elif pvc[0] == '@let':
					tvr = pvc[1].strip().split('=')[0].split()[1].strip()
					if tvr == MESSENGER_VAR:
						return [None,"{0}: It is not allowed declaring '{1}' variable in lib.".format(lineno,MESSENGER_VAR)]
				line = [lineno,self.indent,self.total]+pvc+[self.namespace]
				self.execute.append(line)
				for i in self.jmp:
					if lineno==(i[2]):
						self.execute[i[0]-1] = [i[1],self.indent,self.total,'@jmp',self.total-i[0]]
						self.jmp.remove(i)
						break
		return self.execute
	def __insert_line(self,lineno,pvc):
		self.execute.append([lineno,+self.indent,self.total]+pvc+[self.namespace])

	def __check_line(self,line,niro):
		if   line == None:niro = False
		elif line[0] == None:return line[1]
		elif line[3] not in CMDS.keys():return 'nokeyword'
		else:
			if CMDS.get(line[3],False)[1] == True:
				if len(line)!=6:return 'formaterror'
			return 0
	def compile(self,file):
		print ('[Compiler] : Read script from "{0}"...'.format(file))
		present	= file
		niro = True
		try:lines 	= self.__tokenize(file,present)
		except:
			print ('[Compiler] : Error emerged while tokenization')
			return False
		for line in lines:
			print(line)
			error = self.__check_line(line,niro)
			if niro == False:return line
			if error:
				print ('[Compiler] : < Error Code {0} > {1} : Script grammar error '.format(error,line))
				return line
		lines[-1][1] = -1
		file = file.split('.')[0]
		with open(file+'.tlc', 'wb') as handle:
			pickle.dump(lines, handle)
		print ('[Compiler] : Compiled Compeleted.')
		return True


if __name__ == '__main__':
	
	comp = Preprocessor()
	comp.compile('syscall')
