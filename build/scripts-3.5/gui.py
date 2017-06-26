#!/usr/bin/python3
# -*- coding: utf-8 -*-
#

import string,random
import os,sys,re
import platform,subprocess
import nmap,time
import threading
import socket,rsa
from cryptography.fernet import Fernet
from preprocessor import *
from multiprocessing import *
from PyQt5.QtWidgets import (QMainWindow, QApplication, QLabel,
							 QAction, qApp, QWidget, QPushButton, 
							 QInputDialog, QLineEdit, QFileDialog,
							 QTextEdit, QTabWidget,QHBoxLayout,
							 QVBoxLayout,QTableWidget,QTableWidgetItem,
							 QMessageBox)

from PyQt5 import QtGui, QtCore
TOKEN = '/r/n/r/n'
column_headers = ['Reg_ID', 'Host','Port', 'Status','Current_Script','Comment']

COMMAND_LIST 	= {
	'shutdown':'l0xfff',
	'quit':'l0x001',
	'run':'l0x002',
	'stop':'l0x004',
	'console':'l0x008',
	'change password':'l0x012',
	'change_port':'l0x014',
	'send':'l0x018',
	'receive':'l0x020'
}

if platform.system().lower() == 'windows':
	PATH = 'C\\Program Files\\pycro\\'
else:
	PATH = '/usr/share/pycro/'

def id_generator(size=18, chars=string.ascii_uppercase + string.digits):
	return ''.join(random.choice(chars) for _ in range(size))

class Editor(QTextEdit):
	def __init__(self, parent=None):
		super(Editor, self).__init__(parent)

class ShowPicture(QWidget):
	def __init__(self,path):
		super().__init__()
		self.path = path
		self.__initUI__()
		self.show()
	def __initUI__(self):
		label = QLabel() 
		pixmap = QPixmap(self.path)
		label.setPixmap(pixmap)

class ConsoleWindow(QWidget):
	def __init__(self,host,Title,rsa):
		self.Title		= Title
		self.host		= host
		self.ip			= ''
		self.port   	= ''
		self.conn		= None
		self.sock		= None
		self.curr		= None
		self.rsa		= rsa
		self.command 	= ''
	def __connect(self):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.settimeout(5.0)
		try:
			self.port  = int(self.port)
			self.lport = self.port + 1
			sock.connect((self.ip,self.port))
			return sock
		except socket.timeout:self.retLabel.setText('Creating socket fail : connection timeout')
		except:self.retLabel.setText('Creating socket fail : peer inet socket error')
		return None

	def __create_socket_as_server(self):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind((self.host,self.lport))
		sock.listen(1)
		conn, addr	= sock.accept()
		return conn

	def encrypt(self,plain):
		if plain == b'':return b''
		return rsa.encrypt(plain.encode(),self.host_key)

	def decrypt(self,crypt):
		return rsa.decrypt(crypt,self.rsa[1]).decode()

	def createWindow(self,WindowWidth,WindowHeight):
		parent=None
		super(ConsoleWindow,self).__init__(parent)
		#self.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
		self.resize(WindowWidth,WindowHeight)
		self.setWindowTitle(self.Title)

		self.ipLabel	= self.create_label("Listening ip address",(40,65))
		self.hostLine	= self.create_Line(WindowWidth,0.2,(160,60),self.onChanged_Host)
		self.portLabel	= self.create_label("Listening Port",(290,65))
		self.portLine	= self.create_Line(WindowWidth,0.16,(380,60),self.onChanged_Port)
		self.pswdLabel	= self.create_label("Password",(40,95))
		self.pswdLine	= self.create_Line(WindowWidth,0.2,(160,90),self.onChanged_Pswd)
		self.acesButton	= self.create_button("Connect",(290,90),self.on_access_click)
		self.dscoButton	= self.create_button("Disconnect",(380,90),self.on_disconnect_click)
		self.retLabel	= self.create_label("Stand by",(40,130))
		self.retLabel.setFixedWidth(WindowWidth*0.84)
		self.retLabel.setStyleSheet("color:green;""font: bold 10pt 'Arial'")
		self.retLabel.setAlignment(QtCore.Qt.AlignCenter)
		self.cmdLabel	= self.create_label("Command",(40,155))
		self.cmdLine	= self.create_Line(WindowWidth,0.84,(40,180),self.onChanged_Cmd)
		self.cmdLine.adjustSize()
		self.cmdLine.setAlignment(QtCore.Qt.AlignCenter)
		self.statLabel	= self.create_label("ready",(10,405))
		self.statLabel.setStyleSheet("color:blue;""font: bold 9pt 'Arial'")
		""" Command Buttons """
		
		self.btn_cmd	= self.create_button("Mode",(150,210),self.mode)
		self.btn_commit	= self.create_button("Commit",(270,210),self.commit)
		self.btn_esp	= self.create_button("Backspace",(60,250),self.clicked_backspace)
		self.btn_del	= self.create_button("Delete",(160,250),self.clicked_delete)
		self.btn_tab	= self.create_button("Tab",(260,250),self.clicked_tab)
		self.btn_ret	= self.create_button("Enter",(360,250),self.clicked_ret)
		self.btn_alf	= self.create_button("←",(60,290),self.clicked_leftarrow)
		self.btn_arg	= self.create_button("→",(160,290),self.clicked_rightarrow)
		self.btn_aup	= self.create_button("↑",(260,290),self.clicked_uparrow)
		self.btn_adw	= self.create_button("↓",(360,290),self.clicked_downarrow)
		self.btn_cap	= self.create_button("capslock",(60,330),self.clicked_capslock)
		self.btn_alt	= self.create_button("alt",(160,330),self.clicked_alt)
		self.btn_ctl	= self.create_button("ctrl",(260,330),self.clicked_ctrl)
		self.btn_win	= self.create_button("mouse",(360,330),self.clicked_win)
		self.btn_sh		= self.create_button("screenshot",(60,370),self.clicked_screenshot)
		self.btn_esc	= self.create_button("esc",(160,370),self.clicked_esc)
		self.btn_exit	= self.create_button("exit",(260,370),self.clicked_exit)
		self.btn_pwc	= self.create_button("setting",(360,370),self.clicked_changepasswd)

		self.showArt	= self.create_label("< ScreenShot >",(500,0))

	def create_label(self,title,position):
		bel	= QLabel(title,self)
		bel.move(position[0],position[1])
		return bel
	def create_button(self,title,position,actioncode):
		btn = QPushButton(title,self)
		btn.move(position[0],position[1])
		btn.clicked.connect(actioncode)
		return btn
	def create_Line(self,WindowWidth,ratio,position,actioncode):
		Line	= QLineEdit(self)
		Line.setFixedWidth(WindowWidth*ratio)
		Line.move(position[0],position[1])
		Line.textChanged[str].connect(actioncode)
		return Line
	def inputDialog(self,title,context):
		text, ok = QInputDialog.getText(self, title, context)
		if ok:return str(text)
		else:return None
	def login(self):
		self.curr = 'disconnected'
		self.statLabel.setText(self.curr)
		self.statLabel.adjustSize()
		conn = self.__connect()
		if conn is None:
			self.curr = 'off'
			self.statLabel.setText(self.curr)
			self.conn = None
			return False
		conn.send('login'.encode())
		self.host_key = conn.recv(2048).decode()
		self.host_key = self.host_key.split('|')
		self.host_key = rsa.key.PublicKey(int(self.host_key[0]),int(self.host_key[1]))
		tmp = re.findall(r"\d+",str(self.rsa[0]))
		tmp ='|'.join(tmp)
		conn.send(tmp.encode())	
		if conn.recv(64).decode()=='#980':
			conn.send(self.encrypt('#400'))
			data = conn.recv(64).decode()
			if data=='#980':pass
			else:
				self.conn = None
				return False
		else:
			conn.send('#400').decode()
			self.conn = None
			return False
		conn.send(self.encrypt(self.password))
		if self.decrypt(conn.recv(2048)) != '#980':
			self.conn = None
			return False
		conn.send(self.encrypt(str(self.lport)))
		if self.decrypt(conn.recv(2048)) != '#980':
			self.conn = None
			return False
		sock = self.__create_socket_as_server()
		if sock is None:return False
		if self.decrypt(sock.recv(2048)) == '#lunatic':
			self.retLabel.setText("Access Success.")
			self.conn = conn
			self.sock = sock
			self.curr = 'ready'
			self.statLabel.setText(self.curr)
		else:return False

	def clicked_backspace(self):
		self.command = '\pbsp'
		self.commit()
	def clicked_delete(self):
		self.command = '\pdel'
		self.commit()
	def clicked_tab(self):
		self.command = '\ptab'
		self.commit()
	def clicked_ret(self):
		self.command = '\pret'
		self.commit()
	def clicked_leftarrow(self):
		self.command = '\palf'
		self.commit()
	def clicked_rightarrow(self):
		self.command = '\parg'
		self.commit()
	def clicked_uparrow(self):
		self.command = '\paup'
		self.commit()
	def clicked_downarrow(self):
		self.command = '\padw'
		self.commit()
	def clicked_esc(self):
		self.command = '\pesc'
		self.commit()
	def clicked_capslock(self):
		self.command = '\caps'
		self.commit()
	def clicked_changepasswd(self):
		self.command = '\psetuppswd'
		self.commit()
	def clicked_exit(self):
		self.command = '\pexit'
		self.commit()
	def clicked_screenshot(self):
		self.command = '\psh'
		self.commit()
	def clicked_alt(self):
		self.command = '\palt'
		self.commit()
	def clicked_ctrl(self):
		self.command = '\pctrl'
		self.commit()
	def clicked_win(self):
		self.command = '\pmouse'
		self.commit()
	def on_access_click(self):
		self.retLabel.setText("Try to login target machine.")
		if self.conn is not None:
			self.retLabel.setText("Check current target machine is disonnected with")
			return
		self.login()
		if self.conn is None:
			self.retLabel.setText("Connect failure.")
			return
	def on_disconnect_click(self):
		try:
			self.conn.send(self.encrypt('l0x001'))
			self.conn.recv()
			self.conn.close()
		except:pass
		self.conn 	 = None
		self.retLabel.setText("Disconnect safely.")
		self.statLabel.setText("disconnected")
		self.statLabel.adjustSize()
		self.curr = "ready"
	def onChanged_Port(self, text):self.port 	= text
	def onChanged_Host(self, text):self.ip = text
	def onChanged_Cmd(self, text):self.command = text
	def onChanged_Pswd(self, text):self.password = text
	def mode(self):
		try:
			if self.command == '':return
			if self.command not in COMMAND_LIST.keys():
				if self.command.split()[0] == 'run':
					try:
						target = self.command.split()[1] 
						self.command = self.command.split()[0]
						self.curr ='script mode'
						self.statLabel.setText(self.curr)
						self.statLabel.adjustSize()
					except:
						self.retLabel.setText("Usage : run TARGET_SCRIPT")
						self.retLabel.adjustSize()
			else:
				if self.command=='run':
					self.retLabel.setText("Usage : run TARGET_SCRIPT")
					return
				self.statLabel.setText(self.command)
			command = COMMAND_LIST.get(self.command,'lx011')
			self.conn.send(self.encrypt(command))
			rcv = self.decrypt(self.conn.recv(2048))
			if   rcv == '#200':
				self.retLabel.setText("received OK")
				if command == 'l0x008':
					self.curr = 'console'
					self.statLabel.setText(self.curr)
				else:self.curr = None
			else:self.retLabel.setText("Error Code : {0}".format(rcv))
			if command == 'l0x002':
				self.conn.send(self.encrypt(target))
				rcv = self.decrypt(self.conn.recv(2048))
				if   rcv == '#200':self.retLabel.setText("received OK")
				else:self.retLabel.setText("Error Code : {0}".format(rcv))
			elif command == 'l0xfff':
				try:self.conn.close()
				except:pass
				self.conn 	 = None
				self.retLabel.setText("Pycro System Shutdowned")
				self.curr = "off"
				self.statLabel.setText(self.curr)
		except socket.timeout:pass
		except:
			self.retLabel.setText("Connection Fault. Disconnect with host.")
			self.retLabel.adjustSize()
		self.command = self.cmdLine.text()
	def commit(self):
		if self.curr != 'console':
			self.retLabel.setText("Commit needs to run console mode")
			return
		try:
			if self.command == '':return
			self.sock.send(self.encrypt(self.command))
			rcv = self.decrypt(self.sock.recv(2048))
			if   rcv == '#200':
				self.retLabel.setText("received OK")
				if self.command == '\psetuppswd':
					self.__change_password()
				elif self.command == '\psh':	
					header 	= self.decrypt(self.sock.recv(2048)).split('|')
					self.sock.send(self.encrypt('#200'))
					key    	= header[2].encode()
					cipher_suite = Fernet(key)
					fsize	= header[1]
					try:
						while fsize>0:
							data = cipher_suite.decrypt(conn.recv(11020))
							if not data:break
							fsize = fsize - len(data)
							file.write(data)
					except socket.timeout:
						self.retLabel.setText('Connection Timeout')
					except:
						self.command = self.cmdLine.text()
						return
			else:self.retLabel.setText("Error Code : {0}".format(rcv))
		except socket.timeout:pass
		except:
			self.retLabel.setText("Connection Fault. Disconnect with host.")
		self.retLabel.adjustSize()
		self.command = self.cmdLine.text()

	def __change_password(self):
		pw = self.inputDialog("password","Enter the present password")
		if pw is None or pw == '':
			self.sock.send(self.encrypt('1'))
			self.retLabel.setText("Incorrect password.")
			return True
		self.sock.send(self.encrypt(pw))
		rcv = self.decrypt(self.sock.recv(2048))
		if rcv == '#240':
			pw = self.inputDialog("password","Enter the new password")
			if pw is None or pw == '':
				self.retLabel.setText("Incorrect password.")
				self.sock.send(self.encrypt('1'))
				return True
			self.sock.send(self.encrypt(pw))
			rcv = self.decrypt(self.sock.recv(2048))
			if rcv == '#upix':
				self.retLabel.setText("Password changed.")
			else:
				self.retLabel.setText("New password is too short(more than 8 chars).")
		else:
			self.retLabel.setText("New password is too short(more than 8 chars).")
			return True

	def closeEvent(self, event):
		try:
			self.conn.send(self.encrypt('l0x001'))
			self.decrypt(self.conn.recv(2048))
			self.conn.close()
		except:pass



class Main(QMainWindow):

	def __init__(self,iface):
		super().__init__()
		self.host_list	= dict()
		self.host 		= self.__get_ip_address(iface)
		self.count		= 1
		self.isOpened	= False
		self.pair 		= rsa.newkeys(1024,poolsize=4)
		self.initUI()

	def __get_ip_address(self,iface):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		if platform.system().lower() == 'windows':			
			return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', iface[:15]))[20:24])
		else:
			return subprocess.getoutput("/sbin/ifconfig %s" % iface).split("\n")[1].split()[1][5:]

	def __connect(self,host,port):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.settimeout(10.0)
		try:
			self.host_list.update({host:[sock,0,0,port]})		
			sock.connect((host,port))
			return sock
		except socket.timeout:print ('[!] Connection Timeout')
		except:print ('[!] Inet Socket Error')		
		return None
		

	def __create_socket_as_server(self,target):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		current_host = self.host_list.get(target,None)
		if current_host is None:return None
		sock.bind((target,current_host[3]+1))
		sock.listen(1)
		conn, addr	= sock.accept()
		return conn
	

	def encrypt(self,plain,host=None):
		if plain == b'':return b''
		if host!=None:
			key = self.host_list.get(host,None)
			if key == None:return b''
			return rsa.encrypt(plain.encode(),key[2])

	def encrypt_s(self,plain,key):
		if plain == b'':return b''
		return rsa.encrypt(plain.encode(),key)

	def decrypt(self,crypt):
		return rsa.decrypt(crypt,self.pair[1]).decode()

	def closeEvent(self, event):
		if len(self.host_list.keys()) == 0:pass
		else:
			for key, value in self.host_list.items():
				try:
					sock = value[0]
					sock.send(self.encrypt_s('l0x001',value[2]))
					self.decrypt(sock.recv(2048))
					self.conn.close()
				except:pass

	def help(self):
		file = open(PATH+'manual','r')
		self.editor("manual",1)
		with file:
			text = file.read()
			self.textEdit.setText(text)

	def NetworkManager(self):
		self.newBtn	= self.create_button("New",self.Add_Row)
		self.conBtn	= self.create_button("Connect",self.Connect_Target)
		self.delBtn = self.create_button("Disconnect",self.Disconnect_Row)
		self.remBtn = self.create_button("Remove",self.Delete_Row)
		self.runBtn	= self.create_button("Run",self.Run_Script)
		self.stpBtn	= self.create_button("Stop",self.Stop_Script)
		self.cnlBtn	= self.create_button("Show")

		self.nmTab		= QWidget()
		self.leftSide	= QVBoxLayout()
		self.rightSide	= QVBoxLayout()
		self.totalSide	= QHBoxLayout()

		self.nmTable	= QTableWidget(self)
		self.nmTable.resize(290, 290)
		self.nmTable.setRowCount(0)
		self.nmTable.setColumnCount(6)
		#column_headers = ['Reg_ID', 'Host','Port', 'Status','Current_Script','Comment']
		self.nmTable.setHorizontalHeaderLabels(column_headers)
		self.leftSide.addWidget(self.nmTable)
		self.nmTable.resizeRowsToContents()
		
		#self.nmTable.setItem(0, 0, QTableWidgetItem("(0,0)"))
		#self.nmTable.setItem(0, 1, QTableWidgetItem("(0,1)"))

		self.totalSide.addLayout(self.leftSide)
		self.totalSide.addLayout(self.rightSide)
		self.rightSide.addWidget(self.newBtn)
		self.rightSide.addWidget(self.remBtn)
		self.rightSide.addWidget(self.conBtn)
		self.rightSide.addWidget(self.delBtn)
		self.rightSide.addWidget(self.runBtn)
		self.rightSide.addWidget(self.stpBtn)
		self.rightSide.addWidget(self.cnlBtn)


		self.nmTab.setLayout(self.totalSide)
		self.tab.addTab(self.nmTab,"Manager")
		self.editTableAction('NULL')

	def create_button(self,title,actioncode=None):
		btn = QPushButton(title,self)
		if actioncode is not None:
			btn.clicked.connect(actioncode)
		return btn

	def Add_Row(self):
		ip 	 = self.inputDialog("Server Manager","Enter the target host ip")
		port = self.inputDialog("Server Manager","Enter the target port no")
		if ip is None or port is None:return
		rowPosition = self.nmTable.rowCount()
		self.nmTable.insertRow(rowPosition)
		self.nmTable.setItem(rowPosition, 0, QTableWidgetItem(str(hex(10000+self.count))))
		self.nmTable.setItem(rowPosition, 1, QTableWidgetItem(ip))
		self.nmTable.setItem(rowPosition, 2, QTableWidgetItem(port))
		self.nmTable.setItem(rowPosition, 3, QTableWidgetItem("idle"))
		self.nmTable.setItem(rowPosition, 4, QTableWidgetItem("undetectable"))
		self.nmTable.resizeRowsToContents()
		self.count+=1
		self.statusBar().showMessage('Register target machine.')

	def Delete_Row(self):
		rowPosition = self.nmTable.currentRow()
		try:
			ip 			= self.nmTable.item(rowPosition, 1).text()
			self.communicate(ip,('\pdisconnect','Disconenct target machine. and Delete target machine in list.'))
			self.host_list.pop(ip)
		except:self.statusBar().showMessage('Delete target machine in list.')
		self.nmTable.removeRow(rowPosition)

	def login(self,password,ip,port):
		conn = self.__connect(ip,port)
		if conn is None:return False
		conn.send('login'.encode())
		try:host_key = conn.recv(2048).decode()
		except:return False
		host_key = host_key.split('|')
		host_key = rsa.key.PublicKey(int(host_key[0]),int(host_key[1]))
		tmp = re.findall(r"\d+",str(self.pair[0]))
		tmp ='|'.join(tmp)
		conn.send(tmp.encode())	
		if conn.recv(64).decode()=='#980':
			conn.send(self.encrypt_s('#400',host_key))
			data = conn.recv(64).decode()
			if data=='#980':pass
			else:
				conn = None
				return False
		else:
			conn.send('#400').decode()
			return False
		conn.send(self.encrypt_s(password,host_key))
		if self.decrypt(conn.recv(2048)) != '#980':
			conn = None
			return False
		conn.send(self.encrypt_s(str(port+1),host_key))
		if self.decrypt(conn.recv(2048)) != '#980':
			conn = None
			return False
		sock = self.__create_socket_as_server(ip)
		if sock is None:return False
		if self.decrypt(sock.recv(2048)) == '#lunatic':
			self.statusBar().showMessage('Login Success.')
			self.host_list.update({ip:[conn,sock,host_key,port]})	
		else:return False

	def Disconnect_Row(self):
		rowPosition = self.nmTable.currentRow()
		try:
			ip 	= self.nmTable.item(rowPosition, 1).text()
			self.communicate(ip,('l0x001','Disconenct target machine.'))
			self.host_list.pop(ip)
			self.nmTable.setItem(rowPosition, 3, QTableWidgetItem("dead"))
			return
		except KeyError:self.statusBar().showMessage('Already disconnected.')
		except:self.statusBar().showMessage('Error : when try to delete target machine in list.')
		self.nmTable.setItem(rowPosition, 3, QTableWidgetItem("zombie"))

	def Connect_Target(self):
		row 	= self.nmTable.currentRow()
		ip 		= self.nmTable.item(row, 1)
		port	= self.nmTable.item(row, 2)
		if ip is None or port is None:
			self.statusBar().showMessage('Error : Need selected target.')
			return
		ip 		= ip.text()
		port 	= port.text()
		try:port	= int(port)
		except:
			self.statusBar().showMessage('Error : Port have to be int type.')
			return
		if ip in self.host_list.keys():
			self.statusBar().showMessage('Error : Need disconnection before new connection')
			return
		passwd 	= self.inputDialog("Password","Enter the password to make connection")
		self.login(passwd,ip,port)
		self.statusBar().showMessage('{0} conenct success with target machine.'.format(ip))
		self.nmTable.setItem(row, 3, QTableWidgetItem("live"))

	def Run_Script(self):
		row 	= self.nmTable.currentRow()
		ip 		= self.nmTable.item(row, 1)
		run		= self.nmTable.item(row, 4)
		if ip is None or run is None:
			self.statusBar().showMessage('Error : Need selected target.')
			return
		ip 		= ip.text()
		run 	= run.text()
		ret 	= self.communicate(ip,('l0x002',run))
		if ret:
			self.nmTable.setItem(row, 3, QTableWidgetItem("working"))
	
	def Stop_Script(self):
		row 	= self.nmTable.currentRow()
		ip 		= self.nmTable.item(row, 1)
		if ip is None:
			self.statusBar().showMessage('Error : Need selected target.')
			return
		ip		= ip.text()
		ret		= self.communicate(ip,('l0x004','runnung script stop.'))
		if ret:self.nmTable.setItem(row, 3, QTableWidgetItem("idle"))

	def communicate(self,ip,sets):
		try:
			info = self.host_list.get(ip)
			sock = info[0]
			sock.send(self.encrypt(sets[0],ip))
			rcvd = self.decrypt(sock.recv(512))
			if rcvd=='#200':
				if sets[0] == 'l0x002':
					sock.send(self.encrypt(sets[1],ip))
					rcv = self.decrypt(sock.recv(512))
					if  rcv == '#200':
						self.statusBar().showMessage('Launch script success.')
						return True
					else:
						self.statusBar().showMessage('Cannot found such script.')
						return False
				elif sets[0] == 'l0x018': 
					self.termianl_thread.writeTerminal.connect(self.writeTerminal)
					self.termianl_thread.start()		
				else:self.statusBar().showMessage(sets[1])
				return True
			else:
				self.statusBar().showMessage('command failure. Error Code'.format(rcvd))
				return 0
		except:
			self.statusBar().showMessage('command failure. Target missing'.format(ip))
			self.msessageBox(QMessageBox.Information,"Error","Target missing (does it run?)")
			return 0

	def setTableData(self):
		for k, v in self.host_list.items():
			col = column_idx_lookup[k]
			for row, val in enumerate(v):
				item = QTableWidgetItem(val)
				#item.setTextAlignment(Qt.AlignVCenter | Qt.AlignRight)
				self.tableWidget.setItem(row, col, item)
		self.nmTable.resizeColumnsToContents()
		self.nmTable.resizeRowsToContents()

	def editTableAction(self,cmd):
		self.NTthread = NT_Worker(self.host_list,cmd)
		self.NTthread.editTable.connect(self.editTableData)
		self.writeTerminal('[*] Activate NT_Worker\n')
		self.NTthread.start()
	def editTableData(self,msg):
		msg 	= msg.split()
		col 	= 0
		tot		= self.nmTable.currentRow() if type(self.nmTable.currentRow()) is None else 0
		if type(msg) is None or len(msg)!=3:return
		elif msg[0] not in self.host_list.keys():return
		for row in range(0,tot):
			if msg[0] == self.nmTable.item(row, 1):
				for i in column_headers:
					if text[1]==i:
						self.tableWidget.setItem(row, col, msg[2])
						return
					else:col+=1
		

	def getFileName(self,filename):
		return filename.split('/')[-1]

	def editor(self,name,shield=False):
		self.textEdit = Editor()
		self.setCentralWidget(self.tab)
		if shield:self.textEdit.setReadOnly(True)
		self.tab.addTab(self.textEdit, name)

	def close_handler(self, index):
		if index in (0,1):
			if index == 1:self.isOpened = False
		else:self.tab.removeTab(index)

	def create_log(self):
		self.logOutput = QTextEdit()
		self.logOutput.setReadOnly(True)
		self.logCursor = self.logOutput.textCursor()
		self.logOutput.ensureCursorVisible()
		self.logOutput.setTextCursor(self.logCursor)
		self.logOutput.setLineWrapMode(QTextEdit.NoWrap)
		self.logOutput.setStyleSheet("""QTextEdit { background-color: black; color: rgb(0, 255, 255); }""")
		font = self.logOutput.font()
		#font.setFamily("Monospace")
		font.setPointSize(11)
		self.tab.addTab(self.logOutput, "Teminal")
		return self.logOutput

	def writeTerminal(self,msg):
		self.logOutput.moveCursor(self.logCursor.End)
		self.logOutput.insertPlainText(msg)

	def inputDialog(self,title,context):
		text, ok = QInputDialog.getText(self, title, context)
		if ok:return str(text)
		else:return None

	def msessageBox(self,icon,Title="",Text=""):
		msg = QMessageBox()
		msg.setIcon(icon)
		msg.setText(Text)
		msg.setWindowTitle(Title)
		msg.setStandardButtons(QMessageBox.Ok)
		msg.exec_()

	def createsAconsoleWindow(self):
		self.consoleWindow=ConsoleWindow(self.host,"Console",self.pair)
		self.consoleWindow.createWindow(500,420)	
		self.consoleWindow.show()
		self.writeTerminal("[*] Console window opened at {0}\n".format(time.ctime()))

	def createsNetworkManager(self):
		if self.isOpened is False:
			self.NetworkManager()
			self.isOpened = True
			self.writeTerminal("[*] Server manager window opened at {0}\n".format(time.ctime()))
		else:self.writeTerminal("[*] Server manager window already opened\n")
	def openFileNameDialog(self):    
		options = QFileDialog.Options()
		options |= QFileDialog.DontUseNativeDialog
		fileName, _ = QFileDialog.getOpenFileName(self,"Explorer", "","All Files (*);;Script Files (*.tl)", options=options)
		if fileName:
			file = open(fileName,'r')
			self.editor(self.getFileName(fileName))
			with file:
				text = file.read()
				self.textEdit.setText(text)
			self.statusBar().showMessage(fileName)
		else:self.statusBar().showMessage('There is no such file')

	def saveFileDialog(self):    
		options = QFileDialog.Options()
		options |= QFileDialog.DontUseNativeDialog
		fileName, _ = QFileDialog.getSaveFileName(self,"Saves","","All Files (*);;Script Files (*.tl)", options=options)
		if fileName:
			file = open(fileName,'w')
			text = self.textEdit.toPlainText()
			file.write(text)
			file.close()
			self.tab.setTabText(self.tab.currentIndex(), self.getFileName(fileName))
			self.statusBar().showMessage('Saves at : '+fileName)
		else:self.statusBar().showMessage('Save canceled')

	def newFile(self):
		self.editor('untitled')

	def scanNetwork(self):
		self.statusBar().showMessage('Start to find host...')
		self.termianl_thread = Terminal('scan#1 10730-10731','172.30.1.1-255')
		self.termianl_thread.writeTerminal.connect(self.writeTerminal)
		self.termianl_thread.start()

	def scanDNetwork(self):
		self.statusBar().showMessage('Start to find host...')
		ip = self.inputDialog("Input","Enter target ip address")
		port = self.inputDialog("Input","Enter target port no")
		self.termianl_thread = Terminal('scan#2 {0}'.format(port),ip)
		self.termianl_thread.writeTerminal.connect(self.writeTerminal)
		self.termianl_thread.start()

	def vncNetwork(self):
		self.statusBar().showMessage('Start to vnc service.')
		self.termianl_thread = Terminal('vncviewer','0')
		self.termianl_thread.writeTerminal.connect(self.writeTerminal)
		self.termianl_thread.start()

	def transNetwork(self):
		self.statusBar().showMessage('Ready for file transfer')
		ip 		= self.inputDialog("Input","Enter target ip address")
		port 	= self.inputDialog("Input","Enter target port no")
		pw 		= self.inputDialog("Input","Enter target password")
		options = QFileDialog.Options()
		options |= QFileDialog.DontUseNativeDialog
		Name, _ = QFileDialog.getOpenFileName(self,"Select file for transferring","",
								"All Files (*);;Script Files (*.tl)", options=options)
		if Name:
			conn	= self.login(pw,ip,int(port))
			if conn is False:self.writeTerminal('[-] Transportation Failure. Cannot log in target\n')
			else:
				conn 	= self.host_list.get(ip,None)[0]
				self.termianl_thread = Terminal('transport {0}'.format(Name),ip,conn,self.host_list.get(ip,None)[2],self.pair[1])
				self.writeTerminal('[*] transport {0}\n'.format(Name))
				self.communicate(ip,['l0x018','Transporting'])
		else:pass

	def cmdNetwork(self):
		self.statusBar().showMessage('Start command console.')
		self.createsAconsoleWindow()

	def compileScript(self):
		options = QFileDialog.Options()
		options |= QFileDialog.DontUseNativeDialog
		Name, _ = QFileDialog.getOpenFileName(self,"Select file for compile","",
								"All Files (*);;Script Files (*.tl)", options=options)
		if Name:
			self.termianl_thread = Terminal('compile {0}'.format(Name),'0')
			self.termianl_thread.writeTerminal.connect(self.writeTerminal)
			self.termianl_thread.start()
		else:pass

	def initUI(self):

		""" File Operator """
		exitAction = QAction(QtGui.QIcon('exit.png'), '&종료 (Quit)', self)
		exitAction.setShortcut('Ctrl+Q')
		exitAction.setStatusTip('Exit program')
		exitAction.triggered.connect(qApp.exit)
	
		fileOpenAction = QAction(QtGui.QIcon('exit.png'), '&열기 (Open)', self)
		fileOpenAction.setShortcut('Ctrl+O')
		fileOpenAction.setStatusTip('Open script file')
		fileOpenAction.triggered.connect(self.openFileNameDialog)

		fileSaveAction = QAction(QtGui.QIcon('exit.png'), '&저장 (Save)', self)
		fileSaveAction.setShortcut('Ctrl+S')
		fileSaveAction.setStatusTip('Save current script')
		fileSaveAction.triggered.connect(self.saveFileDialog)

		newFile = QAction("&새 파일 (New File)", self)
		newFile.setShortcut("Ctrl+N")
		newFile.setStatusTip('Open blank script file')
		newFile.triggered.connect(self.newFile)

		""" Connect Operator """
		scanAction = QAction(QtGui.QIcon('exit.png'), '&고정 스캔 (Static scan)', self)
		scanAction.setShortcut('Alt+S')
		scanAction.setStatusTip('(root required) Network scanning with default scanning')
		scanAction.triggered.connect(self.scanNetwork)

		dscanAction = QAction(QtGui.QIcon('exit.png'), '&동적 스캔 (Dynamic scan)', self)
		dscanAction.setShortcut('Alt+D')
		dscanAction.setStatusTip('(root required) Dynamic network scanning')
		dscanAction.triggered.connect(self.scanDNetwork)

		vncAction = QAction(QtGui.QIcon('exit.png'), '&VNC 접속 (Connect VNC server)', self)
		vncAction.setShortcut('Alt+V')
		vncAction.setStatusTip('Connect to vnc server')
		vncAction.triggered.connect(self.vncNetwork)

		transportAction = QAction(QtGui.QIcon('exit.png'), '&파일 전송 (File Transfering)', self)
		transportAction.setShortcut('Alt+T')
		transportAction.setStatusTip('File Transfer to target machine')
		transportAction.triggered.connect(self.transNetwork)

		cmdAction = QAction(QtGui.QIcon('exit.png'), '&명령창     (Command Console)', self)
		cmdAction.setShortcut('Alt+C')
		cmdAction.setStatusTip('Open manual handler console')
		cmdAction.triggered.connect(self.cmdNetwork)

		svrAction = QAction(QtGui.QIcon('exit.png'), '&서버 관리 (Server Management)', self)
		svrAction.setShortcut('Alt+M')
		svrAction.setStatusTip('Open server manager window tab')
		svrAction.triggered.connect(self.createsNetworkManager)


		""" Development Operator """
		compileAction = QAction(QtGui.QIcon('exit.png'), '&컴파일 (Compile)', self)
		compileAction.setShortcut('Ctrl+F5')
		compileAction.setStatusTip('Compile present script')
		compileAction.triggered.connect(self.compileScript)

		showhelpAction = QAction(QtGui.QIcon('exit.png'), '&도움말 (Help)', self)
		showhelpAction.setShortcut('F1')
		showhelpAction.setStatusTip('Help')
		showhelpAction.triggered.connect(self.help)

		""" Menu Bar register """
		menubar = self.menuBar()
		fileMenu = menubar.addMenu('&File')
		fileMenu.addAction(newFile)
		fileMenu.addAction(fileOpenAction)
		fileMenu.addAction(fileSaveAction)
		fileMenu.addAction(exitAction)

		connectMenu = menubar.addMenu('&Connect')
		connectMenu.addAction(scanAction)
		connectMenu.addAction(dscanAction)
		connectMenu.addAction(vncAction)
		connectMenu.addAction(transportAction)
		connectMenu.addAction(transportAction)
		connectMenu.addAction(cmdAction)
		connectMenu.addAction(svrAction)

		develMenu = menubar.addMenu('&Development')
		develMenu.addAction(compileAction)
		develMenu.addAction(showhelpAction)

		self.tab = QTabWidget(self)
		self.setCentralWidget(self.tab)
		self.tab.setTabsClosable(True)
		self.tab.setMovable(True)
		self.tab.tabCloseRequested.connect(self.close_handler)
		
		self.create_log()
		self.createsNetworkManager()
		self.statusBar().showMessage('Ready')			  
		self.setGeometry(300, 300, 500, 500)
		self.setWindowTitle('Pycro')
		
		#self.createsAconsoleWindow()


class Terminal(QtCore.QThread):
	writeTerminal	= QtCore.pyqtSignal(str)
	def __init__(self,command,host,conn=None,key=None,dkey=None):
		QtCore.QThread.__init__(self)
		self.command	= command.split()
		self.host 		= host
		self.conn		= conn
		self.key		= key
		self.dkey		= dkey
	def __del__(self):self.wait()
	def encrypt(self,plain):
		if plain == b'':return b''
		return rsa.encrypt(plain.encode(),self.key)
	def decrypt(self,crypt):
		return rsa.decrypt(crypt,self.dkey).decode()
	def scanner(self,port):
		nm = nmap.PortScanner()
		try:nm.scan(hosts=self.host,ports=str(port),arguments='-T4 -A -v -sS')
		except:return "[!] Unauthorized or incorrect command infomation.\n"
		string = ''
		for host in nm.all_hosts():
			for proto in nm[host].all_protocols():
				string += '----------------------------------------------------\n'
				string += '[hit] Host : {0} (%{1})\n' .format(host, nm[host].hostname())
				string += '----------\nProtocol : {0}\n'.format(proto)
				lport = list(nm[host][proto].keys())
				lport.sort()
				for port in lport:
					string+='port : {0}\tstate : {1}\n'.format(port, nm[host][proto][port]['state'])
		string += '[*] Finish scanning.\n'
		return string
	def transporter(self,Name):
		key = Fernet.generate_key()
		cipher_suite = Fernet(key)
		self.writeTerminal.emit('[*] Start transporting....\n')
		fsize = os.stat(Name).st_size
		Named  = Name.split(os.sep)[-1]
		header = '{0}|{1}|{2}|{3}|{4}'.format(id_generator(),Named,fsize,key.decode(),id_generator())
		self.conn.send(self.encrypt(header))
		rev		= self.decrypt(self.conn.recv(256))
		if rev not in ('#200','#201'):
			self.writeTerminal.emit('[-] Transportation Failure. Header error\n')
		elif rev == '#201':
			self.writeTerminal.emit('[*] Already file exists. Overwriting...\n')
			self.conn.send(self.encrypt('#210'))
		try:
			file = open(Name,'rb')
			while fsize > 0:
				buffer = file.read(8192)
				s = cipher_suite.encrypt(buffer)
				self.conn.send(s)
				fsize -= 8192
			file.close()
			self.writeTerminal.emit('[+] Transportation Success\n')
			self.conn.close()
		except:self.writeTerminal.emit('[-] Transportation Failure. Connection Lost\n')

	def run(self):
		ret = ''
		if self.command[0] == 'scan#1':
			if self.command[1] == '5800':
				self.writeTerminal.emit('*** Scan VNC Channel ***\n')
			self.writeTerminal.emit("[*] Start scanning\n")
			ret = self.scanner(self.command[1])
			self.writeTerminal.emit(ret)
		elif self.command[0] == 'scan#2':
			self.writeTerminal.emit("[*] Start scanning\n")
			ret = self.scanner(self.command[1])
			self.writeTerminal.emit(ret)
		elif self.command[0] == 'vncviewer':
			self.writeTerminal.emit("[*] Start vncviewer\n")
			ret = os.system('vncviewer')
			self.writeTerminal.emit("[*] VNC viewer service dowin with code {0}\n".format(ret))
		elif self.command[0] == 'transport':
			Name = self.command[1]
			self.writeTerminal.emit('[*] Transportation Ready\n >>> Object file : {0}\n'.format(Name))
			if os.path.isfile(Name) == False:pass
			elif self.conn == False:
				self.writeTerminal.emit('[-] Transportation Failure. Cannot log in target\n')
			else:self.transporter(Name)
		elif self.command[0] == 'compile':
			self.writeTerminal.emit('[*] Start compile...\n')
			Name = self.command[1]
			Compiler = Preprocessor()
			ret 	 = Compiler.compile(Name)
			if ret is True:ret = "Success"
			else:ret = " Failed.\n[-] compile error at line_No {0}".format(ret)
			self.writeTerminal.emit('[*] Compiled Result : {0}\n'.format(ret))


class NT_Worker(QtCore.QThread):
	editTable	= QtCore.pyqtSignal(str)
	def __init__(self,hosts,command):
		QtCore.QThread.__init__(self)
		self.host_list		= hosts
		self.command	= command.split()
	def __del__(self):self.wait()
	def autorun(self):pass
	def run(self):
		if   self.command[0] == 'NULL':self.autorun()
		elif self.command[0] == 'edit':
			self.editTable.emit(''.format(self.command[1],self.command[2],self.command[3]))
def main():
	app = QApplication(sys.argv)
	win = Main(iface)
	win.show()
	app.exec_()

if __name__ == '__main__':
	iface = 'enp2s0'
	sys.exit(main()) 
