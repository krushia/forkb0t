#!/usr/bin/env python
# -*- coding: utf-8 -*-
###
# forkb0t.py
#  Main forkb0t code
###
#    Copyright (C) 2008-2010, Ken Rushia (krushia), forkb0t@kenrushia.com
#    Copyright (C) 2008, Kenneth Prugh (Ken69267), ken69267@gentoo.org
#    Inspired by http://www.oreilly.com/pub/h/1968#code
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation under version 2 of the license.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the
#    Free Software Foundation, Inc.,
#    59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
###

import sys
# The following line prevents python from making most *.pyc
sys.dont_write_bytecode = False

import socket
#import string
import threading
import time
#import traceback
#import subprocess
#from optparse import OptionParser
import ConfigParser
#import gc
import Queue
#import asyncore
import plugger

#from ZODB import FileStorage, DB

#storage = FileStorage.FileStorage('test-filestorage.fs')
#db = DB(storage)

# Below was used for debug logs up to 8
# gc.set_debug(gc.DEBUG_LEAK)

#knownCommands = ['JOIN', 'KICK', 'LINKS', 'NAMES', 'NICK', 'NOTICE', 'PART', 'PING', 'PONG', 'PRIVMSG', 'QUIT', 'STATS'. 'VERSION', 'WHOIS']

ircQueue = Queue.Queue()
#outQueue = Queue.Queue()

class streamlang:
	self.buf = ''
	self.stream = ''
	self.error = ''
	commands = {'append':self.append, 'filter':self.filt, 'load':self.load, 'run':self.run, 'save':self.save}
	for line in self.code:
		if line.startswith('#'):
			continue
		
	def append(self, var):
		self.buf = self.buf
	def filt(self, filtname):
		pass
	def load(self, var):
		if var.startswith("'''"):
			self.buf = 'asdf'
		elif var.startswith("'"):
			self.buf = 'asdf'
		elif var == 'error':
			self.buf = self.error
		elif var == 'stream':
			self.buf = self.stream
		else:
			self.buf = self.getVarFromString(var)
	def run(self, params):
		pass
	def save(self, var):
		if var == 'error':
			self.error = self.buf
		elif var == 'stream':
			self.stream = self.buf
		else:
			self.buf = self.getVarFromString(var)
	def getVarFromString(self, string):
		pass
	


class doIRC(threading.Thread):
	def __init__(self, name):
		self.reinit = False
		self.commander = '#b0tcage'
		self.skynet = 'freenode'
		self.ninja = plugger.pluggerThread()
		threading.Thread.__init__(self, name=name)

	def america(self, fuck_yeah, commander, skynet):
		if fuck_yeah != self.name:
			self.reinit = True
			self.commander = commander
			self.skynet = skynet

	def sendRaw(self, name, stuff):
		for taco in fls:
			if taco.name == name:
				for line in stuff.splitlines(True):
					taco.outQueue.put(line)
				break # Dedenting this costs 1 day of debugging

	def log(self, name, stuff):
		for taco in fls:
			if taco.name == name:
				for line in stuff.splitlines(True):
					taco.log("[" + self.name + "]" + line, 2)
				break # Dedenting this costs 1 day of debugging

	def run(self):
		while 1:
			Options, name, msg = ircQueue.get()
			# NOTE: This msgtext is broken on IPv6 and should not be used
			#  Reload codes really needs to be cleaned up
			#  Better way would be to have plugger pick up !reload and signal main
			msgtext = msg.partition(':')[2].partition(':')[2]
			if self.reinit or msgtext.strip() in ["!reload", "+!reload"]:
				try:
					reload(plugger)
					self.ninja = plugger.pluggerThread()
					if not self.reinit:
						self.sendRaw(name, "PRIVMSG " + Options['debugchannel'] + " :["+self.name+"] Plugger reloaded. I am commanding other threads to reload now.\r\n")
						for noodle in fts:
							noodle.america(self.name, Options['debugchannel'], name)
					else:
						self.sendRaw(self.skynet, "PRIVMSG " + self.commander + " :["+self.name+"] Plugger reloaded.\r\n")
						self.reinit = False
				except:
					self.sendRaw(name, "PRIVMSG " + Options['debugchannel'] + " :["+self.name+"] Plugger reload FAILED\r\n")
			try:
				self.ninja.run(msg, Options, name, plugger.pluggar('plugins.conf'), zomgthefiles) #not a real thread...
			except:
				self.sendRaw(name, "PRIVMSG " + Options['debugchannel'] + " :["+self.name+"] Core caught an unhandled exception in plugger. I'd tell you more, but some asshole decided to delete backtrace code from core.\r\n")
			if self.ninja.out.strip():
				self.sendRaw(self.ninja.network, self.ninja.out)
			if self.ninja.log.strip():
				self.log(self.ninja.network, self.ninja.log)
			ircQueue.task_done()


class lineBasedClient(threading.Thread):
	def __init__(self, name, args):
		self.Options = args
		self.inQueue = Queue.Queue()
		self.outQueue = Queue.Queue()
		#self.socket = socket.socket()
		self.logfile = open(name+'.log.txt', 'a', 0)
		self.logQueue = Queue.Queue()
		self.suicide = False
		self.reconnect = False
		self.rapidlines = 0
		self.lastsendtime = 0
		threading.Thread.__init__(self, name=name)

	def doConnect(self):
		attempts = 1
		while 1:
			try:
				self.log("doConnect() commencing attempt #"+str(attempts)+"\r\n", 2)
				self.socket = socket.socket()
				self.socket.connect((self.Options['host'], int(self.Options['port'])))
				self.log("doConnect() has established a connection to the server\r\n", 2)
				break
			except socket.error:
				self.log("doConnect() failed this attempt\r\n", 2)
				if attempts > 3:
					return False
				time.sleep(3)
				attempts += 1
		return True

	def doLogin(self):
		return True

	def doMunch(self, iq):
		while 1:
			try:
				Options, name, msg = self.inQueue.get(block=True, timeout=10)
			except Queue.Empty:
				if self.reconnect:
					return
				continue
			self.msgtype, self.chan, self.nick, self.msgtext, self.paramdict = self.munch(msg)
			self.swallow(Options, name, msg)
			iq.put((self.Options, self.name, msg))
			self.inQueue.task_done()
	
	def munch(self, raw):
		return msg

	def swallow(self):
		return
	
	def doDigest(self, iq):
		while 1:
			try:
				Options, name, msg = self.inQueue.get(block=True, timeout=10)
			except Queue.Empty:
				if self.reconnect:
					return
				continue
			iq.put((self.Options, self.name, msg))
			self.inQueue.task_done()

	def run(self):
		while 1:
			if not self.doConnect(): # connect puked
				self.log("run() is setting the suicide bit because a connection could not be established.\r\n", 2)
				self.suicide = True
			if not self.doLogin(): # login puked
				self.log("run() is setting the suicide bit because we failed login.\r\n", 2)
				self.suicide = True
			inHandler = threading.Thread(target=self.doRead)
			munchHandler = threading.Thread(target=self.doMunch, args=(ircQueue,))
			outHandler = threading.Thread(target=self.doWrite)
			if not self.suicide:
				inHandler.start()
				munchHandler.start()
				outHandler.start()
			while 1:
				try:
					logline = self.logQueue.get(block=True, timeout=10)
				except:
					if not inHandler.is_alive() and not outHandler.is_alive():
						if self.suicide: # shutdown
							self.log("run() is returning in response to suicide bit. There will be no further log entries.\r\n", 2)
							self.logfile.write(logline)
							self.logQueue.task_done()
							return
						elif self.reconnect: # reconnect
							self.reconnect = False
							break
						else:
							continue
					else:
						continue
				self.logfile.write(logline)
				self.logQueue.task_done()

	def doRead(self):
		rbuffer = ''
		while 1:
			try:
				poppy = self.socket.recv(4096)
			except:
				if not self.suicide:
					self.reconnect = True
					self.log('SOCKET READ ERROR, RESTARTING\r\n', 2)
					self.socket.close()
				return
			if not poppy:
				if not self.suicide:
					self.reconnect = True
					self.log('doRead() detected possible connection loss.\r\n', 2)
					self.socket.close()
				return
			rbuffer+=poppy
			if "\r\n" in rbuffer:
				temp=rbuffer.split("\r\n")
				if rbuffer.endswith("\r\n"):
					rbuffer="" # clear buffer
				else:
					rbuffer=temp.pop() # last element prolly incomplete... keep in buffer
					self.log("NOTE: Input lines were read, but this last part was left in the buffer because it isn't terminated with \\r\\n:" + rbuffer + "\r\n", 2)
				for msg in temp:
					if msg.strip():
						self.log(msg+'\r\n', 0)
						self.inQueue.put((self.Options, self.name, msg))
			elif "\r" in rbuffer:
				self.log("WARNING: Input buffer contains a \\r by itself. This should rarely happen.\r\n", 2)
			elif "\n" in rbuffer:
				self.log("WARNING: Input buffer contains a \\n by itself. This should rarely happen.\r\n", 2)
			if self.suicide or self.reconnect:
				self.log("HUGE ASS WARNING: doRead() is continuing to next loop when suicide and/or reconnect is true.\r\n", 2)

	def doWrite(self):
		sbuffer = ''
		while 1:
			try:
				sbuffer = self.outQueue.get(block=True, timeout=10)
			except Queue.Empty:
				if self.reconnect:
					return
				continue
			# in-band signaling ftw :P
			if sbuffer == 'DIAF\r\n':
				self.suicide = True
				self.log('Suiciding cuz pluggar (we hope) said to\r\n', 2)
				self.outQueue.task_done()
				self.socket.close()
				return
			if sbuffer == 'PHOENIX\r\n':
				self.reconnect = True
				self.log('Restarting cuz pluggar (we hope) said to\r\n', 2)
				self.outQueue.task_done()
				self.socket.close()
				return
			try:
				self.socket.sendall(sbuffer)
				self.log(sbuffer, 1)
				self.outQueue.task_done()
				if time.time() <= self.lastsendtime + 1:
					self.rapidlines += 1
				else:
					self.rapidlines = 0
				self.lastsendtime = time.time()
				if self.rapidlines >= 2:
					time.sleep(1+self.rapidlines)
			except:
				self.reconnect = True
				self.log('SOCKET WRITE ERROR, RESTARTING\r\n', 2)
				self.outQueue.task_done()
				self.socket.close()
				return

	def log(self, text, prefix):
		# 0 = in
		# 1 = out
		# 2 = error/info
		prefixes = [' ', ' >>>', ' ***']
		self.logQueue.put(str(int(time.time()*1000.0))+prefixes[prefix]+text)




class linkIRC(lineBasedClient):
	def doLogin(self):
		#TODO: Insert PASS here
		self.outQueue.put("NICK %s\r\n" % self.Options['nick'])
		# Note the USER below is RFC2812 and varies significantly from original codebase
		self.outQueue.put("USER %s 0 * :%s\r\n" % (self.Options['nick'], self.Options['ident']))
		#TODO: Check for RPL_WELCOME here
		self.outQueue.put("PRIVMSG NickServ :identify %s\r\n" % self.Options['password'])
		if self.Options['capab'].strip():
			for i in self.Options['capab'].split():
				self.outQueue.put('CAPAB ' + i + '\r\n')
		if self.Options['cap'].strip():
			for i in self.Options['cap'].split():
				self.outQueue.put('CAP REQ :' + i + '\r\n')
		for i in self.Options['channels'].split():
			self.outQueue.put("JOIN %s\r\n" % i)
		#self.socket.settimeout(0.0)
		return True

	def munch(self, msg):
	# New complete message parser
	# Replaces findType(), findChannel(), and findNick()
		headerdict = {}
		if msg.startswith(':'):
			splitmsg = msg.split(None, 2)
			prefix = splitmsg[0][1:]
			if '!' in prefix:
				nickname, temp = prefix.split('!')
				user, host = temp.split('@')
				rnick = nickname # remove when forky gets smart
			elif '@' in prefix:
				nickname, host = prefix.split('@')
				rnick = nickname # remove when forky gets smart
			else:
				servername = prefix
				rnick = servername # remove when forky gets smart
			splitmsg.pop(0)
		else:
			splitmsg = msg.split(None, 1)
			rnick = 'dumb0t' # remove when forky gets smart
		command = splitmsg[0]
		rmsgtext = splitmsg[1] # remove when forky gets smart
		if ':' in splitmsg[1]:
			a, b, c = splitmsg[1].partition(':')
			if a == '':
				params = [c]
			else:
				params = a.split()
				if c != '':
					params.append(c)
		else:
			params = splitmsg[1].split()

		# A note on the naming of paramdict entries...
		#  While writing this function, I had the RFC open and was making
		#  sure that it was followed 100%. To this end, I decided to use the
		#  exact naming from the RFC for parameters to commands.
		#  ... it seemed like a good idea at first ...
		#  However, it turns out that the RFC was written by those who aren't
		#  gifted in the art of technical writing, as you can plainly see in
		#  the code below. There is an annoying lack of consistency in format
		#  of names. Most astounding are "text" for PRIVMSG and
		#  "text to be sent" for NOTICE. Also confusion of "user" and "nickname"
		paramdict = {}

		# Not implemented:
		# OPER, SERVICE, SQUIT, NAMES, LIST,
		if command == 'PASS': # Not from server
			paramdict['password'] = params[0]
		elif command == 'NICK':
			paramdict['nickname'] = params[0]
		elif command == 'USER': # Not from server
			paramdict['user'] = params[0]
			paramdict['mode'] = params[1]
			paramdict['unused'] = params[2]
			paramdict['realname'] = params[3]
		elif command == 'MODE':
			pass
			#if params[0] == nickname: # Not from server
			#	paramdict['nickname'] = params[0]
			#	 rest are a list of mode changes
			#if params[0] != nickname:
			#	paramdict['channel'] = params[0]
			#	 rest is a bunch of stuff to uberparse
		elif command == 'QUIT':
			pass
			#paramdict['quit_message'] = params[0] # Note that quit message is optional
			# insert netsplit checks here
		elif command == 'JOIN': # Note we don't check lists, since RFC says servers should not return them
			paramdict['channel'] = params[0]
		elif command == 'PART':
			paramdict['channel'] = params[0]
			#paramdict['part_message'] = params[1] # Note that part message is optional
		elif command == 'TOPIC':
			paramdict['channel'] = params[0]
			paramdict['topic'] = params[1]
		elif command == 'INVITE':
			paramdict['nickname'] = params[0]
			paramdict['channel'] = params[1]
		elif command == 'KICK':
			paramdict['channel'] = params[0]
			paramdict['user'] = params[1]
			#paramdict['comment'] = params[2] # comment is optional
		elif command == 'PRIVMSG':
			paramdict['msgtarget'] = params[0]
			paramdict['text_to_send'] = params[1]
			rmsgtext = paramdict['text_to_send'] # remove when forky gets smart
		elif command == 'NOTICE':
			paramdict['msgtarget'] = params[0]
			paramdict['text'] = params[1]
			rmsgtext = paramdict['text'] # remove when forky gets smart
		elif command == 'PING':
			paramdict['server1'] = params[0]
			# we don't check for server2
		elif command == 'ERROR': #should only get when connection is terminated
			paramdict['error_message'] = params[0]

		try: # remove when forky gets smart
			rchan =  paramdict['channel'] # remove when forky gets smart
		except: # remove when forky gets smart
			try: # remove when forky gets smart
				rchan = paramdict['msgtarget'] # remove when forky gets smart
				if self.Options['nick'] in rchan: # remove when forky gets smart
					rchan = rnick # remove when forky gets smart
			except: # remove when forky gets smart
				rchan = self.Options['debugchannel'] # remove when forky gets smart
		return command, rchan, rnick, rmsgtext, paramdict

	def swallow(self):
		CAPAB_IDENTIFY_MSG = True # temporary, till we get data stuff
		if self.msgtype == '290':
			if "IDENTIFY-MSG" in self.msg:
				CAPAB_IDENTIFY_MSG = True
		self.identified = False # reset here every scan
		if CAPAB_IDENTIFY_MSG:
			if self.msgtype in ['PRIVMSG', 'NOTICE']:
				if self.msgtext[:1] in ["+", "-"]:
					if self.msgtext[:1] == "+":
						self.identified = True
					self.msgtext = self.msgtext[1:]

		# Somewhat out of place but critical... play pingpong with ircd
		if self.msgtype == 'PING':
			self.sendRaw("PONG %s\r\n" %self.msg.partition(':')[2])

		# HAX - 2nd half of !names... read response fron nickserv
		# 353 RPL_NAMREPLY - defined in RFC1459 and RFC2812
		#  msgtext is same in both definitions, but header varies
		elif self.msgtype == '353':
			self.online = []
			for name in self.msgtext.split():
				if name.startswith('@') or name.startswith('+'):
					name = name[1:]
				if name not in self.online:
					self.online.append(name)

		# When someone leaves the channel, remove from online list
		elif self.msgtype in ['PART', 'QUIT']:
			if self.nick in self.online:
				self.online.remove(self.nick)

		elif self.msgtype == 'PRIVMSG':
			# If someone talks, they must be online. Add them to online list if missing.
			if self.nick not in self.online:
				self.online.append(self.nick)

			########################################
			# BEGIN PRIVMSG INTERNAL COMMAND CHECK #
			########################################

			# CTCP responses
			if self.msgtext.startswith("\001"):
				# chan == nick makes sure we do not send replies to channel
				# CTCP spammers.
				if "\001ACTION" not in self.msgtext and self.chan == self.nick:
					if not self.msgtext.endswith("\001"):
						self.spam("WARNING: CTCP from "+self.nick+"possibly malformed (doesn't end with \\001) - parsing anyway")
					if self.msgtext.startswith("\001CLIENTINFO"):
						self.sendRaw("NOTICE " + self.nick + " :\001CLIENTINFO ACTION CLIENTINFO PING TIME URL USERINFO VERSION\001\r\n")
					elif self.msgtext.startswith("\001PING"):
						self.sendRaw("NOTICE " + self.nick + " :" + self.msgtext + "\r\n")
					elif self.msgtext.startswith("\001TIME"):
						# Returned in RFC 2822 format per http://www.invlogic.com/irc/ctcp.html
						#  well.. technically it calls for RFC 822, which differs by using 2-digit year
						#  however, it seems most IRC clients use 4-digit, so we should be safe
						# ...
						# On the other hand, irssi and Konversation return a different format,
						#  http://www.irchelp.org/irchelp/rfc/ctcpspec.html but sans timezone!
						self.sendRaw("NOTICE " + self.nick + " :\001TIME " +time.strftime("%a, %d %b %Y %H:%M:%S %z")+"\001\r\n")
					elif self.msgtext.startswith("\001URL"):
						self.sendRaw("NOTICE " + self.nick + " :\001URL http://www.gentoo-pr0n.org/forkb0t:forkb0t\001\r\n")
					elif self.msgtext.startswith("\001USERINFO"):
						self.sendRaw("NOTICE " + self.nick + " :\001USERINFO A friendly b0t based in the #gentoo-pr0n channel on Freenode. Owner is krushia on IRC, who can also be contacted at forkb0t@kenrushia.com\001\r\n")
					elif self.msgtext.startswith("\001VERSION"):
						# Note we go by http://www.invlogic.com/irc/ctcp.html
						# somewhat different than http://www.irchelp.org/irchelp/rfc/ctcpspec.html
						# also we don't quote
						self.sendRaw("NOTICE " + self.nick + " :\001VERSION forkb0t 0.1 - by krushia\001\r\n")
					elif self.msgtext.startswith("\001DCC CHAT"):
						a, b, c = self.msgtext.partition('CHAT')[2].strip().split()
						self.spam("GOT CTCP DCC CHAT from "+self.nick+". protocol: "+a+"  ip: "+self.unDccIP(int(b))+"  port: "+c)
					else:
						self.spam("Unknown CTCP command... "+self.msgtext.partition("\001")[2].partition("\001")[0])


class linkDCC(threading.Thread):
	def __init__(self, name, args):
		self.Options = args
		self.outQueue = Queue.Queue()
		#self.socket = socket.socket()
		self.logfile = open(name+'.log.txt', 'a', 0)
		self.logQueue = Queue.Queue()
		self.suicide = False
		threading.Thread.__init__(self, name=name)

	def doConnect(self):
		try:
			self.socket = socket.socket()
			self.socket.connect((self.Options['host'], int(self.Options['port'])))
		except socket.error:
			return False
		return True

	def run(self):
		while 1:
			if not self.doConnect(): # connect puked
				return
			inHandler = threading.Thread(target=self.doRead, args=(ircQueue,))
			inHandler.start()
			outHandler = threading.Thread(target=self.doWrite, args=(self.outQueue,))
			outHandler.start()
			while 1:
				try:
					logline = self.logQueue.get(block=True, timeout=10)
				except:
					if not inHandler.is_alive() and not outHandler.is_alive():
						return
					continue
				self.logfile.write(logline)
				self.logQueue.task_done()

	def doRead(self, iq):
		rbuffer = ''
		while 1:
			if self.suicide:
				return
			try:
				poppy = self.socket.recv(4096)
			except:
				self.suicide = True
				self.log('SOCKET READ ERROR. CLOSING.\r\n', 2)
				return
			if not poppy:
				continue
			rbuffer+=poppy
			# Some DCC specs, in particular WHITEBOARD, allow either
			# "\r\n" or "\n" as line termination.
			if "\n" in rbuffer:
				temp=rbuffer.splitlines()
				if rbuffer.endswith("\n"):
					rbuffer="" # clear buffer
				else:
					# NOTE: Next line could cut off "\r", but shouldn't matter.
					rbuffer=temp.pop() # last element prolly incomplete... keep in buffer
				for msg in temp:
					if msg.strip():
						self.log(msg+'\r\n', 0)
						iq.put((self.Options, self.name, msg))

	def doWrite(self, oq):
		sbuffer = ''
		while 1:
			if self.suicide:
				return
			try:
				sbuffer = oq.get(block=True, timeout=10)
			except Queue.Empty:
				continue
			try:
				self.socket.sendall(sbuffer)
				self.log(sbuffer, 1)
				oq.task_done()
			except:
				self.suicide = True
				self.log('SOCKET WRITE ERROR. CLOSING.\r\n', 2)
				oq.task_done()
				return

	def log(self, text, prefix):
		# 0 = in
		# 1 = out
		# 2 = error/info
		prefixes = [' ', ' >>>', ' ***']
		self.logQueue.put(str(int(time.time()*1000.0))+prefixes[prefix]+text)




netconf = ConfigParser.SafeConfigParser()
netconf.read('networks.conf')
fls = [] # fork links
fts = [] # fork threads
zomgthefiles = threading.Lock() # lock for all plugin file access

def connectNewNet(t, host, port):
	pass

# Each network section in networks.conf results in two threads produced here.
#  1. fl - forklink (link*) thread that handles sockets. This produces 2 subthreads.
#  2. ft - forkthread (do*) thread that acts as a worker
for n in netconf.sections():
	# TODO: Make sense of this block... can it be simplified?
	nettable = {}
	All = netconf.items(n)
	for v in All:
		nettable[v[0]] = v[1]

	if nettable['type'] == 'irc':
		# Spawn a linkIRC object, which handles the connection to a network
		fl = linkIRC(name=n, args=nettable)
		fl.start()
		fls.append(fl)

		# Spawn a doIRC (or forkthread) object, which handles plugin processing
		#  These threads are NOT linked to any specific forklink (is a worker pool)
		for ftid in range(2): # spawn 2 workers for every network
			ft = doIRC(name="irc thread %s"%ftid)
			ft.start()
			fts.append(ft)

# main program sits here and exits after each forklink dies
for fl in fls:
	fl.join()