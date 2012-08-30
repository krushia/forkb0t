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
			ircQueue.task_done()


class linkIRC(threading.Thread):
	def __init__(self, name, args):
		self.Options = args
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
				self.socket = socket.socket()
				self.socket.connect((self.Options['host'], int(self.Options['port'])))
				break
			except socket.error:
				if attempts > 3:
					return False
				time.sleep(3)
				attempts += 1
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
						if self.suicide: # shutdown
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

	def doRead(self, iq):
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
				continue
			rbuffer+=poppy
			if "\r\n" in rbuffer:
				temp=rbuffer.split("\r\n")
				if rbuffer.endswith("\r\n"):
					rbuffer="" # clear buffer
				else:
					rbuffer=temp.pop() # last element prolly incomplete... keep in buffer
				for msg in temp:
					if msg.strip():
						self.log(msg+'\r\n', 0)
						iq.put((self.Options, self.name, msg))

	def doWrite(self, oq):
		sbuffer = ''
		while 1:
			try:
				sbuffer = oq.get(block=True, timeout=10)
			except Queue.Empty:
				if self.reconnect:
					return
				continue
			# in-band signaling ftw :P
			if sbuffer == 'DIAF\r\n':
				self.suicide = True
				self.log('Suiciding cuz pluggar (we hope) said to\r\n', 2)
				oq.task_done()
				self.socket.close()
				return
			if sbuffer == 'PHOENIX\r\n':
				self.reconnect = True
				self.log('Restarting cuz pluggar (we hope) said to\r\n', 2)
				oq.task_done()
				self.socket.close()
				return
			try:
				self.socket.sendall(sbuffer)
				self.log(sbuffer, 1)
				oq.task_done()
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
				oq.task_done()
				self.socket.close()
				return

	def log(self, text, prefix):
		# 0 = in
		# 1 = out
		# 2 = error/info
		prefixes = [' ', ' >>>', ' ***']
		self.logQueue.put(str(int(time.time()*1000.0))+prefixes[prefix]+text)


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