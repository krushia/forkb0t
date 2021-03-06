#!/usr/bin/env python
# -*- coding: utf-8 -*-
###
# plugger.py
#  Part of forkb0t
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
import trace
import traceback
import subprocess
import time
import ConfigParser
import collections
import linecache
import textwrap
import os
import itertools
#Example plugin import if one was to put it up here
# from plugins.gigablast import gigablast

# TODO:
#	Make namedtuple usage cleaner (always use names rather than positional assignment, and try to remove redundantcy)
#	Add defaults and make all options optional
#	Sanity checks on data
#	Is there any reason for using namedtuple, besides converting to py types?
class pluggar:
	def __init__(self, configfile):
		plugconf = ConfigParser.SafeConfigParser({'shblacklist': 'False', 'shgreylist': 'True', 'prefixnick': 'True', 'input': 'terms', 'debug': 'False', 'output': 'terms', 'api': '1', 'type': 'python', 'load': '', 'run': ''})
		plugconf.read(configfile)
		self.plugwords = {}
		self.functable = {}
		self.plugalways = []
		FuncOptionTuple = collections.namedtuple('FuncOptionTuple', 'shblacklist shgreylist prefixnick input debug output api type load run')
		for i in plugconf.sections():
			for n in plugconf.get(i,'keywords').split():
				if n is not '*':
					self.plugwords[n] = i
				else:
					self.plugalways.append(i)
				self.functable[i] = FuncOptionTuple(shblacklist=plugconf.getboolean(i,'shblacklist'),shgreylist=plugconf.getboolean(i,'shgreylist'),prefixnick=plugconf.getboolean(i,'prefixnick'),input=plugconf.get(i,'input'),debug=plugconf.getboolean(i,'debug'),output=plugconf.get(i,'output'),api=plugconf.getint(i,'api'),type=plugconf.get(i,'type'),load=plugconf.get(i,'load'),run=plugconf.get(i,'run'))

class pluggerThread:
	def __init__(self):
		self.online = [] # not correct... should be in network data

		CAPAB_IDENTIFY_MSG = False
		self.identified = False

		self.out = ''
		self.log = ''

	def run(self, lmsg, net, name, pconf, zomgthefiles):
		self.out = ''
		self.log = ''
		self.pconf = pconf
		self.zomgthefiles = zomgthefiles

		self.Options = net

		self.name = name # will be a network from networks.conf, like "freenode"
		self.network = name #default to output same network

		self.msg = self.decode(lmsg)

		# Optimization globals... use instead of functions if possible
		self.msgtype, self.chan, self.nick, self.msgtext = self.findAll(self.msg)



		# This line is what starts the plugin parsing everytime pandas talk
		if self.msgtype == 'PRIVMSG':
			# BUG: forkb0tswdfkjhnshwidtvst@#$*&%@(#$5fmf234c2#& !wat
			if self.msgtext.startswith(self.Options['nick']):
				# the try... except was added cuz ed found a way to crash with:
				# :quiznilo!~CC@unaffiliated/ed-209 PRIVMSG #gentoo-pr0n :+forkb0t:
				try:
					haxmsgtext = self.msgtext.split(None, 1)[1]
				except:
					haxmsgtext = self.msgtext
			else:
				haxmsgtext = self.msgtext
			# The if statement below was added so all whitespace
			#  msgtext doesn't implode on split
			if haxmsgtext.strip() != '':
				for keyword in self.pconf.plugwords:
					if haxmsgtext.split()[0] == keyword:
						self.doTopPlug(pconf.plugwords[keyword], self.msg, self.msgtext, keyword)
			for plugin in self.pconf.plugalways:
				self.doTopPlug(plugin, self.msg, self.msgtext, "*")
		else:
			# NOTE: In future, add support for non PM regex keywords
			for plugin in self.pconf.plugalways:
				if self.pconf.functable[plugin].input == "raw":
					self.doTopPlug(plugin, self.msg, self.msgtext, "*")

	# I don't think this does much. Only needed if there are massively naughty plugins.
	def decode(self, bytes):
		if bytes is None:
			return bytes
		try:
			text = bytes.decode('utf-8','replace')
			if text != bytes:
				try:
					deedeedeecode = self.loadPlugin('encoding')
					# This happens a lot. Need a more useful message to track bad plugins
					#self.spam("WARNING: decode() did some magic with utf-8. The original bytes are monkeyshit.... " + deedeedeecode(bytes))
				except:
					self.spam("I failed at catching fail", True, True)
		except:
			try:
				text = bytes.decode('iso-8859-1')
			except:
				try:
					text = bytes.decode('cp1252')
				except:
					#self.spam("EPIC WARNING: decode() is useless", True)
					text = bytes
		return text

	# This defines the debug trace spam that forkb0t hurls
	def formatExceptionInfo(self, maxTBlevel=5):
		cla, exc, trbk = sys.exc_info()
		excName = cla.__name__
		try:
			excArgs = str(exc)
		except:
			try:
				excArgs = exc.__dict__["args"]
			except KeyError:
				excArgs = "<no args>"
		excTb = traceback.format_tb(trbk, maxTBlevel)
		return (excName, excArgs, excTb)

	# Reloads plugin modules
	def replug(self, plugin=''):
		try:
			self.pconf = pluggar('plugins.conf')
			plugin1count = 0
			plugin2count = 0
			errors = 0
			if plugin == '':
				repluglist = self.pconf.functable
			else:
				repluglist = [str(plugin)]
			for pluginText in repluglist:
				if self.pconf.functable[pluginText].api == 1:
					plugin1count += 1
					# To update line numbers
					linecache.checkcache("plugins/"+pluginText+"/"+pluginText+".py")
					if self.loadPlugin(pluginText, doreload=True) is None:
						errors += 1
				else:
					plugin2count += 1
					command = self.pconf.functable[pluginText].load
					if command == '':
						if self.pconf.functable[plugin].type == 'python':
							continue
						else:
							self.spam('Pluggar failed to reload plugin ' + pluginText + ' because the load setting in ' + pluginText  + '.conf appears to be empty. If this is intentional, please inform krushia')
							errors += 1
							continue
					loadproc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
					pipe, err = loadproc.communicate()
					if loadproc.returncode != 0:
						self.spam("Pluggar failed to reload plugin " + pluginText + " with load command " + command)
						self.spam("Returncode " + str(loadproc.returncode) + " -- stderr follows")
						for el in str(err).splitlines():
							self.spam(el)
						errors += 1
			linecache.checkcache()
			if errors == 0:
				return "Successfully replugged " + str(plugin2count) + " API v2, and " + str(plugin1count) + " legacy API v1 plugin(s)"
			else:
				return "Replug attempt had " + str(errors) + " error(s). Details in " + self.Options['debugchannel']
		except:
			self.spam("Horrible replug() failure, with passed plugin=" + str(plugin), True, True)
			return "EPIC FAIL"


	def loadPlugin(self, plugin, function='', doreload=False):
		if function == '':
			function = plugin
		try:
			# Will return plugins.foo, where foo is a package
			# On filesystem, this is a directory ./plugins/foo
			opackage = __import__("plugins." + plugin, globals(), locals(), [plugin], -1)
		except:
			self.spam("Pluggar fails at finding package for plugin " + plugin, True)
			return None
		if doreload:
			try:
				reload(opackage)
			except:
				self.spam("Pluggar failed to reload package for plugin " + plugin, True)
				return None
		try:
			# Will return plugins.foo.foo, where foo is a module
			# On filesystem, this is a file ./plugins/foo/foo.py
			omodule = getattr(opackage, plugin)
		except:
			self.spam("Pluggar fails at finding module for plugin " + plugin, True)
			return None
		if doreload:
			try:
				reload(omodule)
			except:
				self.spam("Pluggar failed to reload module for plugin " + plugin, True)
				return None
		try:
			# Will return plugins.foo.foo.bar, where bar is a function
			# On filesystem, this is the function bar() in ./plugins/foo/foo.py
			ofunction = getattr(omodule, function)
			return ofunction
		except:
			self.spam("Pluggar fails at finding function named " + function + " in module for plugin " + plugin, True)
			return None




	# Print debuggin information for fails. The name makes sense if you monitor #b0tcage
	# NOTE: Might not need all the str() - they are there from transition from %s
	# NOTE: say() uses string.encode('utf-8') on output, but spam() doesn't... BUG?
	def spam(self, text, trace=False, fulltrace=False):
		self.sendRaw("PRIVMSG " + self.Options['debugchannel'] + " :" + str(text) + "\r\n")
		if trace:
			try:
				e, a, t = self.formatExceptionInfo()
				self.sendRaw("PRIVMSG "+self.Options['debugchannel']+" : "+ str(e) +" --- "+str(a)+"\r\n")
				for line in t:
					# NOTE: line isn't really line, it is a bt point. Needs work.
					self.sendRaw("PRIVMSG " + self.Options['debugchannel'] + " : " + str(line).splitlines()[0] + "\r\n")
					if ( not fulltrace ) and ( "forkb0t" not in line ):
						# stop after the backtrace leaves our source
						time.sleep(3) # should remove... proper socket level flood control instead
						return
			except:
				self.sendRaw("PRIVMSG "+self.Options['debugchannel']+" : FAILED TO GET TRACEBACK\r\n")

	# Create a raw IRC PRIVMSG line that sends text to destination
	# TODO: Properly handle text with multiple lines
	def say(self, destination, text, prefix=""):
		for line in text.splitlines():
			if not line:
				continue

			command = "PRIVMSG"
			lprefix = prefix
			ldestination = destination

			# ACTION method is depreciated
			#  Make sure pandas don't use it in new plugins!
			if line.startswith("ACTION"):
				self.spam("WARNING: Depreciated ACTION used in plugin output")
				lprefix = ""
				lbody = "\001ACTION" + line.partition('ACTION')[2] + "\001"
			elif line.startswith("/me"):
				lprefix = ""
				lbody = "\001ACTION" + line.partition('/me')[2] + "\001"
			elif line.startswith("/notice"):
				command = "NOTICE"
				lprefix = ""
				ldestination = line.split()[1]
				lbody = line.partition(ldestination)[2].strip()
			elif line.startswith("/ctcp"):
				lprefix = ""
				ldestination = line.split()[1]
				lbody = "\001" + line.partition(ldestination)[2].strip() + "\001"
			elif line.startswith("/nctcp"):
				command = "NOTICE"
				lprefix = ""
				ldestination = line.split()[1]
				lbody = "\001" + line.partition(ldestination)[2].strip() + "\001"
			# note, /msg code should be a function?
			elif line.startswith("/msg"):
				prefix = ""
				lprefix = ""
				destination = line.split()[1]
				ldestination = destination
				lbody = line.partition(ldestination)[2].strip()
			elif line.startswith("/macro"):
				continue
			elif line.startswith("/core"):
				if 'replug' in line.partition('/core')[2]:
					if len(line.split()) >= 3:
						lbody = self.replug(line.split()[2])
					else:
						lbody = self.replug('')
				else:
					self.spam('A plugin specified invalid /core call: ' + line.partition('/core')[2])
					return
			elif line.startswith("/say"):
				lbody = line.partition('/say')[2].lstrip()
			else:
				lbody = line

			if "" != lprefix != ldestination and ldestination.startswith("#"):
				lprefix += ": "
			else:
				lprefix = ""

			# The True added at end cuz too lazy to add superuser bypass here
			if ldestination in self.online or ldestination in self.Options['channels'].split() or True:
				a = command + " " + ldestination + " :" + lprefix
				for z in textwrap.wrap(lbody,512-(len(a)+3+36)):
					tosend = a + z + "\r\n"
					self.sendRaw(tosend.encode('utf-8'))
			else:
				self.spam('A plugin tried to /msg invalid target: ' + ldestination)
				return

	def sendRaw(self, msg):
		self.out+=msg

	# TODO: I have no idea where this was headed...
	def report(self, msg):
		rtime = str(int(time.time()+1000.0))
		self.spam('Autogenerating bug report...')
		import sys
		rfile = open('report_'+rtime+'.txt', 'a', 0)
		rfile.write('Report\n')
		rfile.write('\n\nLoaded Modules\n')
		for i in sys.modules:
			rfile.write('%s\n'%i)

	# Ugly shell exploit checker. Really needs to be abstracted better.
	def checkHaxors(self, lmsgtext, black, grey, master):
		if black:
			for i in ["$", "`", "|", ";", "&", "~", "<<", ">>", '\'\'', '\"', '\\']:
				if i in lmsgtext:
					if master:
						self.spam("WARNING: Master override for shblacklist character " + i)
					else:
						return "This command doesn't allow " + i + " for safety reasons."
		if grey:
			for i in [">", "<", "&", "%", "*", "/"]:
				if i in lmsgtext:
					if master:
						self.spam("WARNING: Master override for shgreylist character " + i)
					else:
						return "This command is configured for stringent safety checks. The character(s) " + i + " are not allowed."
		return False

	def doTopPlug(self, plugin, lmsg, lmsgtext, keyword):
		exportTo = self.chan
		if self.pconf.functable[plugin].prefixnick:
			writeTo = self.nick
		else:
			writeTo = ""

		superuser = False
		master = False
		if self.identified:
			if self.nick in self.Options['superusers'].split():
				superuser = True
			if self.nick == self.Options['master']:
				master = True

		# 1 ONE-TIME PARSE PER MSG
		# Parse redirection operators
		if keyword is not "*":
			if '>>>>>' in lmsgtext:
				self.network = lmsg.partition('>>>>>')[2].strip()
				lmsg = lmsg.partition('>>>>>')[0].strip()
				lmsgtext = lmsgtext.partition('>>>>>')[0].strip()
			if '>>>>' in lmsgtext:
				# note that the validation here is redundant... see self.say()
				if lmsg.partition('>>>>')[2].strip() in self.online or lmsg.partition('>>>>')[2].strip() in self.Options['channels'].split() or superuser:
					exportTo = lmsg.partition('>>>>')[2].strip()
					lmsg = lmsg.partition('>>>>')[0].strip()
					lmsgtext = lmsgtext.partition('>>>>')[0].strip()
					writeTo = ""
				else:
					self.say(self.chan, '''I either don't know or am not allowed to redirect to ''' + lmsg.partition('>>>>')[2].strip())
					self.spam('Failed an exportTo')
					return
			if '>>>' in lmsgtext:
				writeTo = lmsg.partition('>>>')[2].strip()
				lmsg = lmsg.partition('>>>')[0].strip()
				lmsgtext = lmsgtext.partition('>>>')[0].strip()

		# 2 INSERT PIPING AND COMMAND SUBSTITUTION HERE

		# 3 CODE RUNS FOR EVERY COMMAND (MAKE IT HAPPEN)
		# Set plugin environment variables
		# NOTE: This is code prevents us from threading msg parsing
		self.zomgthefiles.acquire()
		penv = ConfigParser.SafeConfigParser()
		penv.read('plugin.env')
		if not penv.has_section('msg'):
			penv.add_section('msg')
		penv.set('msg', 'network', self.name.encode('unicode_escape'))
		penv.set('msg', 'nick', self.nick.encode('unicode_escape'))
		penv.set('msg', 'channel', self.chan.encode('unicode_escape'))
		penv.set('msg', 'keyword', keyword.encode('unicode_escape'))
		penv.set('msg', 'plugin', plugin.encode('unicode_escape'))
		penv.set('msg', 'identified', str(self.identified).encode('unicode_escape'))
		# Note that following line was redundant with doPlugKeyword
		if keyword is not "*":
			# Changed from lstrip to partition, old code on next line
			# lmsgtext = lmsgtext.lstrip(keyword).strip()
			lmsgtext = lmsgtext.partition(keyword)[2].strip()
		# BUG: Usually get exceptions here when % in values
		try:
			penv.set('msg', 'terms', lmsgtext.encode('unicode_escape'))
		except:
			penv.set('msg', 'terms', ' '.encode('unicode_escape'))
		try:
			penv.set('msg', 'raw', lmsg.encode('unicode_escape'))
		except:
			penv.set('msg', 'raw', ' '.encode('unicode_escape'))

		penv.set('msg', 'superuser', str(superuser).encode('unicode_escape'))
		penv.set('msg', 'master', str(master).encode('unicode_escape'))
		with open('plugin.env', 'wb') as configfile:
			penv.write(configfile)

		# Run plugin
		# NOTE: this is only place doPlugKeyword is called
		output = self.doPlugKeyword(plugin, lmsg, lmsgtext, keyword, master)
		self.zomgthefiles.release()

		# 3.5 (?) PARSE OF OUTPUT FROM EACH COMMAND

		# 4 ONE-TIME PARSE OF FINAL OUTPUT
		# NOTE: Need to put a flood detector here
		if output is None:
			return

		# Apply personal preferences (noprefixnick)
		if writeTo == self.nick:
			parsedmyconf = ConfigParser.SafeConfigParser()
			parsedmyconf.read('parsed.my.conf')
			if parsedmyconf.has_section(self.nick):
				if parsedmyconf.has_option(self.nick, 'noprefixnick'):
					if parsedmyconf.getboolean(self.nick, 'noprefixnick'):
						writeTo = ""

		self.say(exportTo, output, writeTo)

	# This huge mutha is waht runs a plugin. It keeps getting bigger. WTF.
	def doPlugKeyword(self, plugin, raw, lmsgtext, keyword, master):
		grey = self.pconf.functable[plugin].shgreylist
		black = self.pconf.functable[plugin].shblacklist
		if self.pconf.functable[plugin].api == 2:
			grey = True
			black = True
		if keyword is not "*":
			bypass = master
		else:
			bypass = False
		# NOTE: this is only place checkHaxors is called
		haxresult = self.checkHaxors(lmsgtext, black, grey, bypass)
		if haxresult:
			if keyword is not "*":
				return haxresult
			return

		try:
			if self.pconf.functable[plugin].api == 1:
				if self.pconf.functable[plugin].input == "raw":
					return self.runPlugin(plugin, raw, keyword, self.pconf.functable[plugin].debug)
				else:
					return self.runPlugin(plugin, lmsgtext, keyword, self.pconf.functable[plugin].debug)
			else:
				return self.runPlugin2(plugin, lmsgtext, keyword, self.pconf.functable[plugin].debug)
		except:
			# NOTE: This exception catches problems in runPlugin, NOT plugins themselves
			if keyword is not "*":
				self.say(self.chan, "I accidentally teh " + keyword + ". Details in " + self.Options['debugchannel'])
			self.spam("Failed doPlugKeyword for " + keyword + " (plugin " + plugin + ")", True)

	def runPlugin2(self, plugin, text, keyword, debug):
		command = self.pconf.functable[plugin].run
		if command == '':
			if self.pconf.functable[plugin].type == 'python':
				command = "python -B /home/forkb0t/forkb0t/plugins/" + plugin + "/" + plugin + ".py '" + text + "'"
			else:
				return 'Accident (FIXME - runPlugin2)'
		if plugin == 'dst':
			command += " '" + self.nick + "' '" + text + "'"
		plugproc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		pid = plugproc.pid
		pipe, err = plugproc.communicate()
		if plugproc.returncode != 0:
			self.say(self.chan, "I accidentally teh %s (plugin %s). Details in %s" %(keyword, plugin, self.Options['debugchannel']))
			if debug:
				self.spam("Failed to run plugin %s (keyword %s) *EXTENDED DEBUGGING ENABLED*" %(plugin, keyword), True, True)
			else:
				self.spam("Failed to run plugin %s (keyword %s)" %(plugin, keyword), True)
				self.spam("Returncode " + str(plugproc.returncode) + " -- stderr follows", False)
				for el in str(err).splitlines():
					self.spam(el, False)
			funcout = '' # to avoid second accident at next return
		return pipe

	def runPlugin(self, plugin, text, keyword, debug):
		functext = plugin

		if keyword is not "*":
			# NOTE: Plugin help() is going to be removed in the future
			if text in ['-h', '-?', '--help']:
				functext = 'help'
				text = keyword

		func = self.loadPlugin(plugin, function=functext)
		if func is None:
			self.spam("Used bailout clause in runPlugin, functext=" + str(functext))
			return

		if debug:
			command = "bash forkdev-debug-setup.sh " + plugin
			pipe = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True).communicate()[0]
			tf = open(plugin+'.trace.txt', 'w', 0)
			sys.stdout = tf
			tracer = trace.Trace(ignoredirs=[sys.prefix, sys.exec_prefix], timing=True)

		try:
			if debug:
				funcout = tracer.runfunc(func, text)
			else:
				funcout = func(text)
		except:
			if keyword is not "*":
				self.say(self.chan, "I accidentally teh %s (plugin %s). Details in %s" %(keyword, plugin, self.Options['debugchannel']))
			if debug:
				self.spam("Failed to run plugin %s (keyword %s) *EXTENDED DEBUGGING ENABLED*" %(plugin, keyword), True, True)
			else:
				self.spam("Failed to run plugin %s (keyword %s)" %(plugin, keyword), True)
			funcout = '' # to avoid second accident at next return

		if debug:
			sys.stdout = sys.__stdout__
			command = "bash forkdev-debug-postrun.sh " + plugin
			pipe = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True).communicate()[0]

		return self.decode(funcout)

	# Function borrowed from supybot ircutils.py
	# commit 6135a88741fcafa49bb2bd768cfc971cd7d58b5e
	def dccIP(self, ip):
		"""Converts an IP string to the DCC integer form."""
		i = 0
		x = 256**3
		for quad in ip.split('.'):
			i += int(quad)*x
			x /= 256
		return i

	# Function borrowed from supybot ircutils.py
	# commit 6135a88741fcafa49bb2bd768cfc971cd7d58b5e
	def unDccIP(self, i):
		"""Takes an integer DCC IP and return a normal string IP."""
		L = []
		while len(L) < 4:
			L.append(i % 256)
			i /= 256
		L.reverse()
		return '.'.join(itertools.imap(str, L))