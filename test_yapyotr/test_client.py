#!/opt/local/bin/python2.5
# -*- coding: UTF-8 -*-

#
# Module design:
# TestClient uses py-jabber to connect to the server and
# send/recv messages.  Any conversation is routed through
# an OtrHandler, which just passes messages unchanged if 
# no Otr session has been initiated.  Each message that comes
# in to the OtrHandler is wrapped in an OtrMessage, which
# checks types, validates, and unpacks the message.
# the OtrHandler performs the appropriate action based on the
# type of OtrMessage and its state in the auth process.
#
# OtrTypes (_OT) is a namespace for the some-dozen type 
# conversion and validation routines.
#
# Part of yapyotr - copyright 2009 Eric Conlon
# Licensed under the GPLv3
# ejconlon@gmail.com | http://it.fuelsyourcyb.org

import sys
#reload(sys)
#sys.setdefaultencoding("utf-8")
import jabber, getpass, logging
#import os, time, hashlib
ustr = jabber.ustr

logging.basicConfig(
     level=logging.DEBUG,
     )

from yapyotr import *

# A simple non-interactive client that will connect and perform OTR authentication
class TestClient(jabber.Client):	
	def __init__(self, username, hostname, resource, password=None,  replay=OtrReplay()):
		jabber.Client.__init__(self, hostname, debug=[jabber.debug.DBG_ALWAYS],
		connection=jabber.xmlstream.TCP)
		self.connect()
		self.my_jid = username+"@"+hostname+"/"+resource
		if password is None:
			password = getpass.getpass('Password for %s: ' % self.my_jid)
		self.auth(username, password, resource)
		# send this so people who subscribe to our presence can see us online
		self.sendPresence(type='available', show='chat', status='Online')
		# register the message handler so we can proccess jabber messages in our otr handler
		self.registerHandler('message', self.recv_message)
		self.handler_dict = dict()
		self.replay = replay
	
	# gets the appropriate handler for the given connection
	def get_handler(self, their_jid, thread):
		ok = ustr(their_jid)
		if thread is None:
			tk = ustr('__default')
		else:
			tk = ustr(thread)
		if ok not in self.handler_dict.keys():
			self.handler_dict[ok] = {tk:None}
		elif tk not in self.handler_dict[ok].keys():
			self.handler_dict[ok][tk] = None
		handler = self.handler_dict[ok][tk]
		if handler is None:
			handler = OtrHandler(self, self.my_jid, their_jid, thread, self.replay)
			self.handler_dict[ok][tk] = handler
			handler.echolalic = True # just repeat stuff
		return handler
	
	# initate otr on the given connection
	def start_otr(self, uto, thread):
		handler = self.get_handler(uto, thread)
		handler.initiate()
		
	# stop otr on the given connection
	def stop_otr(self, uto, thread):
		handler = self.get_handler(uto, thread)
		stopMsg = handler.finish()
		
	# pipes outgoing jabber messages through the otr handler
	def send_message(self, msg):
		uto = msg.getTo()
		thread = msg.getThread()
		handler = self.get_handler(uto, thread)
		msgEnc = handler.process_outgoing(msg)
		print "CLIENT SENDING: "+ustr(msgEnc)
		self.send(msgEnc)
		
	# pipes incoming jabber messages through the otr handler
	def recv_message(self, client, msg):
		ufrom = msg.getFrom()
		thread = msg.getThread()
		handler = self.get_handler(ufrom, thread)
		msgDec = handler.process_incoming(msg)
		if msgDec:
			print "CLIENT RECEIVED: "+ustr(msgDec)
	
	# this is for inheritance
	def disconnectHandler(self):
		return

# default run parameters
if __name__ == "__main__":
	if len(sys.argv) == 3:
		assert(sys.argv[2] == "replay")
		assert(sys.argv[1] == "initiate" or sys.argv[1] == "wait")
		import test_client_arams as tcp
		import otr_replay_data
		if sys.argv[1] == "initiate":
			replay = OtrReplay(data=otr_replay.alice, do_both_sides=False)
		else:
			replay = OtrReplay(data=otr_replay.bob, do_both_sides=False)
		client = TestClient(tcp.my_username, tcp.my_hostname, tcp.my_resource, tcp.my_password, replay=replay)
		if sys.argv[1] == "initiate":
			client.start_otr(tcp.test_jid, None)
		while True:
			#time.sleep(1)
			client.process(1)
			
	elif len(sys.argv) == 2:
		assert(sys.argv[1] == "initiate" or sys.argv[1] == "wait")
		import test_client_params as tcp
		client = TestClient(tcp.my_username, tcp.my_hostname, tcp.my_resource, tcp.my_password)
		if sys.argv[1] == "initiate":
			client.start_otr(tcp.test_jid, None)
		while True:
			#time.sleep(1)
			client.process(1)
			
	else:
		print "USE: "+sys.argv[0]+" [initiate | wait] [replay | ]" 
