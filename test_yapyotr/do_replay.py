#!/opt/local/bin/python2.5
# Part of yapyotr - copyright 2009 Eric Conlon
# Licensed under the GPLv3
# ejconlon@gmail.com | http://it.fuelsyourcyb.org

from yapyotr import *
import otr_replay_data

bob_jid = "bob@localhost.localdomain/replay"
alice_jid = "alice@localhost.localdomain/replay"
replays = {
	bob_jid: OtrReplay(otr_replay_data.bob),
	alice_jid: OtrReplay(otr_replay_data.alice)
}

class DummyClient:
	def __init__(self):
		global replays, bob_jid, alice_jid
		self.handler_dict = {}
		self.bob_jid = bob_jid
		self.alice_jid = alice_jid
		self.thread = "replay_thread" 
		self.bob_handler = self.get_handler(bob_jid, alice_jid, self.thread, replays[bob_jid])
		self.alice_handler = self.get_handler(alice_jid, bob_jid, self.thread, replays[alice_jid])

	def get_handler(self, my_jid, their_jid, thread, replay=None):
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
			handler = OtrHandler(self, my_jid, their_jid, thread, replay)
			self.handler_dict[ok][tk] = handler
		return handler
		
	def start_replay(self):
		self.alice_handler.initiate()
		
	def send_data(self):
		msg_text = "Hey bob, what's up?"
		msg = OtrMessage(from_jid=self.alice_jid, to_jid=self.bob_jid, 
			thread=self.thread).make_jabber_message(msg_text)
		self.alice_handler.process_outgoing(msg)
		
		msg_text = "not much, alice, what's up with you?"
		msg = OtrMessage(from_jid=self.bob_jid, to_jid=self.alice_jid, 
			thread=self.thread).make_jabber_message(msg_text)
		self.bob_handler.process_outgoing(msg)
		
		msg_text = "nm, hey did you get that thing i sent you?"
		msg = OtrMessage(from_jid=self.alice_jid, to_jid=self.bob_jid, 
			thread=self.thread).make_jabber_message(msg_text)
		self.alice_handler.process_outgoing(msg)
		
		msg_text = "you know, that thing"
		msg = OtrMessage(from_jid=self.alice_jid, to_jid=self.bob_jid, 
			thread=self.thread).make_jabber_message(msg_text)
		self.alice_handler.process_outgoing(msg)
		
		msg_text = "yeah, thanks for the thing"
		msg = OtrMessage(from_jid=self.bob_jid, to_jid=self.alice_jid, 
			thread=self.thread).make_jabber_message(msg_text)
		self.bob_handler.process_outgoing(msg)
		
		
		
	# pipes outgoing jabber messages through the otr handler
	def send_message(self, msg):
		uto = msg.getTo()
		ufrom = msg.getFrom()
		thread = msg.getThread()
		handler = self.get_handler(ufrom, uto, thread)
		msgEnc = handler.process_outgoing(msg)
		print "CLIENT SENDING: "+ustr(msgEnc)
		self.send(msgEnc)
		
	# pipes incoming jabber messages through the otr handler
	def recv_message(self, client, msg):
		uto = msg.getTo()
		ufrom = msg.getFrom()
		thread = msg.getThread()
		handler = self.get_handler(uto, ufrom, thread)
		msgDec = handler.process_incoming(msg)
		if msgDec:
			print "CLIENT RECEIVED: "+ustr(msgDec)
			
	def send(self, msg):
		self.recv_message(None, msg)

if __name__ == "__main__":
	client = DummyClient()
	client.start_replay()
	client.send_data()
