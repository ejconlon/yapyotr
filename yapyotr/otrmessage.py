# Part of yapyotr - copyright 2009 Eric Conlon
# Licensed under the GPLv3
# ejconlon@gmail.com | http://it.fuelsyourcyb.org

import logging, base64, jabber, sys
from bytestreamreader import ByteStreamReader
from otrtypes import OtrTypes as _OT
from otrvars import *
ustr = jabber.ustr

# This wraps a jabber message and automatically
# classifies, validates, and unpacks it
class OtrMessage:
	@staticmethod
	def get_type(msg):
		body = msg.getBody()
		if body is None: 
			return "other"
		elif (body.startswith(OtrConstants['text_dh_commit'])):
			return "dh_commit"
		elif (body.startswith(OtrConstants['text_dh_key'])):
			return "dh_key"
		elif (body.startswith(OtrConstants['text_reveal_sig'])):
			return "reveal_sig"
		elif (body.startswith(OtrConstants['text_signature'])):
			return "signature"
		elif (body.startswith(OtrConstants['text_v1_key_exch'])):
			return "v1_key_exchange"
		elif (body.startswith(OtrConstants['text_data_1'])):
			return "data"
		elif (body.startswith(OtrConstants['text_data_2'])):
			return "data"
		elif body.startswith(OtrConstants['text_error']):
			return "error"
		elif body.startswith(OtrConstants['text_query_1']):
			return "query"
		elif body.startswith(OtrConstants['text_query_2']):
			return "query"
		elif body.find(OtrConstants['whitespace_base']) >= 0:
			return "whitespaced"
		else:
			# plaintext message, no whitespace tag
			return "plaintext"

	# init with msg=None creates a blank message we can
	# initialize with a create_* routine
	# otherwise it automatically parses msg
	def __init__(self, msg=None, from_jid=None, to_jid=None, thread=None):
		self.jabber_msg = msg
		self.type = None
		self.parsed_ok = False
		if msg is None: 
			self.from_jid = from_jid
			self.to_jid = to_jid
			self.thread = thread
		else:
			self.from_jid = msg.getFrom()
			self.to_jid = msg.getTo()
			self.thread = msg.getThread()
			self.parsers[OtrMessage.get_type(msg)](self)
	
	def payload_to_bytes(self, payload):
		return _OT.string_to_bytes(base64.b64decode(payload))
	def bytes_to_payload(self, bytes):
		return base64.b64encode(bytes)
	
	def parse_versions(self, s):
		versions = dict(((x,False) for x in ['1','2']))
		v_string = s[4:]
		last_q_mark_index = v_string[1:].find('?')
		if (last_q_mark_index >= 0):
			v_string = v_string[:last_q_mark_index+1]
		logging.debug( ("v_string", v_string) )
		for char in v_string:
			if char == '?':
				versions['1'] = True
			elif char == 'v':
				pass
			else:
				versions[char] = True
		return versions

	def parse_plaintext(self):
		self.type = "plaintext"
		self.parsed_ok = True
		
	def parse_query(self):
		self.type = "query"
		self.versions = self.parse_versions(self.jabber_msg.getBody())
		self.parsed_ok = True
		
	def parse_whitespaced(self):
		self.type = "whitespaced"
		body = self.jabber_msg.getBody()
		wb_index = body.find(OtrConstants["whitespace_base"])
		new_start = wb_index + len(OtrConstants["whitespace_base"])
		self.versions = {}
		self.versions['1'] = (body[newstart:].find(OtrConstants["whitespace_v1"]) >= 0)
		self.versions['2'] = (body[newstart:].find(OtrConstants["whitespace_v2"]) >= 0)
		self.parsed_ok = True
	
	def parse_vars(self):
		body = self.jabber_msg.getBody()
		assert(body[0:0+5] == "?OTR:")
		assert(body[-1] == ".")
		payload = body[5:-1]
		bytes = self.payload_to_bytes(payload)
			
		byte_reader = ByteStreamReader(bytes)
		parsed_vars = byte_reader.parse_format(self.vars)
		self.__dict__.update(parsed_vars)
							
		if not byte_reader.consumed_all():
			raise Exception('Invalid message format: expected %d bytes; got %d' % (o, len(bytes)))
		if self.protocol_version != list(OtrConstants["version_2_bytes"]):
			raise Exception('Invalid protocol version: %s' % str(self.protocol_version))
		if self.message_type != self.code:
			raise Exception('Invalid message type: expected %s, got %s' % (self.code, self.message_type))
			
	
	def parse_dh_commit(self):
		self.type = "dh_commit"
		self.vars = (
			("protocol_version", "short"),
			("message_type", "byte"),
			("enc_gxmpi_data", "data"),
			("hash_gxmpi_data", "data")
		)
		self.code = [OtrConstants["code_dh_commit"]]
		try:
			self.parse_vars()
			self.parsed_ok = True
		except:
			logging.error( "ERROR IN PARSING DH_COMMIT" )
			logging.error( sys.exc_info()[1] )
			self.parsed_ok = False
		
	def parse_dh_key(self):
		self.type = "dh_key"
		self.vars = (
			("protocol_version", "short"),
			("message_type", "byte"),
			("gympi", "mpi")
		)
		self.code = [OtrConstants["code_dh_key"]]
		try:
			self.parse_vars()
			self.parsed_ok = True
		except:
			logging.error( sys.exc_info()[1] )
			self.parsed_ok = False
			
	def parse_reveal_sig(self):
		self.type = "reveal_sig"
		self.vars = (
			("protocol_version", "short"),
			("message_type", "byte"),
			("revealed_key_data", "data"),
			("enc_sig_data", "data"),
			("sig_mac", "mac")
		)
		self.code = [OtrConstants["code_reveal_sig"]]
		try:
			self.parse_vars()
			self.parsed_ok = True
		except:
			logging.error( sys.exc_info()[1] )
			self.parsed_ok = False
	
	def parse_signature(self):
		self.type = "signature"
		self.vars = (
			("protocol_version", "short"),
			("message_type", "byte"),
			("enc_sig_data", "data"),
			("sig_mac", "mac")
		)
		self.code = [OtrConstants["code_signature"]]
		try:
			self.parse_vars()
			self.parsed_ok = True
		except:
			logging.error( sys.exc_info()[1] )
			self.parsed_ok = False
	
	def parse_v1_key_exchange(self):
		self.type = "v1_key_exchange"
	
	def parse_data(self):
		self.type = "data"
		self.vars = (
			("protocol_version", "short"),
			("message_type", "byte"),
			("flags", "byte"),
			("sender_keyid", "int"),
			("recipient_keyid", "int"),
			("next_dh", "mpi"),
			("counter", "ctr"),
			("enc_msg", "data"),
			("authenticator", "mac"),
			("old_mac_keys", "data")
		)
		self.code = [OtrConstants["code_data"]]
		try:
			#print 'parsing data'
			self.parse_vars()
			self.parsed_ok = True
			#print 'parsed data'
		except:
			logging.error( sys.exc_info()[0], sys.exc_info()[1] )
			self.parsed_ok = False
	
	def parse_error(self):
		self.type = "error"
		self.error_text = self.jabber_msg.getBody()
		self.parsed_ok = True
		
	def parse_other(self):
		self.type = "other"
		self.parsed_ok = True
		
	def make_jabber_message(self, text=None):
		msg = jabber.Message()
		msg.setFrom(self.from_jid)
		msg.setTo(self.to_jid)
		msg.setType('chat')
		if self.thread and self.thread != '__default':
			msg.setThread(self.thread)
		if text:
			msg.setBody(text)
		return msg
		
	def create_error(self, error_text):
		self.type = "error"
		self.jabber_msg = self.make_jabber_message('?OTR Error: '+error_text)
		self.error_text = error_text
		self.parsed_ok = True
		return self
		
	def create_plaintext(self, text):
		self.type = "plaintext"
		self.jabber_msg = self.make_jabber_message(text)
		self.parsed_ok = True
		return self
		
	def create_query(self):
		# TODO Plaintext msg for clients that don't support OTR
		self.type = "query"
		self.versions = {'1': False, '2': True, '4': False, 'x': False}
		self.jabber_msg = self.make_jabber_message('?OTRv2?')
		self.parsed_ok = True
		return self
	
	def pack_message(self, bytes):
		message_data = _OT.bytes_to_cbytes(bytes)
		message_data_str = base64.b64encode(message_data)
		body_str = "?OTR:" + message_data_str+"."
		self.jabber_msg = self.make_jabber_message(body_str)
	
	def create_dh_commit(self, enc_gxmpi_data, hash_gxmpi_data):
		self.type = "dh_commit"
		
		self.protocol_version = list(OtrConstants["version_2_bytes"])
		self.message_type = [OtrConstants["code_dh_commit"]]
		self.enc_gxmpi_data = enc_gxmpi_data
		self.hash_gxmpi_data = hash_gxmpi_data
		
		if ( not _OT.check_data(enc_gxmpi_data) or 
		     not _OT.check_data(hash_gxmpi_data) ):
			raise Exception('Invalid data format')
		
		message_data = self.protocol_version + self.message_type + \
						self.enc_gxmpi_data + self.hash_gxmpi_data
		self.pack_message(message_data)
		self.parsed_ok = True
		return self
		
	def create_dh_key(self, gympi):
		self.type = "dh_key"
		
		self.protocol_version = list(OtrConstants["version_2_bytes"])
		self.message_type = [OtrConstants["code_dh_key"]]
		self.gympi = gympi
		
		if ( not _OT.check_mpi(gympi) ):
			raise Exception('Invalid data format')
		
		message_data = self.protocol_version + self.message_type + \
						self.gympi
		self.pack_message(message_data)
		self.parsed_ok = True
		return self
	
	def create_reveal_sig(self, revealed_key_data, enc_sig_data, sig_mac):
		self.type = "reveal_sig"
		
		self.protocol_version = list(OtrConstants["version_2_bytes"])
		self.message_type = [OtrConstants["code_reveal_sig"]]
		
		self.revealed_key_data = revealed_key_data
		self.enc_sig_data = enc_sig_data
		self.sig_mac = sig_mac
		
		if ( not _OT.check_data(revealed_key_data) or
			 not _OT.check_data(enc_sig_data) ):
			raise Exception('Invalid data format')
		
		if ( not _OT.check_mac(sig_mac) ):
			raise Exception('Invalid MAC')
		
		message_data = self.protocol_version + self.message_type + \
						revealed_key_data + enc_sig_data + sig_mac
		self.pack_message(message_data)
		self.parsed_ok = True
		return self
	
	def create_signature(self, enc_sig_data, sig_mac):
		self.type = "signature"
		self.protocol_version = list(OtrConstants["version_2_bytes"])
		self.message_type = [OtrConstants["code_signature"]] 
		
		self.enc_sig_data = enc_sig_data
		self.sig_mac = sig_mac
		
		if ( not _OT.check_data(enc_sig_data) ):
			raise Exception('Invalid data format')
		
		if ( not _OT.check_mac(sig_mac) ):
			raise Exception('Invalid MAC')
		
		message_data = self.protocol_version + self.message_type + \
						enc_sig_data + sig_mac
		self.pack_message(message_data)
		self.parsed_ok = True
		return self
		
	def create_v1_key_exchange(self):
		raise Exception('Version 1 Not Supported')
	
	def create_data(self, flags, sender_keyid, recipient_keyid, next_dh,
					counter, enc_msg, authenticator, old_mac_keys):
		self.type = "data"
		#self.vars = (
		#	("protocol_version", "short"),
		#	("message_type", "byte"),
		#	("flags", "byte"),
		#	("sender_keyid", "int"),
		#	("recipient_keyid", "int"),
		#	("next_dh", "mpi"),
		#	("counter", "ctr"),
		#	("enc_msg", "data"),
		#	("authenticator", "mac"),
		#	("old_mac_keys", "data")
		#)
		
		if ( not len(flags) == 1 ):
			raise Exception('Invalid data format: flags')
		
		if ( not len(sender_keyid) == 4 ):
			raise Exception('Invalid data format: sender_keyid')
		
		if ( not len(recipient_keyid) == 4 ):
			raise Exception('Invalid data format: recipient_keyid')
		
		if ( not _OT.check_mpi(next_dh) ):
			raise Exception('Invalid data format: next_dh')
		
		if (not len(counter) == 8 ):
			raise Exception('Invalid data format: counter')
		
		if ( not _OT.check_data(enc_msg) ):
			raise Exception('Invalid data format: enc_msg')
		
		if ( not _OT.check_mac(authenticator) ):
			raise Exception('Invalid data format: authenticator')
		
		if ( not _OT.check_data(old_mac_keys) ):
			raise Exception('Invalid data format: old_mac_keys')
		
		self.protocol_version = list(OtrConstants["version_2_bytes"])
		self.message_type = [OtrConstants["code_data"]]
		
		self.flags = flags
		self.sender_keyid = sender_keyid
		self.recipient_keyid = recipient_keyid
		self.next_dh = next_dh
		self.counter = counter
		self.enc_msg = enc_msg
		self.authenticator = authenticator
		self.old_mac_keys = old_mac_keys
		
		message_data = self.protocol_version + self.message_type + \
						flags + sender_keyid + recipient_keyid + \
						next_dh + counter + enc_msg + authenticator + \
						old_mac_keys
		self.pack_message(message_data)
		self.parsed_ok = True
		return self
										
	parsers = {
	"plaintext"			: parse_plaintext, 
	"query"				: parse_query, 
	"whitespaced"       : parse_whitespaced,
	"dh_commit"			: parse_dh_commit, 
	"dh_key"			: parse_dh_key,
	"reveal_sig"		: parse_reveal_sig, 
	"signature"			: parse_signature,
	"v1_key_exchange"	: parse_v1_key_exchange, 
	"data"				: parse_data, 
	"error"				: parse_error,
	"other"				: parse_other
	}
