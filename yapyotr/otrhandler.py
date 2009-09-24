# Part of yapyotr - copyright 2009 Eric Conlon
# Licensed under the GPLv3
# ejconlon@gmail.com | http://it.fuelsyourcyb.org

import logging
from otrtypes import OtrTypes as _OT
from otrreplay import OtrReplay
from otrmessage import OtrMessage
from otrauth import OtrAuth
from otrvars import *

class OtrHandler:

	def __init__(self, client, my_jid, their_jid, thread, replay=OtrReplay()):
		self.echolalic = False
		self.my_jid = my_jid
		self.their_jid = their_jid
		self.thread = thread
		self.replay = replay
		self.client = client
		self.auth = OtrAuth(self.replay)
				
	def message_factory(self):
		return OtrMessage(from_jid=self.my_jid, to_jid=self.their_jid, thread=self.thread)
				
	def initiate(self):
		if ( not self.auth.message_state_is("MSGSTATE_PLAINTEXT") or
			 not self.auth.auth_state_is("AUTHSTATE_NONE") ):
			logging.error("Protocol already initiated")
			return
		# send query
		query = self.message_factory()
		query.create_query()
		self.client.send(query.jabber_msg)
	
	def respond_to_plaintext(self, msg):
		if self.auth.message_state_is("MSGSTATE_PLAINTEXT"):
			if OtrOptions["REQUIRE_ENCRYPTION"]:
				logging.warn("Message was received UNENCRYPTED.")
		else:
			logging.warn("Message was received UNENCRYPTED.")
		return msg.jabber_msg # display plaintext to user
		
	# wait
	def respond_to_query(self, msg):
		logging.debug("Responding to Query")
		logging.debug("OTR REQUEST: "+str(msg.versions))
		
		if not msg.versions['2']:
			response = self.message_factory().create_error('Version 1 Not Supported')
			self.client.send(response)
			return None # nothing to show user
		
		# RESPOND WITH DH_COMMIT MESSAGE
		
		my_dh_keyid = self.auth.dh_keys.get_my_cur_keyid()
		self.auth.dh_keys.generate_r_secret()
		self.auth.dh_keys.mark_my_key_as_used(my_dh_keyid)
		enc_gxmpi_data = self.auth.dh_keys.encrypt_my_public_factor_mpi(my_dh_keyid)
		hash_gxmpi_data = self.auth.dh_keys.hash_my_public_factor_mpi(my_dh_keyid)
		
		response = self.message_factory().create_dh_commit(enc_gxmpi_data, hash_gxmpi_data)
		
		self.replay.check('msg_dh_commit', response.jabber_msg.getBody())
		
		self.auth.set_auth_state("AUTHSTATE_AWAITING_DHKEY")
		self.client.send(response.jabber_msg)
		
		return None # nothing to user
		
	def respond_to_whitespaced(self, msg):
		logging.debug("Responding to Whitespaced")
		logging.debug("OTR (secret) REQUEST: "+str(msg.versions))
	
		if self.auth.message_state_is("MSGSTATE_PLAINTEXT"):
			if OtrOptions["REQUIRE_ENCRYPTION"]:
				logging.warn("Message was received UNENCRYPTED.")
		else:
			logging.warn("Message was received UNENCRYPTED.")
		
		# replace the whitespace tags
		body = msg.jabber_msg.getBody()
		body = body.replace(OtrConstants['whitespace_base'], '')
		body = body.replace(OtrConstants['whitespace_v1'], '')
		body = body.replace(OtrConstants['whitespace_v2'], '')
		msg.jabber_msg.setBody(body)
		
		if OtrOptions["WHITESPACE_START_AKE"]:
			if not msg.versions['2']:
				response = self.message_factory().create_error('Version 1 Not Supported')
				self.client.send(response)
				return None # nothing to show user
		
			# RESPOND WITH DH_COMMIT MESSAGE
			
			my_dh_keyid = self.auth.dh_keys.get_my_cur_keyid()
			self.auth.dh_keys.generate_r_secret()
			self.auth.dh_keys.mark_my_key_as_used(my_dh_keyid)
			enc_gxmpi_data = self.auth.dh_keys.encrypt_my_public_factor_mpi(my_dh_keyid)
			hash_gxmpi_data = self.auth.dh_keys.hash_my_public_factor_mpi(my_dh_keyid)		
			
			response = self.message_factory().create_dh_commit(enc_gxmpi_data, hash_gxmpi_data)
		
			self.replay.check('msg_dh_commit', response.jabber_msg.getBody())
		
			self.auth.set_auth_state("AUTHSTATE_AWAITING_DHKEY")
			self.client.send(response.jabber_msg)
		
		return msg.jabber_msg # send user the plaintext message
		
	# initiate	
	def respond_to_dh_commit(self, msg):
		logging.debug("Responding to DH Commit")
		
		send_dh_key = True
		
		if self.auth.auth_state_is("AUTHSTATE_NONE"):
			# Reply with a D-H Key Message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG.
			pass # pick it up in the 'if' below
			
		elif self.auth.auth_state_is("AUTHSTATE_AWAITING_DHKEY"):
			#This is the trickiest transition in the whole protocol. It indicates that you have
			# already sent a D-H Commit message to your correspondent, but that he either
			#  didn't receive it, or just didn't receive it yet, and has sent you one as well. 
			#  The symmetry will be broken by comparing the hashed gx you sent in your D-H Commit 
			#  Message with the one you received, considered as 32-byte unsigned big-endian values.
			my_dh_keyid = self.auth.dh_keys.get_my_cur_keyid()
			
			my_hashed_gxmpi = self.auth.dh_keys.hash_my_public_factor_mpi(my_dh_keyid)
			their_hashed_gxmpi = _OT.data_to_bytes(msg.hash_gxmpi_data)
			
			my_hash_as_int = _OT.bytes_to_int(my_hashed_gxmpi)
			their_hash_as_int = _OT.bytes_to_int(their_hashed_gxmpi)
		
			if my_hash_as_int > their_hash_as_int:
				# If yours is the higher hash value:
				# Ignore the incoming D-H Commit message, but resend your D-H Commit message.
				self.auth.dh_keys.mark_my_key_as_used(my_dh_keyid)
				enc_gxmpi_data = self.auth.dh_keys.encrypt_my_public_factor_mpi(my_dh_keyid)
				hash_gxmpi_data = self.auth.dh_keys.hash_my_public_factor_mpi(my_dh_keyid)
				response = self.message_factory().create_dh_commit(enc_gxmpi_data, hash_gxmpi_data)
				self.replay.check('msg_dh_commit', response.jabber_msg.getBody())
				send_dh_key = False
				self.client.send(response.jabber_msg)
							
		if send_dh_key:
			my_dh_keyid = self.auth.dh_keys.get_my_cur_keyid()
			self.auth.dh_keys.mark_my_key_as_used(my_dh_keyid)
		
			# this is g**y formatted as an MPI (4 byte length prepended)	
			# our D-H secret is y (with g**x the shared key is g**(xy))
			gympi = self.auth.dh_keys.my_public_factor_to_mpi(my_dh_keyid)
		
			# SAVE their info
			self.auth.dh_keys.store_their_commitment( _OT.data_to_bytes(msg.enc_gxmpi_data),
													  _OT.data_to_bytes(msg.hash_gxmpi_data) )
		
			# ok, now make dh_key message
			response = self.message_factory().create_dh_key(gympi)
			self.replay.check('msg_dh_key', response.jabber_msg.getBody())
			self.auth.set_auth_state("AUTHSTATE_AWAITING_REVEALSIG")
			self.client.send(response.jabber_msg)
				
		return None # nothing for user
	
	# wait
	def respond_to_dh_key(self, msg):
		logging.debug("Responding to DH Key")
		
		send_reveal_sig = True
		
		my_dh_keyid = self.auth.dh_keys.get_my_cur_keyid()
		
		if self.auth.auth_state_is("AUTHSTATE_AWAITING_DHKEY"):
			# calculate the shared dh key
			their_dh_factor = _OT.mpi_to_int(msg.gympi)
			self.auth.dh_keys.store_their_public_factor(their_dh_factor)
			
			# calculate the factor's we'll need
			self.auth.dh_keys.compute_c_and_m_factors()
		
			# load DSA key
			self.auth.dsa_keys.load_my_key()
		
			self.auth.compute_my_M_and_X_values()
			
		elif self.auth.auth_state_is("AUTHSTATE_AWAITING_SIG"):
			if msg.gympi == self.auth.dh_keys.their_public_factor_to_mpi():
				pass # retransmit reveal sig msg
			else:
				send_reveal_sig = False
		else:
			send_reveal_sig = False
			
		if send_reveal_sig:
			revealed_key_data = self.auth.dh_keys.get_r_secret()
			enc_sig_data = self.auth.get_enc_sig()
			sig_mac = self.auth.get_enc_sig_mac()
			response = self.message_factory().create_reveal_sig(revealed_key_data, enc_sig_data, sig_mac)
			self.replay.check('msg_reveal_sig', response.jabber_msg.getBody())
			self.auth.set_auth_state("AUTHSTATE_AWAITING_SIG")
			self.client.send(response.jabber_msg)
		
		return None # nothing for user
	
	# etc	
	def respond_to_reveal_sig(self, msg):
		logging.debug("Responding to Reveal Sig")
		if not self.auth.auth_state_is("AUTHSTATE_AWAITING_REVEALSIG"):
			return None # nothing for user
			
		# Now decrypt and check their DH factor 
		my_dh_keyid = self.auth.dh_keys.get_my_cur_keyid()
		it_checks_out = self.auth.dh_keys.decrypt_their_public_factor( _OT.data_to_bytes(msg.revealed_key_data) )
		
		if not it_checks_out:
			err_msg = self.message_factory()
			err_msg.create_error('Committed DH factor incorrect')
			self.client.send(err_msg.jabber_msg)
			return None # nothing for user
			raise Exception('stop here - committed DH factor incorrect')
			
		# calculate the factors we'll need
		self.auth.dh_keys.compute_c_and_m_factors()
		
		# check their sig
		it_checks_out = self.auth.check_their_sig(_OT.data_to_bytes(msg.enc_sig_data), msg.sig_mac)
		
		if not it_checks_out:
			err_msg = self.message_factory()
			err_msg.create_error('Signature incorrect')
			self.client.send(err_msg.jabber_msg)
			return None # nothing for user
			#raise Exception('stop here - signature incorrect')
		
		# ok, now make our sig message
		# load DSA key
		self.auth.dsa_keys.load_my_key()
				
		self.auth.compute_my_M_and_X_values(usePrimes=True)
		enc_sig_data = self.auth.get_enc_sig()
		sig_mac = self.auth.get_enc_sig_mac(usePrimes=True)
		
		response = self.message_factory().create_signature(enc_sig_data, sig_mac)
		
		self.replay.check('msg_signature', response.jabber_msg.getBody())
		
		self.client.send(response.jabber_msg)
		
		self.auth.set_auth_state("AUTHSTATE_NONE")
		self.auth.set_message_state("MSGSTATE_ENCRYPTED")
		self.auth.dh_keys.reset_session()
		self.auth.authing = False
		self.auth.dh_keys.authing = False
		
		return None # nothing for user
		
	def respond_to_signature(self, msg):
		logging.debug("Responding to Signiature")
		
		if not self.auth.auth_state_is("AUTHSTATE_AWAITING_SIG"):
			return None # nothing for user
		
		# check their sig
		it_checks_out = self.auth.check_their_sig(_OT.data_to_bytes(msg.enc_sig_data), msg.sig_mac, usePrimes=True)
		
		if not it_checks_out:
			err_msg = self.message_factory()
			err_msg.create_error('Signature incorrect')
			self.client.send(err_msg.jabber_msg)
			return None # nothing for user
			#raise Exception('stop here - signature incorrect')
		
		self.auth.set_auth_state("AUTHSTATE_NONE")
		self.auth.set_message_state("MSGSTATE_ENCRYPTED")
		self.auth.dh_keys.reset_session()
		self.auth.authing = False
		self.auth.dh_keys.authing = False
		
		logging.debug( "SUCESSFULLY AUTHENTICATED!" )
		
		return None
		
	def respond_to_v1_key_exchange(self, msg):
		logging.debug("Responding to V1 Key Exchange")
		msg = self.message_factory().create_error('Version 1 Not Supported')
		self.client.send(msg)
		return None
		
	def respond_to_data(self, msg):
		logging.debug("Responding to Data")
		if self.auth.message_state_is("MSGSTATE_ENCRYPTED"):
			# Verify the info in the message
			
			dec_msg = self.auth.dh_keys.receive_data_message(msg)
			logging.debug( dec_msg )
			if len(dec_msg) > 0:
				logging.debug( "DECRYPTED: "+_OT.bytes_to_string(dec_msg) )
				if self.echolalic:
					msg = self.message_factory().make_jabber_message(_OT.bytes_to_string(dec_msg))
					self.process_outgoing(msg)
			# If verification succeeds:
			
			# Decrypt the message and display the human-readable part (if non-empty) to the user.
			
			# Update the D-H encryption keys, if necessary.
			
			# If you have not sent a message to this correspondent in some (configurable) time, 
			# send a "heartbeat" message, consisting of a Data Message encoding an empty plaintext. 
			# The heartbeat message should have the IGNORE_UNREADABLE flag set.
			
			# If the received message contains a TLV type 1, forget all encryption keys 
			# for this correspondent, and transition msgstate to MSGSTATE_FINISHED.
			
		else:
			# Inform the user that an unreadable encrypted message was received, and reply with an Error Message.
			# TODO check for heartbeat messages
			
			logging.debug( "Not ready!" )
			pass
			
		return None
		
	def respond_to_error(self, msg):
		logging.debug("Responding to Error")
		logging.error(msg.error_text)
		if OtrOptions["ERROR_START_AKE"]:
			msg = self.message_factory().create_query()
			self.client.send(msg)
		return None
	
	def respond_to_other(self, msg):
		logging.debug("Responding to Other")
		logging.error("Undecipherable message: "+str(msg.jabber_msg))
		return None
	
	def finish(self):
		if self.auth.message_state_is("MSGSTATE_PLAINTEXT"):
			# Do nothing.
			pass
		elif self.auth.message_state_is("MSGSTATE_ENCRYPTED"):
			# Send a Data Message, encoding a message with an empty human-readable part, 
			# and TLV type 1. Transition msgstate to MSGSTATE_PLAINTEXT.
			# TODO send the data message
			self.auth.set_message_state("MSGSTATE_PLAINTEXT")
		elif self.auth.message_state_is("MSGSTATE_FINISHED"):
			# Transition msgstate to MSGSTATE_PLAINTEXT.
			self.auth.set_message_state("MSGSTATE_PLAINTEXT")
	
	def process_outgoing(self, msg):
		logging.debug("Outgoing")
		if self.auth.message_state_is("MSGSTATE_ENCRYPTED"):
			self.auth.dh_keys.prepare_session_to_send()
			vars = self.auth.dh_keys.encrypt_data_message(_OT.string_to_bytes(msg.getBody()))
			logging.debug( vars )
			#r = raw_input()
			enc_msg = self.message_factory().create_data(*vars)
			self.client.send(enc_msg.jabber_msg)
		else:
			self.client.send(msg)
		return msg
	
	responders = {
	"plaintext"			: respond_to_plaintext, 
	"query"				: respond_to_query,
	"whitespaced"		: respond_to_whitespaced,
	"dh_commit"			: respond_to_dh_commit, 
	"dh_key"			: respond_to_dh_key,
	"reveal_sig"		: respond_to_reveal_sig, 
	"signature"			: respond_to_signature,
	"v1_key_exchange"	: respond_to_v1_key_exchange, 
	"data"				: respond_to_data, 
	"error"				: respond_to_error,
	"other"				: respond_to_other
	}
	
	def process_incoming(self, msg):
		logging.debug("Incoming")
		otr_msg = OtrMessage(msg)
		if not otr_msg.parsed_ok:
			logging.error('Received strange message: %s' % str(msg))
		else:
			return self.responders[otr_msg.type](self, otr_msg)
