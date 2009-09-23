# Part of yapyotr - copyright 2009 Eric Conlon
# Licensed under the GPLv3
# ejconlon@gmail.com | http://it.fuelsyourcyb.org

import logging
from otrtypes import OtrTypes as _OT
from otrreplay import OtrReplay
from otrdh import OtrDH
from otrdsa import OtrDSA
from otrcrypt import OtrCrypt
from bytestreamreader import ByteStreamReader
from otrvars import *

# It's a mess
# Created at the start of new authentication over a channel
# holds all the data, crypt routines, and shorthand funcs
class OtrAuth:	
	
	# SOME OTR VARS, defined in the spec
	msd = {
	"MSGSTATE_PLAINTEXT"			: 0,
	"MSGSTATE_ENCRYPTED"			: 1,
	"MSGSTATE_FINISHED"				: 2
	}

	asd = {
	"AUTHSTATE_NONE"				: 0,
	"AUTHSTATE_AWAITING_DHKEY"		: 1,
	"AUTHSTATE_AWAITING_REVEALSIG"	: 2,
	"AUTHSTATE_AWAITING_SIG"		: 3,
	"AUTHSTATE_V1_SETUP"			: 4
	}
	
	def __init__(self, replay=OtrReplay()):
		self.replay=replay
		self.dh_keys = OtrDH(replay=replay)
		self.dsa_keys = OtrDSA(replay=replay)
		self.message_state = self.msd["MSGSTATE_PLAINTEXT"]
		self.auth_state = self.asd["AUTHSTATE_NONE"]
		self.authing = True
	
	def set_message_state(self, mst):
		self.message_state = self.msd[mst]
		#print "SETTING MESSAGE STATE: "+mst
		#r = raw_input()
	def message_state_is(self, mst):
		return self.message_state == self.msd[mst]
	def set_auth_state(self, ast):
		self.auth_state = self.asd[ast]
		#print "SETTING AUTH STATE: "+ast
		#r = raw_input()
	def auth_state_is(self, ast):
		return self.auth_state == self.asd[ast]
				
	def compute_my_M_and_X_values(self, usePrimes=False):
		my_dh_keyid = self.dh_keys.get_my_cur_keyid()
		if usePrimes:
			cKey = self.dh_keys.cprime
			m1Key = self.dh_keys.m1prime
		else:
			cKey = self.dh_keys.c
			m1Key = self.dh_keys.m1
		
		# Compute the 32-byte value MB to be the SHA256-HMAC of the following data, using the key m1:
		mbytes = []
		# gx (MPI)
		mbytes.extend( self.dh_keys.my_public_factor_to_mpi(my_dh_keyid) )
		# gy (MPI)
		mbytes.extend( self.dh_keys.their_public_factor_to_mpi() )
		# pubB (PUBKEY)
		mbytes.extend( OtrDSA.format_key(self.dsa_keys.my_public_key) )
		# keyidB (INT)
		keyid = _OT.zero_pad(_OT.int_to_bytes(my_dh_keyid), 4)
		mbytes.extend( keyid )
		self.replay.check('M', mbytes)
		my_M = OtrCrypt.get_sha256_hmac(m1Key, mbytes)
		self.replay.check('hash_M', my_M)
		
		# Let XB be the following structure:
		xbytes = []
		# pubB (PUBKEY)
		xbytes.extend( OtrDSA.format_key(self.dsa_keys.my_public_key) )
		# keyidB (INT)
		xbytes.extend( keyid )
		# sigB(MB) (SIG)
		# This is the signature, using the private part of the key pubB, of the 32-byte MB 
		# (which does not need to be hashed again to produce the signature).
		xbytes.extend( self.dsa_keys.sign( my_M ) )
		my_X = xbytes
		self.replay.check('X', my_X)
		
		# Encrypt XB using AES128-CTR with key c and initial counter value 0.
		self.my_enc_sig = OtrCrypt.aes_zero_ctr_crypt(cKey, my_X)
		self.replay.check('enc_X', self.my_enc_sig)

	def get_enc_sig(self):
		return _OT.bytes_to_data(self.my_enc_sig)

	def get_enc_sig_mac(self, usePrimes=False):
		if usePrimes:
			m2Key = self.dh_keys.m2prime
		else:
			m2Key = self.dh_keys.m2
		enc_sig_mac = OtrCrypt.get_sha256_hmac_160(m2Key, _OT.bytes_to_data(self.my_enc_sig))
		self.replay.check('hash_enc_X', enc_sig_mac)
		return enc_sig_mac

	def compute_their_M_factor(self, usePrimes=False):
		my_dh_keyid = self.dh_keys.get_my_cur_keyid()
		their_dh_keyid = self.dh_keys.get_their_cur_keyid()
		if usePrimes:
			m1PrimeKey = self.dh_keys.m1prime
		else:
			m1PrimeKey = self.dh_keys.m1
			
		# Compute the 32-byte value MA to be the SHA256-HMAC of the following data, using the key m1':
		mbytes = []
		# gy (MPI)
		mbytes.extend( self.dh_keys.their_public_factor_to_mpi(their_dh_keyid) )
		# gx (MPI)
		mbytes.extend( self.dh_keys.my_public_factor_to_mpi(my_dh_keyid) )
		# pubA (PUBKEY)
		mbytes.extend( OtrDSA.format_key(self.dsa_keys.their_public_key) )
		# keyidA (INT)
		keyid = _OT.zero_pad(_OT.int_to_bytes(their_dh_keyid), 4)
		mbytes.extend( keyid )
		self.their_M = OtrCrypt.get_sha256_hmac(m1PrimeKey, mbytes)

	def check_their_sig(self, enc_sig, sig_mac, usePrimes=False):
		my_dh_key = self.dh_keys.get_my_cur_keyid()
		if usePrimes:
			cKey = self.dh_keys.cprime
			m1Key = self.dh_keys.m1prime
			m2Key = self.dh_keys.m2prime
		else:
			cKey = self.dh_keys.c
			m1Key = self.dh_keys.m1
			m2Key = self.dh_keys.m2
		
		sig = OtrCrypt.aes_zero_ctr_crypt(cKey, enc_sig)
		#print sig
		
		byte_reader = ByteStreamReader(sig)
		
		their_dsa_key = byte_reader.get_pubkey()
		if their_dsa_key["cipher_code"] != list(OtrConstants["dsa_code_bytes"]):
			return False
		
		# now keyid
		their_dh_keyid = _OT.bytes_to_int(byte_reader.get_int())
		self.dh_keys.associate_their_keyid(their_dh_keyid)
		
		# load their DSA public key - (y,g,p,q)
		their_dsa_key_tup = (
			_OT.mpi_to_int(their_dsa_key["y_mpi"]),
			_OT.mpi_to_int(their_dsa_key["g_mpi"]),
			_OT.mpi_to_int(their_dsa_key["p_mpi"]),
			_OT.mpi_to_int(their_dsa_key["q_mpi"])
		)
		self.dsa_keys.load_their_key(their_dsa_key_tup)
		
		# compute their M factor
		self.compute_their_M_factor(usePrimes=usePrimes)
		
		# now load their signed M factor
		q_len = their_dsa_key["q_len"]
		M_sig_r_factor = _OT.bytes_to_int(byte_reader.get_n_bytes(q_len))
		M_sig_s_factor = _OT.bytes_to_int(byte_reader.get_n_bytes(q_len))
		
		assert (byte_reader.consumed_all())
	
		if not OtrDSA.verify(self.dsa_keys.their_public_key, self.their_M, 
								M_sig_r_factor, M_sig_s_factor):
			logging.debug("DID NOT VERIFY")
			return False
		
		# now check their MAC
		calc_sig_mac = OtrCrypt.get_sha256_hmac_160(m2Key, _OT.bytes_to_data(enc_sig))
		if calc_sig_mac != sig_mac:
			logging.debug( "MAC INCORRECT" )
			#print enc_sig
			#print calc_sig_mac
			#print sig_mac
			return False
		
		# alright, looks like everything checks out 
		return True
