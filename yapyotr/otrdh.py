# Part of yapyotr - copyright 2009 Eric Conlon
# Licensed under the GPLv3
# ejconlon@gmail.com | http://it.fuelsyourcyb.org

import logging
from otrtypes import OtrTypes as _OT
from otrreplay import OtrReplay
from otrcrypt import OtrCrypt
from otrvars import memo

class OtrDH:
	# this is the modulus of the group we do DH with
	dh_mod = int (
	"""FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
	   29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
	   EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
	   E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
	   EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
	   C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
	   83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
	   670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF""".replace(' ','').replace('\n','').replace('\t',''), 16)

	# this is the generator we do DH with
	dh_g = 2

	def __init__(self, replay=OtrReplay()):
		self.replay = replay
		self.authing = True
		self.my_cur_keyid = -1
		self.their_public_factor_temp = None
		self.my_public_factors = {}
		self.my_key_has_been_used = {}
		self.my_private_keys = {}
		self.their_public_factors = {}
		self.my_most_recently_seen = []
		self.their_most_recently_seen = []
		self.r_secret = None
		self.enc_gxmpi = None
		self.hash_gxmpi = None
		self.ssid = None
		self.c = None
		self.cprime = None
		self.m1 = None
		self.m1prime = None
		self.m2 = None
		self.m2prime = None
		self.end = None
		self.sendbyte = None
		self.recvbyte = None
		self.send_aes_key = None
		self.send_mac_key = None
		self.recv_aes_key = None
		self.recv_mac_key = None
		self.ctr = None
		self.my_sess_keyid = None
		self.their_sess_keyid = None
		self.old_ctr_vals = {}
		self.old_mac_keys = []
		
		# make 2 keys to start out with
		self.make_new_key()
		self.make_new_key()
		
	def reset_session(self):
		self.r_secret = None
		self.enc_gxmpi = None
		self.hash_gxmpi = None
		self.ssid = None
		self.c = None
		self.cprime = None
		self.m1 = None
		self.m1prime = None
		self.m2 = None
		self.m2prime = None
		self.end = None
		self.sendbyte = None
		self.recvbyte = None
		self.send_aes_key = None
		self.send_mac_key = None
		self.recv_aes_key = None
		self.recv_mac_key = None
		self.ctr = None
		self.my_sess_keyid = None
		self.their_sess_keyid = None
		self.old_mac_keys = []
		
	def make_new_key(self, add_as_seen=False):
		# RCHANGE
		if self.my_cur_keyid==0 and self.replay.can_replay('private_dh_key'):
			x = _OT.int_to_bytes(self.replay.data['private_dh_key'])
		else:
			#r = raw_input("random x")
			x = _OT.make_random_bytes(320/8) # Byte range?
		
		new_keyid = self.my_cur_keyid + 1
		logging.debug( "making new key %d" % new_keyid)
		x_int = _OT.bytes_to_int(x)
		new_factor = pow(self.dh_g, x_int, self.dh_mod)
		
		self.my_private_keys[new_keyid] = x_int
		self.my_public_factors[new_keyid] = new_factor
		self.my_key_has_been_used[new_keyid] = False
		self.my_cur_keyid = new_keyid
		if add_as_seen:
			self.my_most_recently_seen.append(new_keyid)
		#r=raw_input()
		
		# RCHANGE
		if self.authing and self.my_cur_keyid==1: self.replay.check('public_dh_factor', self.my_public_factors[1])
	
	def get_my_cur_keyid(self):
		return self.my_cur_keyid
	def get_their_cur_keyid(self):
		return self.their_cur_keyid
	def mark_my_key_as_used(self, keyid):
		self.my_key_has_been_used[keyid] = True
		self.my_most_recently_seen.append(keyid)
	def mark_their_key_as_used(self, keyid):
		self.their_most_recently_seen.append(keyid)
	def get_my_most_recently_seen_keyid(self):
		return self.my_most_recently_seen[-1]
	def get_their_most_recently_seen_keyid(self):
		return self.their_most_recently_seen[-1]
	
	def make_shared_key(self, my_keyid=None, their_keyid=None):
		if not (my_keyid is None):
			my_secret_key = self.my_private_keys[my_keyid]
		else:
			my_secret_key = self.my_private_keys[self.my_cur_keyid]
		if not (their_keyid is None):
			their_public_factor = self.their_public_factors[their_keyid]
		else:
			their_public_factor = self.their_public_factor_temp
		shared_key = pow(their_public_factor, my_secret_key, self.dh_mod)
		return shared_key
	
	def store_their_public_factor(self, their_public_factor):
		self.their_public_factor_temp = their_public_factor
		self.their_cur_keyid = None
		# RCHANGE
		if self.authing and self.my_cur_keyid==1: 
			our_secret_key = pow(their_public_factor, self.my_private_keys[1], self.dh_mod)
			self.replay.check('s', _OT.int_to_bytes(our_secret_key))
	
	def associate_their_keyid(self, their_keyid, their_public_factor=None):
		logging.debug( ("NEW KEYID", their_keyid))
		if their_public_factor:
			self.their_public_factor_temp = their_public_factor
		self.their_public_factors[their_keyid] = self.their_public_factor_temp
		self.their_most_recently_seen.append(their_keyid)
		self.their_cur_keyid = their_keyid
		logging.debug((self.their_most_recently_seen, self.their_cur_keyid))
		#r = raw_input()
	
	# shorthand
	def my_public_factor_to_mpi(self, keyid=None):
		if not (keyid is None):
			return _OT.int_to_mpi(self.my_public_factors[keyid])
		else:
			return _OT.int_to_mpi(self.my_public_factors[self.my_cur_keyid])
	
	def their_public_factor_to_mpi(self, keyid=None):
		if not (keyid is None):
			return _OT.int_to_mpi(self.their_public_factors[keyid])
		else:
			return _OT.int_to_mpi(self.their_public_factor_temp)
			
	def our_shared_key_to_mpi(self, my_keyid, their_keyid=None):
		return _OT.int_to_mpi(self.make_shared_key(my_keyid, their_keyid))

	def generate_r_secret(self):
		# RCHANGE
		if self.my_cur_keyid==1 and self.replay.can_replay('r'):
			self.r_secret = self.replay.data['r']
		else:
			self.r_secret = _OT.make_random_bytes(128/8)

	def encrypt_my_public_factor_mpi(self, my_keyid=None):
		enc_gxmpi = OtrCrypt.aes_zero_ctr_crypt(self.r_secret, self.my_public_factor_to_mpi(my_keyid))
		# RCHANGE
		if self.authing: self.replay.check('enc_dh_factor', enc_gxmpi)
		enc_gxmpi_data = _OT.bytes_to_data(enc_gxmpi)
		return enc_gxmpi_data
		
	def hash_my_public_factor_mpi(self, my_keyid=None):
		hash_gxmpi = OtrCrypt.get_sha256_bytes(self.my_public_factor_to_mpi(my_keyid))
		# RCHANGE
		if self.authing: self.replay.check('hash_dh_factor', hash_gxmpi)
		hash_gxmpi_data = _OT.bytes_to_data(hash_gxmpi)
		return hash_gxmpi_data
	
	def store_their_commitment(self, enc_gxmpi, hash_gxmpi):
		self.enc_gxmpi = enc_gxmpi
		self.hash_gxmpi = hash_gxmpi
	
	def get_r_secret(self):
		return _OT.bytes_to_data(self.r_secret)

	def decrypt_their_public_factor(self, r_secret):
		self.r_secret = r_secret
		their_public_factor_mpi = \
			OtrCrypt.aes_zero_ctr_crypt(r_secret, self.enc_gxmpi)
		calculated_hash = OtrCrypt.get_sha256_bytes(their_public_factor_mpi)
		if calculated_hash == self.hash_gxmpi:
			self.store_their_public_factor(_OT.mpi_to_int(their_public_factor_mpi))
			return True
		else:
			return False
			
	def compute_c_and_m_factors(self, my_keyid=None, their_keyid=None):
		#Write the value of s as a minimum-length MPI, as specified above
		# (4-byte big-endian len, len-byte big-endian value). 
		# Let this (4+len)-byte value be "secbytes".
		self.secbytes = _OT.int_to_mpi(self.make_shared_key(my_keyid, their_keyid))
		
		#For a given byte b, define h2(b) to be the 256-bit output of the SHA256 hash of the 
		# (5+len) bytes consisting of the byte b, followed by secbytes.
		
		#Let ssid be the first 64 bits of h2(0x00).
		self.ssid = OtrCrypt.h2(0x00, self.secbytes)[0:0+8]
		#Let c be the first 128 bits of h2(0x01), and let c' be the second 128 bits of h2(0x01).
		t = OtrCrypt.h2(0x01, self.secbytes)
		
		self.c = t[0:0+16]
		if self.authing: self.replay.check('c', self.c)
		
		self.cprime = t[16:16+16]
		if self.authing: self.replay.check('cp', self.cprime)
		
		#Let m1 be h2(0x02).
		self.m1 = OtrCrypt.h2(0x02, self.secbytes)
		if self.authing: self.replay.check('m1', self.m1)
		
		#Let m2 be h2(0x03).
		self.m2 = OtrCrypt.h2(0x03, self.secbytes)
		if self.authing: self.replay.check('m2', self.m2)
		
		#Let m1' be h2(0x04).
		self.m1prime = OtrCrypt.h2(0x04, self.secbytes)
		if self.authing: self.replay.check('m1p', self.m1prime)
		
		#Let m2' be h2(0x05).
		self.m2prime = OtrCrypt.h2(0x05, self.secbytes)
		if self.authing: self.replay.check('m2p', self.m2prime)

	def get_ssid_str(self):
		return "".join(_OT.bytes_to_hex(self.ssid[0:8])) + " " + "".join(_OT.bytes_to_hex(self.ssid[8:16]))
	
	def compute_ek_and_mk_factors(self, my_keyid, their_keyid):
		my_public_key = self.my_public_factors[my_keyid]
		their_public_key = self.their_public_factors[their_keyid]
		#self.compute_c_and_m_factors(my_keyid, their_keyid)
		if my_public_key > their_public_key:
			self.end = "high"
			self.sendbyte = 0x01
			self.recvbyte = 0x02
		else:
			self.end = "low"
			self.sendbyte = 0x02
			self.recvbyte = 0x01
		self.send_aes_key = OtrCrypt.h1(self.sendbyte, self.secbytes)[0:16]
		self.send_mac_key = OtrCrypt.get_sha1_bytes(self.send_aes_key)[0:20]
		self.recv_aes_key = OtrCrypt.h1(self.recvbyte, self.secbytes)[0:16]
		self.recv_mac_key = OtrCrypt.get_sha1_bytes(self.recv_aes_key)[0:20]
		
	def generate_next_counter(self, my_keyid, their_keyid):
		k = (my_keyid, their_keyid)
		if k in self.old_ctr_vals:
			self.ctr = self.old_ctr_vals[k]+1
		else:
			self.ctr = 1
		self.old_ctr_vals[k] = self.ctr
		
	def update_next_counter(self, my_keyid, their_keyid, counter):
		k = (my_keyid, their_keyid)
		self.ctr = counter
		self.old_ctr_vals[k] = counter
		
	def prepare_session_to_send(self):
		# prepare everything to send
		self.my_sess_keyid = self.get_my_most_recently_seen_keyid()
		self.their_sess_keyid = self.get_their_most_recently_seen_keyid()
		#print "USING1", self.my_sess_keyid, self.my_public_factor_to_mpi(self.my_sess_keyid)
		logging.debug( "?= %d %d" % (self.my_sess_keyid, self.my_cur_keyid) )
		#r = raw_input()
		if self.my_sess_keyid == self.my_cur_keyid:
			self.make_new_key(add_as_seen=True) # increments self.my_cur_keyid
		#print "USING2", self.my_sess_keyid, self.my_public_factor_to_mpi(self.my_sess_keyid)
		#r = raw_input()
		self.next_dh = self.my_public_factors[self.my_cur_keyid]
		self.compute_c_and_m_factors(self.my_sess_keyid, self.their_sess_keyid)
		self.compute_ek_and_mk_factors(self.my_sess_keyid, self.their_sess_keyid)
		self.generate_next_counter(self.my_sess_keyid, self.their_sess_keyid)
		
	def receive_data_message(self, msg):
		#global memo
		self.my_sess_keyid = _OT.bytes_to_int(msg.recipient_keyid)
		self.their_sess_keyid = _OT.bytes_to_int(msg.sender_keyid)
		logging.debug( "KEYIDS %d %d " % (self.my_sess_keyid, self.their_sess_keyid))
		if len(msg.next_dh) > 4:
			logging.debug( "GOT NEXT DH" )
			logging.debug( msg.next_dh )
			self.associate_their_keyid(self.their_sess_keyid+1, _OT.mpi_to_int(msg.next_dh))
		self.update_next_counter(self.my_sess_keyid, self.their_sess_keyid, _OT.bytes_to_int(msg.counter))
		logging.debug( (msg.counter, _OT.int_to_bytes(self.ctr)) )
		self.compute_c_and_m_factors(self.my_sess_keyid, self.their_sess_keyid)
		self.compute_ek_and_mk_factors(self.my_sess_keyid, self.their_sess_keyid)
	
		#assert memo.sender_keyid == msg.sender_keyid
		#assert memo.recipient_keyid == msg.recipient_keyid
		#assert memo.next_dh == msg.next_dh
		#assert memo.counter == msg.counter
		#assert memo.enc_msg == _OT.data_to_bytes(msg.enc_msg)
		
		T = [0,2,3, msg.flags[0]] # protocol version and type code 
		# my_keyid
		T.extend( msg.sender_keyid )
		# their_keyid
		T.extend( msg.recipient_keyid )
		# next_dh
		T.extend( msg.next_dh )
		# ctr
		T.extend( msg.counter )
		# enc_msg
		logging.debug(("ENC DATA: ", msg.enc_msg))
		T.extend( msg.enc_msg )
		
		#assert memo.T == T
		#print memo.sender_factor
		
		#print "RECVER"
		#for x in sorted(self.their_public_factors.keys()):
		#	print (x, self.their_public_factor_to_mpi(x)) 
		#r = raw_input()
		
		#assert memo.sender_factor == self.their_public_factor_to_mpi(self.their_sess_keyid)
		#assert memo.recipient_factor == self.my_public_factor_to_mpi(self.my_sess_keyid)
		#assert memo.secbytes == self.secbytes
		# compute MAC_mk(T)
		auth_check = OtrCrypt.get_sha1_hmac(self.recv_mac_key, T)
		
		if auth_check != msg.authenticator:
			logging.debug( ("got: ", auth_check) )
			logging.debug( ("exp: ", msg.authenticator) )
			#print self.recv_mac_key, self.send_mac_key
			#print memo.send_mac_key
			raise Exception("mac fail")
		
		return OtrCrypt.aes_ctr_crypt(self.recv_aes_key, _OT.data_to_bytes(msg.enc_msg), msg.counter)
		
		
	def encrypt_data_message(self, msg):
		#global memo
		# encrypt the message
		counter = _OT.zero_pad(_OT.int_to_bytes(self.ctr), 8)
		enc_msg = OtrCrypt.aes_ctr_crypt(self.send_aes_key, msg, self.ctr)
		
		memo.enc_msg = enc_msg
		
		flags = [0x00]
		
		#memo.flags = flags
		
		# generate T = (my_keyid, their_keyid, next_dh, ctr, AES-CTR_ek,ctr(msg))
		T = [0,2,3, flags[0]] # protocol version and msg code
		# my_keyid
		sender_keyid = _OT.zero_pad(_OT.int_to_bytes(self.my_sess_keyid), 4)
		#memo.sender_keyid = sender_keyid
		T.extend( sender_keyid )
		# their_keyid
		recipient_keyid = _OT.zero_pad(_OT.int_to_bytes(self.their_sess_keyid), 4)
		#memo.recipient_keyid = recipient_keyid
		T.extend( recipient_keyid )
		# next_dh
		next_dh = _OT.int_to_mpi(self.next_dh)
		#memo.next_dh = next_dh
		T.extend( next_dh )
		# ctr
		#memo.counter = counter
		T.extend( counter )
		# enc_msg
		T.extend( _OT.bytes_to_data(enc_msg) )
		
		#memo.T = T
		
		# compute MAC_mk(T)
		authenticator = OtrCrypt.get_sha1_hmac(self.send_mac_key, T)
		
		#memo.authenticator = authenticator
		#memo.old_mac_keys = self.old_mac_keys
		
		#memo.send_mac_key = self.send_mac_key
		#memo.recv_mac_key = self.recv_mac_key
		#memo.send_aes_key = self.send_aes_key
		#memo.recv_aes_key = self.recv_aes_key
		
		#memo.secbytes = self.secbytes
		#memo.sender_factor = self.my_public_factor_to_mpi(self.my_sess_keyid)
		
		#print "SENDER"
		#for x in sorted(self.my_public_factors.keys()):
		#	print (x, self.my_public_factor_to_mpi(x)) 
		#r = raw_input()
		
		#memo.recipient_factor = self.their_public_factor_to_mpi(self.their_sess_keyid)
		return (flags, sender_keyid, recipient_keyid, next_dh, counter,
			_OT.bytes_to_data(enc_msg), authenticator, _OT.bytes_to_data(self.old_mac_keys))
