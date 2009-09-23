# Part of yapyotr - copyright 2009 Eric Conlon
# Licensed under the GPLv3
# ejconlon@gmail.com | http://it.fuelsyourcyb.org

import logging, random
from otrtypes import OtrTypes as _OT
from otrreplay import OtrReplay
from otrcrypt import OtrCrypt, DSA, RandomPool
from otrvars import *
		
class OtrDSA:
	# this is the length of the DSA key to generate if we done have one
	dsa_len = 512 # This is def. not long enough; 2048 or more is needed
	
	def __init__(self, replay=OtrReplay()):
		self.my_private_key = None
		self.my_public_key = None
		self.their_public_key = None
		self.my_q_len = None
		self.their_q_len = None
		self.replay = replay

	@staticmethod
	def calc_q_len(key):
		return len( _OT.int_to_bytes(key.q) )
		
	def load_my_key(self, tup=None):
		if self.replay.can_replay('dsa_private_key') and self.replay.can_replay('dsa_public_key'):
			self.my_private_key = self.replay.load_dsa_key()
		else:
			if tup is None:
				self.my_private_key = OtrDSA.make_key()
			else:
				self.my_private_key = DSA.construct(tup)
		self.my_public_key = self.my_private_key.publickey()
		self.my_q_len = OtrDSA.calc_q_len(self.my_private_key)
		
	def load_their_key(self, tup):
		self.their_public_key = DSA.construct(tup)
		self.their_q_len = OtrDSA.calc_q_len(self.their_public_key)

	@staticmethod
	def make_key():
		rp = RandomPool()
		return DSA.generate(OtrDSA.dsa_len, rp.get_bytes)
		
	def sign(self, data):
		if self.replay.can_replay('k'):
			k = self.replay.data['k']
		else:
			k = random.SystemRandom().randint(2, self.my_private_key.q-1)
		r, s = self.my_private_key.sign(_OT.bytes_to_string(data), k)
		ra = _OT.zero_pad(_OT.int_to_bytes(r), self.my_q_len)
		sa = _OT.zero_pad(_OT.int_to_bytes(s), self.my_q_len)
		return ra + sa
		
	@staticmethod
	def verify(key, data, r, s):
		return key.verify(_OT.bytes_to_string(data), (r,s))
		
	@staticmethod
	def format_key(key):
		bytes = list(OtrConstants["dsa_code_bytes"])
		bytes.extend( _OT.int_to_mpi(key.p) )
		bytes.extend( _OT.int_to_mpi(key.q) )
		bytes.extend( _OT.int_to_mpi(key.g) )
		bytes.extend( _OT.int_to_mpi(key.y) )
		return bytes
