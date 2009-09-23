# Part of yapyotr - copyright 2009 Eric Conlon
# Licensed under the GPLv3
# ejconlon@gmail.com | http://it.fuelsyourcyb.org

import logging
from bytestreamreader import ByteStreamReader
from otrtypes import OtrTypes as _OT
from otrcrypt import DSA

class OtrReplay:
	one_sided_keys = set(
		["private_dh_key", "public_dh_factor", "dsa_public_key", "dsa_private_key", "keyid"]
	)

	def __init__(self, data=None, do_both_sides=True):
		self.data = data
		self.do_both_sides = do_both_sides
		self.enabled = not (data is None)
		
	def assert_equal(self, key, calc_val):
		if calc_val != self.data[key]:
			raise Exception("ASSERT EQUAL FAIL: "+key+":\n calc:  %s\n replay: %s" % (str(calc_val), str(self.data[key])))
		else:
			logging.debug( "*** ASSERT EQUAL success: "+key+":\n %s" % str(calc_val) )

	def can_replay(self, key):
		if self.enabled and key in self.data.keys():
			if not self.do_both_sides and key not in self.one_sided_keys:
				return False
			else:
				return True
		else:
			return False
			
	def check(self, key, calc_val):
		if self.can_replay(key):
			self.assert_equal(key, calc_val)

	def load_dsa_key(self):
		assert self.can_replay('dsa_public_key')
		assert self.can_replay('dsa_private_key')
		key = self.data['dsa_public_key']
		priv_key = self.data['dsa_private_key']
		
		key_reader = ByteStreamReader(key)
		
		p = _OT.mpi_to_int(key_reader.get_mpi())
		q = _OT.mpi_to_int(key_reader.get_mpi())
		g = _OT.mpi_to_int(key_reader.get_mpi())
		y = _OT.mpi_to_int(key_reader.get_mpi())
		
		assert (key_reader.consumed_all())
		
		priv_key_reader = ByteStreamReader(priv_key)
		
		x = _OT.mpi_to_int(priv_key_reader.get_mpi())
				
		assert (priv_key_reader.consumed_all())
		
		return DSA.construct((y,g,p,q,x))
