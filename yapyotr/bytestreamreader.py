# Part of yapyotr - copyright 2009 Eric Conlon
# Licensed under the GPLv3
# ejconlon@gmail.com | http://it.fuelsyourcyb.org

from otrtypes import OtrTypes as _OT

class ByteStreamReader:
	def __init__(self, bytes):
		self.bytes = bytes
		self.offset = 0
		
	def get_n_bytes(self, n):
		assert(self.offset + n <= len(self.bytes))
		next = self.bytes[self.offset:self.offset+n]
		self.offset += n
		return next
		
	def get_byte(self):
		return self.get_n_bytes(1)
		
	def get_short(self):
		return self.get_n_bytes(2)
		
	def get_int(self):
		return self.get_n_bytes(4)
		
	def get_data(self):
		len_array = self.get_n_bytes(4)
		length = _OT.bytes_to_int(len_array)
		value_array = self.get_n_bytes(length)
		return len_array+value_array
				
	def get_mpi(self):
		return self.get_data()
		
	def get_mac(self):
		return self.get_n_bytes(20)
	
	def get_ctr(self):
		return self.get_n_bytes(8)
		
	def get_tlv(self):
		tlv_type = _OT.bytes_to_int(self.get_short())
		tlv_len = _OT.bytes_to_int(self.get_short())
		value = []
		if tlv_len > 0:
			value.extend(self.get_n_bytes(tlv_len))
		return {'type': tlv_type, 'length': tlv_len, 'value': value}
	
	def get_pubkey(self):
		cipher_code = self.get_n_bytes(2)
		
		# public key now, p, q, g, y
		# p,q,g,y
		p = self.get_mpi()
		q = self.get_mpi()
		g = self.get_mpi()
		y = self.get_mpi()
		
		return {"p_mpi": p, "q_mpi": q, "g_mpi": g, "y_mpi": y, 
			"q_len": len(q)-4, "cipher_code": cipher_code}
	
	def consumed_all(self):
		return self.offset == len(self.bytes)
	
	format_funcs = {
		"byte" : get_byte,
		"short" : get_short,
		"int" : get_int,
		"data" : get_data,
		"mpi" : get_mpi,
		"mac" : get_mac,
		"pubkey" : get_pubkey,
		"ctr" : get_ctr,
		"tlv": get_tlv
	}
				
	def parse_format(self, format):
		return dict( ( (pair[0], self.format_funcs[pair[1]](self)) for pair in format ) )
