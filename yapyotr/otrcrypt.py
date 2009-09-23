# Part of yapyotr - copyright 2009 Eric Conlon
# Licensed under the GPLv3
# ejconlon@gmail.com | http://it.fuelsyourcyb.org

import logging
from otrtypes import OtrTypes as _OT
from Crypto.Hash import SHA256, SHA
from Crypto.Hash import HMAC
from Crypto.Cipher import AES
from Crypto.PublicKey import DSA
from Crypto.Util.randpool import RandomPool

class OtrCrypt:
	# makes somewhere between minlen and maxlen (inclusive) random bytes
	class aes_counter:
		def __init__(self, start = 0):
			if type(start) == type(0): # initialize it w/ an int
				self.count = _OT.bytes_to_int(_OT.int_to_bytes(start)+[0]*8)
			else: # or initialize it with the top half of the ctr array
				self.count = _OT.bytes_to_int(start+[0]*8)
	
		def __call__(self):
			c = _OT.int_to_bytes(self.count)
			self.count += 1
			return _OT.bytes_to_string(_OT.zero_pad(c, 16))
	
	# AES128-CTR - handles arbitrary length data, key must be 128 bits
	# it is its own inverse (XOR)
	@staticmethod
	def aes_ctr_crypt(key, data_orig, ctr_val):
		data = [x for x in data_orig]
		AESr = AES.new(_OT.bytes_to_cbytes(key), AES.MODE_CTR, counter=OtrCrypt.aes_counter(ctr_val))
		# need to fill to a multiple of 16; since it is in 
		# counter mode, we can just ignore the end of the encrypted output
		fill_len = (16 - (len(data) % 16)) % 16
		data.extend([0]*fill_len)
		# do the encryption
		enc_str = AESr.encrypt(_OT.bytes_to_cbytes(data))
		return _OT.string_to_bytes(enc_str[:-fill_len])
		
	@staticmethod
	def aes_zero_ctr_crypt(key, data_orig):
		return OtrCrypt.aes_ctr_crypt(key, data_orig, ctr_val=0)
		
	@staticmethod
	def get_sha256_hmac(key, data):
		return _OT.string_to_bytes(HMAC.new(_OT.bytes_to_string(key), _OT.bytes_to_string(data), SHA256).digest())
		
	@staticmethod
	def get_sha256_hmac_160(key, data):
		return OtrCrypt.get_sha256_hmac(key, data)[0:0+20]

	@staticmethod
	def get_sha256_bytes(data):
		return _OT.string_to_bytes(SHA256.new(_OT.bytes_to_string(data)).digest())
		
	@staticmethod
	def get_sha1_hmac(key, data):
		return _OT.string_to_bytes(HMAC.new(_OT.bytes_to_string(key), _OT.bytes_to_string(data), SHA).digest())
		
	@staticmethod
	def get_sha1_hmac_160(key, data):
		return OtrCrypt.get_sha1_hmac(key, data)[0:0+20]
		
	@staticmethod
	def get_sha1_bytes(data):
		return _OT.string_to_bytes(SHA.new(_OT.bytes_to_string(data)).digest())
		
	@staticmethod
	def h1(b, secbytes):
		return OtrCrypt.get_sha1_bytes([b] + secbytes)[0:0+20]
		
	@staticmethod
	def h2(b, secbytes):
		return OtrCrypt.get_sha256_bytes([b] + secbytes)

