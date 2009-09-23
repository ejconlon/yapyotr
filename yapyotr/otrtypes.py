# Part of yapyotr - copyright 2009 Eric Conlon
# Licensed under the GPLv3
# ejconlon@gmail.com | http://it.fuelsyourcyb.org

import random, array, ctypes

# aka _OT - a namespace for the some-dozen type 
# conversion and validation routines.
# 
# int - python int
# bytes - python array of ints, each in the range [0, 255] (inclusive)
# cbytes - wrapped c-array of bytes
# mpi - multiple precision integer, a byte-formatted int with prepended four-byte length
# data - bytes with prepended four-byte length
# string - string of bytes, since we are using utf-8 (CHECK YOUR LOCALE!) we use
#				chr and ord to convert to and from
# hex - string of hex characters, usually w/o the '0x' prepended
# mac - SHA256-HMAC-160 - first 20 bytes of a SHA256-HMAC
#
# short, byte not included here; anywhere they are used they are converted explicitly
#
class OtrTypes:
	@staticmethod
	def int_to_bytes(num):
		#print "i2ba", num, hex(num)
		s = hex(num)[2:]
		if s[-1] == 'L': s = s[:-1]
		#print s, s[0:1]
		if len(s) % 2 != 0:
			s = '0'+s
		a = [int(s[2*i:2*i+2],16) for i in xrange(len(s)/2)]
		#print a
		return a
	
	@staticmethod
	def hex_to_bytes(s):
		if s[:2] == '0x':
			s = s[2:]
		if s[-1] == 'L': s = s[:-1]
		if len(s) % 2 != 0:
			s = '0'+s
		a = [int(s[2*i:2*i+2], 16) for i in xrange(len(s)/2)]
		return a
	
	@staticmethod
	def bytes_to_hex(a):
		#print "BA2HS: "+str(a)
		t = [hex(n)[2:] for n in a]
		for i in xrange(len(t)):
			if len(t[i]) == 1:
				t[i] = '0'+t[i]
		return "".join(t)
	
	@staticmethod
	def bytes_to_int(a):
		return int(OtrTypes.bytes_to_hex(a), 16)

	@staticmethod
	def bytes_to_cbytes(a):
		return array.array('B', a)
	
	@staticmethod
	def bytes_to_string(a):
		return "".join( (chr(x) for x in a) )
	
	@staticmethod
	def string_to_bytes(a):
		return [ord(c) for c in a]

	@staticmethod
	def int_to_mpi(num):
		# 4 byte unsigned len, big-endian 
		# len byte unsigned value, big-endian 
		# (MPIs must use the minimum-length encoding; i.e. no leading 0x00 bytes. 
		# This is important when calculating public key fingerprints.)
		#print num
		value_array = OtrTypes.int_to_bytes(num)
		len_array = OtrTypes.int_to_bytes(len(value_array))
		len_array = [0]*(4-len(len_array))+len_array
		return len_array+value_array

	@staticmethod
	def bytes_to_data(value_array):
		#value_array = [x for x in a]
		len_array = OtrTypes.int_to_bytes(len(value_array))
		len_array = [0]*(4-len(len_array))+len_array
		return len_array+value_array

	@staticmethod
	def mpi_to_bytes(m):
		return m[4:]
	
	@staticmethod
	def data_to_bytes(d):
		return d[4:]

	@staticmethod
	def mpi_to_int(m):
		return OtrTypes.bytes_to_int(OtrTypes.mpi_to_bytes(m))

	# validation routines below
	@staticmethod
	def check_mpi(a):
		len_array = a[0:0+4]
		value_array = a[4:]
		if value_array[0] == 0:
			return False # no leading zeros allowed!
		l = int(OtrTypes.bytes_to_hex(len_array), 16)
		if len(value_array) != l:
			return False
		return True
	
	# leading zeros in the value array are allowed!
	@staticmethod
	def check_data(a): 
		len_array = a[0:0+4]
		value_array = a[4:]
		l = int(OtrTypes.bytes_to_hex(len_array), 16)
		if len(value_array) != l:
			return False
		return True
		
	@staticmethod
	def check_mac(a):
		#print "CHECK_MAC: ", a
		if len(a) != 20:
			return False
		for x in a:
			if type(x) != type(0):
				return False
		return True
		
	@staticmethod
	def make_random_bytes(minlen, maxlen=None):
		random.seed()
		if maxlen:
			n = random.randint(minlen, maxlen)
		else:
			n = minlen
		randBytes = [random.randint(0, 255) for x in xrange(n)]
		#print "x", randBytes
		#r = raw_input()
		return randBytes
		
	@staticmethod
	def zero_pad(a, n):
		pad_len = n-len(a)
		if pad_len > 0:
			return [0]*pad_len + a
		else:
			return a

# Shorthand, you can search and replace if you dont like it
_OT = OtrTypes
