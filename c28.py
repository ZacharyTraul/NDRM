import re

class c28:
	'''
	A class of functions defined under the FT8 protocol for certain message fragments to the c28 bit field.
	'''
	NTOKENS = 2063592				#Number of possible tokens
	MAX22 = 4194304					#Number of possible 22-bit hashes
	A1 = " 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"	#Various alphabets used in the
	A2 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"	#token_to_c28 function
	A3 = "0123456789"
	A4 = " ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	NPRIME = 47055833459				#Prime used in callsign_to_hash_c28 function

	def token_to_c28(self, t):
		#Special tokens DE, QRZ, and CQ map to 0, 1, and 2 respectively
		#Special CQ's map to following ranges
		#CQ000 - CQ999	: 3 - 1002
		#CQA - CQZ	: 1004 - 1029
		#CQAA - CQZZ	: 1031 - 1731
		#CQAAA - CQZZZ	: 1760 - 20685
		#CQAAAA - CQZZZZ: 21443 - 532443
		#Note: they do not entirely fill their ranges.

		t = t.upper()
		if t == "DE":
			return 0
		if t == "QRZ":
			return 1
		if t[0:2] == "CQ" and len(t) <= 6:
			if len(t) == 2:
				return 2
			if re.search("[0-9][0-9][0-9]", t):
				return 3 + int(t[2:5])
			if re.search("[0-9]", t):
				raise Exception("Token not in proper format")
			t = t[2:len(t)]
			c28 = 1003
			for i in range(len(t)):
				c28 += 26**i * (ord(t[-(i+1)]) - 65) + 27**i
			return c28
		raise Exception("Token not in proper format")

	def standard_call_to_c28(self, cs):
		if len(cs) > 6 or re.search(r"[^0-9A-Z]", cs):
			raise Exception(f"Callsign '{cs}' is not a standard callsign.")
		#Make upper case and pad length to 6 characters if not already.
		cs = cs.upper()
		cs = cs.rjust(6)
		#Encode the callsign using a mixed-radix system.
		N28 =  self.A1.find(cs[0]) *36*10*27*27*27
		N28 += self.A2.find(cs[1]) *10*27*27*27
		N28 += self.A3.find(cs[2]) *27*27*27
		N28 += self.A4.find(cs[3]) *27*27
		N28 += self.A4.find(cs[4]) *27
		N28 += self.A4.find(cs[5])
		#Offset N28 to avoid overlap with tokens and hashes.
		N28 += self.NTOKENS + self.MAX22
		return N28

	def callsign_to_hash_c28(self, cs):
		if len(cs) > 11:
			raise Exception("Callsign is longer than 11 characters.")
		#Make upper case and pad length to 11 characters if not already.
		cs = cs.upper()
		cs = cs.ljust(11)
		#Augment A1 with "/" since it may be present in certain callsigns.
		A = self.A1 + "/"
		#Hashing algorithm
		ih22 = 0
		for i in range(11):
			ih22 = 38 * ih22 + A.find(cs[i])
		#Bit-shift ih22 in order to be 22 bits.
		ih22 = (self.NPRIME * ih22) % (2**64) >> (64-22)
		#Offset ih22 to avoid overlap with tokens.
		ih22_biased = ih22 + self.NTOKENS
		return ih22_biased
