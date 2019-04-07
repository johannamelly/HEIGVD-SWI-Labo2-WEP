#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
import binascii
import rc4

#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

# setting plain text with 36 chars
quotation = "How strange that all you have to do sometimes to meet somebody is walk up to their house and ring a doorbell, and magically they appear as if from nowhere."

fragments = [quotation[0:36],  quotation[36:72], quotation[72:108]]


arps = []
for index in range(0, len(fragments)):
	arp = rdpcap('arp.cap')[0]
	##1. compute ICV of fragment
	icv = binascii.crc32(fragments[index]) 
	icv = struct.pack("<i", icv)
	
	##2. seed -> (RC4) = keystream
	##3. keystream XOR (fragment + ICV) = cipher
	cipher= rc4.rc4crypt(fragments[index] + icv, arp.iv+key)
	
	##4. add fields
	arp.wepdata = cipher[:-4]
	(arp.icv,) = struct.unpack("!L", cipher[-4:])
	# setting fragment counter
	arp.SC = index
	# if last fragment, no more fragments after
	if(index != len(fragments)-1):
		# setting more fragments flag to 1
		arp.FCfield = arp.FCfield | 0x04
	arps.append(arp)
###5. forge cap file
wrpcap("fragmentsForged.cap", arps)

