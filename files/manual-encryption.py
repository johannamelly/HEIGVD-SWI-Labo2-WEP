#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
import binascii
import rc4

#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'
arp = rdpcap('arp.cap')[0]

# setting plain text with 36 chars
plain = "hello-world hello-world hello-world "

##1. compute ICV of plain 
icv = binascii.crc32(plain) 
icv = struct.pack("<i", icv)
##2. seed -> (RC4) = keystream
##3. keystream XOR (plain + ICV) = cipher
cipher= rc4.rc4crypt(plain + icv, arp.iv+key)

##4. add fields
arp.wepdata = cipher[:-4]
(arp.icv,) = struct.unpack("!L", cipher[-4:])

###5. forge cap file
wrpcap('arpForged.cap', arp)

