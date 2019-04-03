#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
import binascii
import rc4

#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'
#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

data = arp.wepdata
print(data)
# rc4 seed est composé de IV+clé
seed = arp.iv+key

plain = "Knowing the source of any information is way more important than the information itself." 
plain = "hello-world hello-world hello-world "
##1. compute ICV of plain 

icv = binascii.crc32(plain) 
icv = struct.pack("!l", icv)
##2. seed -> (RC4) = keystream
##3. keystream XOR (plain + ICV) = cipher
cipher= rc4.re4encrypt(plain + icv, arp.iv, key)



##4. add shit
#arp.icv = long(icv.encode("hex"), 16)
# arp.icv = 
print(struct.unpack('!L', icv))
arp.wepdata = cipher

###5. Send shit
wrpcap('arpForged.cap', arp)

# recuperation de icv dans le message (arp.icv) (en chiffre) -- je passe au format "text". Il y a d'autres manières de faire ceci...
icv_encrypted='{:x}'.format(arp.icv).decode("hex")

# text chiffré y-compris l'icv
message_encrypted=arp.wepdata+icv_encrypted

# déchiffrement avec rc4
#cleartext=rc4.rc4crypt(message_encrypted,seed)

# le ICV est les derniers 4 octets - je le passe en format Long big endian
#icv_enclair=cleartext[-4:]
#(icv_numerique,)=struct.unpack('!L', icv_enclair)

# le message sans le ICV
#text_enclair=cleartext[:-4]

#print 'Text: ' + text_enclair.encode("hex")
#print 'icv:  ' + icv_enclair.encode("hex")
#print 'icv(num): ' + str(icv_numerique)
