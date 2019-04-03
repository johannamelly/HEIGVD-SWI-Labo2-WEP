#!/usr/bin/env python
#
#       RC4, ARC4, ARCFOUR algorithm
#
#       Copyright (c) 2009 joonis new media
#       Author: Thimo Kraemer <thimo.kraemer@joonis.de>
#
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#       
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#       
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#       MA 02110-1301, USA.
#

def rc4crypt(data, key):
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))
    
    return ''.join(out)

def re4encrypt(data, iv, key):
	T = []
	for i in iv:
		T.append(ord(i))
	for i in key:
		T.append(ord(i))
	print(T)
	S = range(0,256)
	j = 0
	
	for i in range(0,256):
		j = (j+S[i] + T[i%len(T)])%256
		print(j)
		S[i], S[j] = S[j], S[i]

	i = 0
	k = 0
	res = ""
	
	for c in data:
		i = (i+1)%256
		k = (k+ S[i])%256
		S[i], S[k] = S[k], S[i]
		chfr = S[(S[i]+S[k])%256]
		res=res+''.join(chr(chfr^ord(c)))
	
	return res
crypted = re4encrypt("coucou", "asox", "29dj2i9hdb")
print(rc4crypt(crypted, "asox29dj2i9hdb"))
