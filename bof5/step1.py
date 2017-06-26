#!/usr/bin/python
import sys
import time
import argparse
from pwn import *
context.update(arch='i386', os='linux')

def wait_for_prompt(r):
  print r.recvuntil("overflow me:")

#--------------------------------------------------------------------------
if __name__ == "__main__":

  parser = argparse.ArgumentParser(description='Exploit the bins.')
  parser.add_argument('--dbg'   , '-d', action="store_true")
  args = parser.parse_args()
  exe = './bof5'

  libc_path = '/lib/i386-linux-gnu/libc.so.6'
  libc = ELF(libc_path)

  if args.dbg:
    r = gdb.debug([exe], """
    b *func
    continue
    """)
  else:
    r = process(exe)

  r.recvuntil('stdin: 0x')
  leak_stdin = int(r.recvuntil('\n')[:-1],16)
  print "We have %s as a leak" %hex(leak_stdin)
  wait_for_prompt(r)


  # Drop to interactive console
  r.interactive()

