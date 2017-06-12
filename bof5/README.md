# bof5

This challenge introduces the concept of return to libc (ret2libc), and also requires defeating ASLR.

Steps to solve:
1) Use the leaked address to calculate the base address of libc
2) Find the return pointer offset in the stack
3) Find a usable pointer to the string "/bin/sh" (in libc)
4) Ensure the stack is set up correctly to pass the pointer to `"/bin/sh"` to `system()`

Some gotcha's here are:
* How to calculate the base address
* How to figure out the offset of system in libc
* How set up the stack correctly to pass an argument via a return instruction instead of a call instruction

Write-up will come later
