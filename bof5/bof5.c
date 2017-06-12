// $ gcc -m32 -fno-stack-protector bof5.c -o bof5
// Relevant paper: https://www.exploit-db.com/docs/28553.pdf

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void func(void)
{
  char overflowme[64];

  printf("overflow me:");
  gets(overflowme);	// smash me!

  printf("Psych!!! No shell for you");
}

void main(int argc, char* argv[])
{
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  printf("Here is your leaked LIBC address\n");
  printf("stdin: %p\n", stdin);
  func();

  return;
}

