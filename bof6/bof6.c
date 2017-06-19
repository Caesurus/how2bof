// $ gcc -g -fstack-protector-all -Wl,-z,relro,-z,now -m32 bof6.c -o bof6
// Relevant paper: https://www.exploit-db.com/docs/28553.pdf

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#define BUFSIZE  64
char name[BUFSIZE];

void func(void)
{
  char overflowme[64];

  printf("overflow me:");
  gets(overflowme);	// smash me!

}

void main(int argc, char* argv[])
{
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  memset(name, 0, 64);
  printf("What's your name? I need this so I can mock you later!!!\nName: ");
  read(0, name, BUFSIZE);
  printf("Hi there "); printf(name);

  func();

  printf("\nMUHAHAHA, %s can't get a shell!!!\nTry again!", name);
  return;
}

