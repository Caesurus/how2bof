// $ gcc -m32 -fno-stack-protector bof4.c -o bof4


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

const char name[10];
int key = 0xdeadbeef;

void hidden(void)
{
  system("/bin/echo BLAH, can't touch me!");
}


void func(void)
{
  char overflowme[1024];

  printf("overflow me:");
  gets(overflowme);	// smash me!

  printf("Psych!!! No shell for you");
}

void main(int argc, char* argv[])
{
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  
  printf("What's you name?: ");
  scanf("%10s",name);  

  func();

  return;
}

