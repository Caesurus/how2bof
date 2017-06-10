// $ gcc -m32 -fno-stack-protector bof2.c -o bof2

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int key = 0xdeadbeef;

void func(void)
{
  char overflowme[32];

  printf("overflow me : ");
  gets(overflowme);	// smash me!

  if(key == 0xcafebabe){
    system("/bin/sh");
  }
  else{
    printf("Nah..\n");
  }
}

void main(int argc, char* argv[])
{
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  func();

  return;
}

