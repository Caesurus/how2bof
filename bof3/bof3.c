// $ gcc -m32 -fno-stack-protector bof3.c -o bof3


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int key = 0xdeadbeef;

void func(void)
{
  char overflowme[1024];

  printf("\noverflow me to get /bin/sh");
  printf("\nIF YOU CAN... MUHAHAHAH: ");

  gets(overflowme);	// smash me!

  if(key == 0xcafebabe){
    system("/bin/echo LOL Nice Try!!!");
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

