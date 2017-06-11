# bof3

This challenge is similar to bof2, but there are some minor changes:
```C
void func(void)
{
  char overflowme[1024];

  printf("\noverflow me to get /bin/sh");
  printf("\nIF YOU CAN... MUHAHAHAH: ");

  gets(overflowme);     // smash me!

  if(key == 0xcafebabe){
    system("/bin/echo LOL Nice Try!!!");
  }
  else{
    printf("Nah..\n");
  }
}
```

1. The size of the buffer has gotten bigger (1024 bytes instead of 32)
2. There is no direct `system("/bin/sh");` call in the code.

The previous challenge showed how parameters are passed to a function, so the steps necessary to solve this are:
1) Locate the offset of the return pointer
2) Find a usable pointer to the string `"/bin/sh"`
3) Find _where_ to redirect code execution
4) Ensure the stack is set up correctly to pass the pointer to `"/bin/sh"` to `system()`

