# bof4

This challenge is similar to bof3, but there are some minor changes:
```C
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
  gets(overflowme);     // smash me!

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

```

1) You get to input your name **Yay**, This is stored in the global scope variable `name[10]`. You can't overflow this.
2) There is a `hidden()` function that is never called, but that does have a call to `system()`

Steps to solve this are exactly like bof3:
1) Locate the offset of the return pointer
2) Find where to redirect code execution
3) Find a usable pointer to the string "/bin/sh"
4) Ensure the stack is set up correctly to pass the pointer to "/bin/sh" to system()

There is no existing '/bin/sh' string in the application. But you can write to a predictable memory location by setting your name.
Did you know that your name is now: `/bin/sh`? That's a curious name, your momma must have been a linux guru :P

At this point, you should be able to write an exploit for this one yourself.
