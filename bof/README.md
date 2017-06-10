# bof @ pwnable.kr

This challenge originally comes from [pwnable.kr](http://pwnable.kr/play.php). 
This is the same binary and is essentially a practical walk through.
Please go and play the other challenges on the site. They are excellent.

For this challenge there are a couple of things you should know.

 * When I first started playing pwnable.kr, it took me several days to solve this. So don't get discouraged.
 * A lot of information out there talks about overwriting the return pointer on the stack (don't worry if this doesn't make any sense at the moment). That is not the goal of this challenge
 * It's OK to watch a walkthrough as long as you walk away understanding WHY/HOW the challenge was solved.
 * [Excellent video walkthrough](https://www.youtube.com/watch?v=BxSD0cSjyNg&t=13s), But it still may be a bit impractical.

_There is a LOT to learn, and the goal of this page is to walk you through a practical process of solving this challenge. You may not understand all of the finer details, but that will come later on_

So where to start?
First lets install some tools. I would advise running a system with Ubuntu 16.04 (or 14.04)

Install: [pwntools](https://github.com/Gallopsled/pwntools) please head over there and look up how to install this excellent python module.

It is also recommended that you use something to make the use of GDB a bit 'friendlier'.

I would recommend using one of the following:
 - [PEDA](https://github.com/longld/peda)
 - [pwndbg](https://github.com/pwndbg/pwndbg)

---
Now that you have all of that installed and you have done a local clone of this repo lets proceed and look at the source code
[bof.c](/master/bof/bof.c)
Specifically this code:
```C
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
```

 We see that `key` is an argument passed to the `func()` function. 
 
 We also see `overflowme[32]` is an array the holds 32 bytes.
 
 There is a call to `gets()` with the pointer to `overflowme` as the buffer. 
 
 Then `key` is checked to see if it is a certain value `0xcafebabe`.
 
The vulnerability lies in the fact that you can pass more than 32 bytes to the `gets()` function. It will keep reading data till a return(`\n`) is encountered.

Rather than going into boring theory about the stack, lets fire up a script to step through what is actually happening.

Try running the [step1.py](./step1.py) script and reading through what it's doing.
Run the script with the `-d` option it will cause gdb to attach to the running process with the breakpoint set at exactly the start of `func()`

RUN: `./step1.py -d`

---

Now if all went well, and you loaded [PEDA](https://github.com/longld/peda), You should see something like this:
```asm
 [----------------------------------registers-----------------------------------]
EAX: 0xf76e6dbc --> 0xffd9cbcc --> 0xffd9d312 ("GLADE_PIXMAP_PATH=:")
EBX: 0x0 
ECX: 0x4b62348c 
EDX: 0xffd9cb54 --> 0x0 
ESI: 0xf76e5000 --> 0x1b1db0 
EDI: 0xf76e5000 --> 0x1b1db0 
EBP: 0xffd9cb28 --> 0x0 
ESP: 0xffd9cb0c --> 0x5665169f (<main+21>:      mov    eax,0x0)
EIP: 0x5665162c (<func>:        push   ebp)
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x56651627 <__i686.get_pc_thunk.bx>: mov    ebx,DWORD PTR [esp]
   0x5665162a <__i686.get_pc_thunk.bx+3>:       ret    
   0x5665162b <__i686.get_pc_thunk.bx+4>:       nop
=> 0x5665162c <func>:   push   ebp
   0x5665162d <func+1>: mov    ebp,esp
   0x5665162f <func+3>: sub    esp,0x48
   0x56651632 <func+6>: mov    eax,gs:0x14
   0x56651638 <func+12>:        mov    DWORD PTR [ebp-0xc],eax
[------------------------------------stack-------------------------------------]
0000| 0xffd9cb0c --> 0x5665169f (<main+21>:     mov    eax,0x0)
0004| 0xffd9cb10 --> 0xdeadbeef 
0008| 0xffd9cb14 --> 0x56651250 --> 0x6e ('n')
0012| 0xffd9cb18 --> 0x566516b9 (<__libc_csu_init+9>:   add    ebx,0x193b)
0016| 0xffd9cb1c --> 0x0 
0020| 0xffd9cb20 --> 0xf76e5000 --> 0x1b1db0 
0024| 0xffd9cb24 --> 0xf76e5000 --> 0x1b1db0 
0028| 0xffd9cb28 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
gdb-peda$ 
```

If none of this makes sense, don't worry about it right now. Just keep going.

Now if we want to look at the whole assembly of the `func` we can issue the command `disassemble func`
```asm
gdb-peda$ disassemble func
Dump of assembler code for function func:
=> 0x5665162c <+0>:     push   ebp
   0x5665162d <+1>:     mov    ebp,esp
   0x5665162f <+3>:     sub    esp,0x48
   0x56651632 <+6>:     mov    eax,gs:0x14
   0x56651638 <+12>:    mov    DWORD PTR [ebp-0xc],eax
   0x5665163b <+15>:    xor    eax,eax
   0x5665163d <+17>:    mov    DWORD PTR [esp],0x5665178c
   0x56651644 <+24>:    call   0xf7592ca0 <_IO_puts>
   0x56651649 <+29>:    lea    eax,[ebp-0x2c]
   0x5665164c <+32>:    mov    DWORD PTR [esp],eax
   0x5665164f <+35>:    call   0xf75923e0 <_IO_gets>
   0x56651654 <+40>:    cmp    DWORD PTR [ebp+0x8],0xcafebabe
   0x5665165b <+47>:    jne    0x5665166b <func+63>
   0x5665165d <+49>:    mov    DWORD PTR [esp],0x5665179b
   0x56651664 <+56>:    call   0xf756dda0 <__libc_system>
   0x56651669 <+61>:    jmp    0x56651677 <func+75>
   0x5665166b <+63>:    mov    DWORD PTR [esp],0x566517a3
   0x56651672 <+70>:    call   0xf7592ca0 <_IO_puts>
   0x56651677 <+75>:    mov    eax,DWORD PTR [ebp-0xc]
   0x5665167a <+78>:    xor    eax,DWORD PTR gs:0x14
   0x56651681 <+85>:    je     0x56651688 <func+92>
   0x56651683 <+87>:    call   0xf762a4c0 <__stack_chk_fail>
   0x56651688 <+92>:    leave  
   0x56651689 <+93>:    ret    
End of assembler dump.
```
Remember the source code... Does anything look familiar between the disassembly and the source?
```C
	printf("overflow me : ");                 # 0x56651644 <+24>:    call   0xf7592ca0 <_IO_puts>
	gets(overflowme);	// smash me!            # 0x5665164f <+35>:    call   0xf75923e0 <_IO_gets>
	if(key == 0xcafebabe){                    # 0x56651654 <+40>:    cmp    DWORD PTR [ebp+0x8],0xcafebabe
		system("/bin/sh");                      # 0x56651664 <+56>:    call   0xf756dda0 <__libc_system>
	}
```

So now we can see exactly when the input is passed to the program (`0x5665164f <+35>`)
Lets step through the instructions till we get to that instruction. You do this by typing `next` and enter.
Now press enter again to repeat that gdb command and step to the next instruction. Do this till the arrow in the disassembly is pointing to `0x5665164f <+35>`.

```asm
 [----------------------------------registers-----------------------------------]
EAX: 0xffd9cadc --> 0xffd9caec --> 0xffd9caff --> 0x6e5000b9 
EBX: 0x0 
ECX: 0xffffffff 
EDX: 0xf76e6870 --> 0x0 
ESI: 0xf76e5000 --> 0x1b1db0 
EDI: 0xf76e5000 --> 0x1b1db0 
EBP: 0xffd9cb08 --> 0xffd9cb28 --> 0x0 
ESP: 0xffd9cac0 --> 0xffd9cadc --> 0xffd9caec --> 0xffd9caff --> 0x6e5000b9 
EIP: 0x5665164f (<func+35>:     call   0xf75923e0 <_IO_gets>)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x56651644 <func+24>:        call   0xf7592ca0 <_IO_puts>
   0x56651649 <func+29>:        lea    eax,[ebp-0x2c]
   0x5665164c <func+32>:        mov    DWORD PTR [esp],eax
=> 0x5665164f <func+35>:        call   0xf75923e0 <_IO_gets>
   0x56651654 <func+40>:        cmp    DWORD PTR [ebp+0x8],0xcafebabe
   0x5665165b <func+47>:        jne    0x5665166b <func+63>
   0x5665165d <func+49>:        mov    DWORD PTR [esp],0x5665179b
   0x56651664 <func+56>:        call   0xf756dda0 <__libc_system>
Guessed arguments:
arg[0]: 0xffd9cadc --> 0xffd9caec --> 0xffd9caff --> 0x6e5000b9 
[------------------------------------stack-------------------------------------]
0000| 0xffd9cac0 --> 0xffd9cadc --> 0xffd9caec --> 0xffd9caff --> 0x6e5000b9 
0004| 0xffd9cac4 --> 0xffd9cb64 --> 0x519fba9d 
0008| 0xffd9cac8 --> 0xf76e5000 --> 0x1b1db0 
0012| 0xffd9cacc --> 0x9d57 
0016| 0xffd9cad0 --> 0xffffffff 
0020| 0xffd9cad4 --> 0x2f ('/')
0024| 0xffd9cad8 --> 0xf753fdc8 (jbe    0xf753fdf5)
0028| 0xffd9cadc --> 0xffd9caec --> 0xffd9caff --> 0x6e5000b9 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
gdb-peda$ 
```



