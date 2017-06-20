# how2bof
Guide to buffer overflows, binaries that can be used to practice BufferOverFlows. All these binaries are 32bit. Compiled on Ubuntu 16.04

You probably arrive here because you're interested in learning to hack. Hopefully this repo contains information that is useful in your pursuit. Another resource I can highly recommend is [LiveOverflow](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w). He has a real gift for explaining the underlying technical principles.

### [Level 1](./bof)
This challenge was taken directly from the [pwnable.kr](http://pwnable.kr) challenge "bof". This is a great starting point for learning about buffer overflows.

### [Level 2](./bof2)
This challenge requires you to overwrite the return pointer on the stack. Can you get shell?

### [Level 3](./bof3)
This challenge requires you to set up the stack correctly to pass arguments to the system function. Are you up for the challenge?

### [Level 4](./bof4)
Similar to bof3, but strings won't be as readily available, can you still get shell?

### [Level 5](./bof5)
Introduction into ASLR, and using return to libc (ret2libc) for popping a shell.

### [Level 6](./bof6)
Building on the last level, this introduces the concept of stack cookies/sentinels/guards and requires leaking several values yourself by using [FSB](https://github.com/Caesurus/how2fsb).

---
## Essential Tools:

[pwntools](https://github.com/Gallopsled/pwntools). Please head over there and look up how to install this excellent python module.

It is also recommended that you use something to make the use of GDB a bit 'friendlier'.
I would recommend using one of the following:
 - [pwndbg](https://github.com/pwndbg/pwndbg)
 - [PEDA](https://github.com/longld/peda)

After putting these challenges together I found: https://github.com/bert88sta/how2exploit_binary
Take a look at his repo and very similar information there (plus more) ;)
