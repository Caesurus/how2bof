# bof2

This challenge is designed to show how to find and overwrite the return pointer on the stack. 
You may want to check out: [LiveOverflow](https://www.youtube.com/watch?v=8QzOC8HfOqU)

This challenge build off of the previous one. The last challenge overwrote a variables value on the stack. This challenge we look into program flow and taking control of code execution.

The source for this challenge is very similar except that the passed parameter is defined in a global scope. This means that the comparison is not going to look on the stack for the variable value.

If we revisit my very crude depiction of what a stack we can see where the return pointer is. When a function is called the return pointer will get pushed to the stack and then stack memory will be allocated for that function to do what it needs with its local variables.
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

In this challenge, we need to do two things:
 * Find _where that return pointer is_, and how many bytes we need to pass in order to overwrite it
 * Find _a location to return code execution to_. What do we want to execute, and HOW do we find that location?

Time to look at an example.
<to be continued>
