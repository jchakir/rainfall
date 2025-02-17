
# Binary Protections Explained

When analyzing binaries in binary exploitation, various security mechanisms may be enabled or disabled. Below is an explanation of each protection found in the given output:

**RELRO (Relocation Read-Only)**  
- **No RELRO**: The GOT (Global Offset Table) is writable, making it vulnerable to GOT overwrite attacks.  
- **Partial RELRO**: The GOT is only partially protected, reducing but not eliminating risks.  
- **Full RELRO**: The GOT is fully read-only, preventing GOT overwrite attacks.

**Stack Canary**  
- **No canary found**: The binary does not use stack canaries, making it vulnerable to stack-based buffer overflow attacks.  
- **Canary found**: A random value (canary) is placed before the return address, detecting buffer overflows and preventing exploitation.  

**NX (Non-Executable Stack)**  
- **NX enabled**: The stack is non-executable, preventing shellcode execution on the stack.  
- **NX disabled**: The stack is executable, allowing attackers to inject and execute shellcode.  

**PIE (Position Independent Executable)**  
- **No PIE**: The binary is loaded at a fixed address, making it easier for attackers to predict addresses for return-oriented programming (ROP).  
- **PIE enabled**: The binary is loaded at a random address (ASLR-friendly), making exploitation harder.  

**RPATH & RUNPATH**  
- **No RPATH / No RUNPATH**: No custom library search paths are defined, reducing the risk of library hijacking.  
- **RPATH/RUNPATH set**: The binary may load libraries from non-standard paths, potentially leading to security risks.  

# Summary of the Binary's Protections:

```
| Protection   | Status           | Security Impact
|--------------|------------------|----------------
| RELRO        | No RELRO         | Vulnerable to GOT overwrite attacks
| Stack Canary | No Canary Found  | Vulnerable to stack buffer overflow
| NX           | Enabled          | Stack is non-executable (mitigates shellcode execution)
| PIE          | No PIE           | Binary is at a fixed address (easier ROP exploitation)
| RPATH        | No RPATH         | No risk of library hijacking
| RUNPATH      | No RUNPATH       | No risk of library hijacking
```

This binary lacks key protections like **RELRO, Stack Canary, and PIE**, making it easier to exploit.

### Source Code in Assembly
```asm
   0x08048ec0 <+0>:     push   ebp
   0x08048ec1 <+1>:     mov    ebp,esp
   0x08048ec3 <+3>:     and    esp,0xfffffff0
   0x08048ec6 <+6>:     sub    esp,0x20
   0x08048ec9 <+9>:     mov    eax,DWORD PTR [ebp+0xc]
   0x08048ecc <+12>:    add    eax,0x4
   0x08048ecf <+15>:    mov    eax,DWORD PTR [eax]
   0x08048ed1 <+17>:    mov    DWORD PTR [esp],eax
   0x08048ed4 <+20>:    call   0x8049710 <atoi>
   0x08048ed9 <+25>:    cmp    eax,0x1a7
   0x08048ede <+30>:    jne    0x8048f58 <main+152>
   0x08048ee0 <+32>:    mov    DWORD PTR [esp],0x80c5348
   0x08048ee7 <+39>:    call   0x8050bf0 <strdup>
   0x08048eec <+44>:    mov    DWORD PTR [esp+0x10],eax
   0x08048ef0 <+48>:    mov    DWORD PTR [esp+0x14],0x0
   0x08048ef8 <+56>:    call   0x8054680 <getegid>
   0x08048efd <+61>:    mov    DWORD PTR [esp+0x1c],eax
   0x08048f01 <+65>:    call   0x8054670 <geteuid>
   0x08048f06 <+70>:    mov    DWORD PTR [esp+0x18],eax
   0x08048f0a <+74>:    mov    eax,DWORD PTR [esp+0x1c]
   0x08048f0e <+78>:    mov    DWORD PTR [esp+0x8],eax
   0x08048f12 <+82>:    mov    eax,DWORD PTR [esp+0x1c]
   0x08048f16 <+86>:    mov    DWORD PTR [esp+0x4],eax
   0x08048f1a <+90>:    mov    eax,DWORD PTR [esp+0x1c]
   0x08048f1e <+94>:    mov    DWORD PTR [esp],eax
   0x08048f21 <+97>:    call   0x8054700 <setresgid>
   0x08048f26 <+102>:   mov    eax,DWORD PTR [esp+0x18]
   0x08048f2a <+106>:   mov    DWORD PTR [esp+0x8],eax
   0x08048f2e <+110>:   mov    eax,DWORD PTR [esp+0x18]
   0x08048f32 <+114>:   mov    DWORD PTR [esp+0x4],eax
   0x08048f36 <+118>:   mov    eax,DWORD PTR [esp+0x18]
   0x08048f3a <+122>:   mov    DWORD PTR [esp],eax
   0x08048f3d <+125>:   call   0x8054690 <setresuid>
   0x08048f42 <+130>:   lea    eax,[esp+0x10]
   0x08048f46 <+134>:   mov    DWORD PTR [esp+0x4],eax
   0x08048f4a <+138>:   mov    DWORD PTR [esp],0x80c5348
   0x08048f51 <+145>:   call   0x8054640 <execv>
   0x08048f56 <+150>:   jmp    0x8048f80 <main+192>
   0x08048f58 <+152>:   mov    eax,ds:0x80ee170
   0x08048f5d <+157>:   mov    edx,eax
   0x08048f5f <+159>:   mov    eax,0x80c5350
   0x08048f64 <+164>:   mov    DWORD PTR [esp+0xc],edx
   0x08048f68 <+168>:   mov    DWORD PTR [esp+0x8],0x5
   0x08048f70 <+176>:   mov    DWORD PTR [esp+0x4],0x1
   0x08048f78 <+184>:   mov    DWORD PTR [esp],eax
   0x08048f7b <+187>:   call   0x804a230 <fwrite>
   0x08048f80 <+192>:   mov    eax,0x0
   0x08048f85 <+197>:   leave
   0x08048f86 <+198>:   ret
```

### Source Code in C

```c
int main (int argc, char** argv) {

  int   n;
  int   egid, euid;
  char*  binsh[2];

  n = atoi(argv[1]);
  if (n == 423) {
    binsh[0] = srtdup("/bin/sh");
    binsh[1] = 0;
    egid = getegid();
    euid = geteuid();
    setresgid();
    setresuid();
    execv("/bin/sh", binsh, 0);
  } else {
    write(1, "No !\n", 5);
  }
}
```


 ### Exploit
 the first impression at the program take a argument and convert them to int with atoi
 
 ```asm
   0x08048ed4 <+20>:    call   0x8049710 <atoi>
   0x08048ed9 <+25>:    cmp    eax,0x1a7
   0x08048ede <+30>:    jne    0x8048f58 <main+152>
 ```
then compare them with a harcoded value 0x1a7 which is (423)
if not equal its write 'No !'
if argument equal 423 it continue executing to execv('/bin/sh')

```linux
level0@RainFall:~$ ./level0 423
$ whoami
level1
```
Next read the .pass file

