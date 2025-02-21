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
   0x080484f4 <+0>:     push   ebp
   0x080484f5 <+1>:     mov    ebp,esp
   .
   .
   .
   0x08048618 <+292>:   pop    ebx
   0x08048619 <+293>:   pop    edi
   0x0804861a <+294>:   pop    ebp
   0x0804861b <+295>:   ret
</code></pre>
</td>
<td>
<pre><code class="language-c">
int main(int argc, const char **argv)
{
  char buff[132];
  FILE *pass_file;
  int i;

  pass_file = fopen("/home/user/end/.pass", "r");
  memset(buff, 0, sizeof(buff));
  if ( !pass_file || argc != 2 )
    return -1;
  fread(buff, 1, 66, pass_file);
  ptr[65] = 0;
  i = atoi(argv[1]);
  ptr[i] = 0;
  fread(buff + 66, 1, 65, pass_file);
  fclose(pass_file);
  if ( !strcmp(buff, argv[1]) )
    execl("/bin/sh", "sh", 0);
  else
    puts(buff + 66);
}
</code></pre>
</td>
</tr>
</table>



# Exploring

## Objective

The program's goal is to authenticate a user by comparing a password read from a file with the argument provided (`argv[1]`). If the comparison succeeds (`strcmp(buff, argv[1]) == 0`), the program executes a shell (`/bin/sh`). Otherwise, it prints a message stored in the second part of the buffer (`buff + 66`). Our task is to bypass this check and gain shell access without knowing the actual password.

---

## Understanding the Program

Let's analyze the program's behavior step by step:

### 1. Initialization and Input Validation
- **Buffer Declaration:** A buffer `buff` of size 132 bytes is declared to store data read from the password file.
- **File Opening:** The program attempts to open the file `/home/user/end/.pass` in read mode.
- **Input Validation:** The program checks two conditions:
  - The file must open successfully (`pass_file != NULL`).
  - Exactly two arguments must be provided (`argc == 2`), where `argv[0]` is the program name and `argv[1]` is the user-provided argument.
- If either condition fails, the program returns `-1`, indicating failure.

### 2. Reading the Password File
- **First Read:** Assuming the file opens successfully and `argc == 2`, the program reads 66 bytes from the file into `buff` using `fread(buff, 1, 66, pass_file)`.
- **Null Termination:** The line `ptr[65] = 0;` is likely a typo, and it should be `buff[65] = 0;`. This sets the byte at index 65 to null (`\0`), effectively null-terminating the string at position 65. Thus, `buff[0]` to `buff[64]` can hold up to 65 characters, and `buff[65]` is `\0`.
- **Argument Conversion:** The provided argument (`argv[1]`) is converted to an integer using `atoi(argv[1])`, and the result is stored in `i`.
- **Buffer Modification:** The line `ptr[i] = 0;` is also likely a typo, and it should be `buff[i] = 0;`. This sets the byte at index `i` in `buff` to null (`\0`), potentially truncating the string at position `i`.
- **Second Read:** The program reads another 65 bytes from the file into `buff + 66` (i.e., `buff[66]` to `buff[130]`) using `fread(buff + 66, 1, 65, pass_file)`.
- **File Closing:** The file is closed using `fclose(pass_file)`.

### 3. Password Comparison and Shell Execution
- **Comparison:** The program compares the modified `buff` with the provided argument `argv[1]` using `strcmp(buff, argv[1])`.
  - If `strcmp` returns 0 (indicating the strings are equal), the program executes a shell using `execl("/bin/sh", "sh", 0)`.
  - Otherwise, it prints the string starting from `buff + 66` (i.e., the second part of the file) using `puts(buff + 66)`.

---

## Identifying the Vulnerability

The key to bypassing the password check lies in understanding how the program modifies `buff` and how `strcmp` compares it with `argv[1]`. Let's focus on the critical parts of the code:

### 1. Converting the Argument with `atoi`
- The program uses `atoi(argv[1])` to convert the user-provided argument to an integer.
- According to the C standard, if `argv[1]` is not a valid integer string, `atoi` returns 0. This includes cases where `argv[1]` is an empty string (`""`), because `atoi("")` cannot parse it as a number and returns 0.

### 2. Modifying the Buffer with `buff[i] = 0`
- After computing `i = atoi(argv[1])`, the program sets `buff[i] = 0`.
- If `i = 0`, this sets `buff[0] = 0`, effectively making `buff` an empty string, because in C, strings are null-terminated, and a null character at index 0 terminates the string immediately.

### 3. Comparing Strings with `strcmp`
- The program compares `buff` with `argv[1]` using `strcmp`.
- In C, `strcmp` compares two null-terminated strings and returns 0 if they are equal.
- If `buff` is an empty string and `argv[1]` is also an empty string, then `strcmp("", "")` returns 0, indicating a match.

---

## The Trick: Using an Empty String

The vulnerability can be exploited by providing an empty string (`""`) as the command-line argument. Let's walk through what happens in this case:

### 1. Providing the Empty String
- Run the program as `./program ""`.
- Here, `argc = 2`, `argv[0] = "./program"`, and `argv[1] = ""` (an empty string, i.e., `argv[1][0] = '\0'`).

### 2. Converting the Argument
- The program computes `i = atoi(argv[1])`.
- Since `argv[1] = ""`, `atoi("")` returns 0, so `i = 0`.

### 3. Modifying the Buffer
- The program sets `buff[65] = 0`, null-terminating the string at position 65 (after reading the first 66 bytes from the file).
- Then, it sets `buff[i] = 0`, where `i = 0`, so `buff[0] = 0`.
- Setting `buff[0] = 0` makes `buff` an empty string, because the first null character terminates the string.

### 4. Comparing Strings
- The program compares `buff` with `argv[1]` using `strcmp`.
- Since `buff` is now an empty string (`buff[0] = '\0'`) and `argv[1]` is also an empty string (`""`), `strcmp("", "")` returns 0, indicating a match.

### 5. Executing the Shell
- Because the comparison succeeds, the program calls `execl("/bin/sh", "sh", 0)`, which executes a shell, granting us unauthorized access.

---

## Why This Works

The trick works because:
- Providing an empty string as the argument exploits the behavior of `atoi`, which returns 0 for non-numeric inputs.
- Setting `buff[0] = 0` makes `buff` an empty string, regardless of the actual password read from the file.
- Comparing two empty strings with `strcmp` results in a match, bypassing the authentication check.

### Exploring Other Inputs
- **Non-Empty Strings:** If `argv[1] = "5"`, then `i = atoi("5") = 5`, and `buff[5] = 0`. This truncates `buff` to the first 5 characters of the password, and `strcmp(buff, "5")` is unlikely to match unless the password starts with "5" followed by nulls.
- **Non-Numeric Strings:** If `argv[1] = "abc"`, then `i = atoi("abc") = 0`, so `buff[0] = 0`, making `buff` empty. However, `strcmp("", "abc") != 0`, so it fails.
- **Negative Numbers:** If `argv[1] = "-1"`, then `i = -1`, and `buff[-1] = 0` would likely cause a segmentation fault due to invalid memory access.
- Only the empty string (`""`) reliably exploits the vulnerability to gain shell access.

---

## Solution

To bypass the password check and gain shell access, execute the program with an empty string as the argument:

```sh
./program ""
```

### Explanation of the Command
- `./program` is the program name (`argv[0]`).
- `""` is the empty string argument (`argv[1]`), which is a string with just a null terminator (`argv[1][0] = '\0'`).
- This ensures `argc = 2`, satisfying the input validation check.

### Step-by-Step Execution
1. The program opens the password file and reads 66 bytes into `buff`.
2. It sets `buff[65] = 0`, null-terminating the string.
3. It computes `i = atoi("") = 0`.
4. It sets `buff[0] = 0`, making `buff` an empty string.
5. It reads another 65 bytes into `buff[66]` to `buff[130]`, but this does not affect the comparison.
6. It compares `buff` (empty string) with `argv[1]` (empty string) using `strcmp`, which returns 0.
7. Since the comparison succeeds, it executes `/bin/sh`, giving shell access.

---

# Exploiting

Output:

```
bonus3@RainFall:~$ ./bonus3 ""
$ whoami
end
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```

We successfully got the `end` user password.


The last user `end` have just file named `end` contain:

```
end@RainFall:~$ ls -l
total 4
-rwsr-s---+ 1 end users 26 Sep 23  2015 end
end@RainFall:~$ cat end
Congratulations graduate!
```

At this point we finished the `rainfall` challenges, maybe see you again on `override` with more hard ones.
