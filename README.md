# Rainfall Project - Solved Challenges

## 📚 Overview
This repository contains the solutions and explanations for the **Rainfall** project, which introduces binary exploitation techniques on ELF-like binaries in an i386 environment. The main goal is to gain a deeper understanding of security vulnerabilities and memory management in software applications.

## 🎯 Project Objectives
- Explore binary exploitation methods.
- Understand RAM operations and security flaws in software.
- Develop logical thinking and secure coding practices.
- Successfully read the `.pass` file of each level's user by exploiting binary vulnerabilities.

---

## 📝 Repository Structure
```plaintext
rainfall/
├── tools/
├── level0/
│   ├── pass
│   ├── source.c
│   └── walkthrough.md
...
├── level9/
│   ├── pass
│   ├── source.c
│   └── walkthrough.md
├── bonus0/
│   ├── pass
│   ├── source.c
│   └── walkthrough.md
...
└── bonus3/
    ├── pass
    ├── source.c
    └── walkthrough.md
```

Each **levelX** directory includes:
- **pass:** Output file after successful exploitation.
- **source.c:** Decompiled or reverse-engineered source code for analysis.
- **walkthrough.md:** Detailed explanation of the exploitation process.
---

## 💡 Solved Challenges Walkthrough

- **Objective:** Exploit the binary to read `/home/user/level<x>/.pass`.
- **Key Techniques:** Buffer overflow basics, understanding function calls.
- **Techniques:**
  - Stack smashing
  - Format string vulnerabilities
  - Environment variable manipulation
  - Shellcode injection and NOP sled creation.
  - Handling segmentation faults with precise offset calculations.
- **Tools Used:** `gdb`, `objdump`, `strings`, `readelf`
- **Walkthrough Highlights:**
  - Identified buffer size vulnerability.
  - Crafted a simple payload to redirect execution flow.
  - Analyzed binary with `gdb` for vulnerable functions.
  - Created a payload to execute `system("/bin/sh")`.

---

## 🔨 Tools & Environment
- **Operating System:** Linux VM (64-bit)
- **Debugger:** `gdb`
- **Reverse Engineering:** `objdump`, `readelf`, `strings`
- **Scripting:** Python for exploit automation.

---

## ✅ Final Notes
- All exploits were developed manually without brute-force techniques.
- Every solution step is clearly explained in each `walkthrough.md` file.
