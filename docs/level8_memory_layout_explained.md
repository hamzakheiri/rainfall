# Level8 - Memory Layout Explained: Why Service Doesn't Overwrite Auth

## The Common Misconception

**Question**: "If auth is allocated before service, how does overfilling service change auth content?"

**Answer**: **It doesn't!** This is the key insight - we're NOT overwriting auth at all.

---

## What's Actually Happening

### The Vulnerable Check

```c
if (*(int *)(auth + 32))  // Check 32 bytes BEYOND auth pointer
    system("/bin/sh");
```

This checks the value at `auth + 32`, which is **32 bytes beyond** where auth points.

### The Problem

```c
auth = malloc(4);  // Only allocates 4 bytes!
```

But the check looks at `auth + 32` - that's **28 bytes beyond** the allocated memory!

---

## Detailed Memory Layout

### Step 1: After `auth` command

```
Heap Memory:
┌─────────────────────────────────────────────────────────┐
│ Address    │ Content        │ Description               │
├────────────┼────────────────┼───────────────────────────┤
│ 0x804a000  │ [metadata]     │ Heap chunk header         │
│ 0x804a008  │ [00 00 00 00]  │ auth data (4 bytes)       │ ← auth points here
│ 0x804a00c  │ [unallocated]  │ Free heap space           │
│ 0x804a010  │ [unallocated]  │ Free heap space           │
│ 0x804a014  │ [unallocated]  │ Free heap space           │
│ 0x804a018  │ [unallocated]  │ Free heap space           │
│ 0x804a01c  │ [unallocated]  │ Free heap space           │
│ 0x804a020  │ [unallocated]  │ Free heap space           │
│ 0x804a024  │ [unallocated]  │ Free heap space           │
│ 0x804a028  │ [unallocated]  │ Free heap space           │ ← auth + 32 points here!
│            │                │                           │    (currently zero)
└─────────────────────────────────────────────────────────┘
```

**Key Point**: `auth + 32` points to unallocated heap space!

### Step 2: After `service AAAA...` command

```
Heap Memory:
┌─────────────────────────────────────────────────────────┐
│ Address    │ Content        │ Description               │
├────────────┼────────────────┼───────────────────────────┤
│ 0x804a000  │ [metadata]     │ First chunk header        │
│ 0x804a008  │ [00 00 00 00]  │ auth data (4 bytes)       │ ← auth (unchanged!)
│ 0x804a00c  │ [metadata]     │ Padding/alignment         │
│ 0x804a010  │ [metadata]     │ Service chunk header      │
│ 0x804a018  │ [41 41 41 41]  │ 'AAAA' (bytes 0-3)        │ ← service points here
│ 0x804a01c  │ [41 41 41 41]  │ 'AAAA' (bytes 4-7)        │
│ 0x804a020  │ [41 41 41 41]  │ 'AAAA' (bytes 8-11)       │
│ 0x804a024  │ [41 41 41 41]  │ 'AAAA' (bytes 12-15)      │
│ 0x804a028  │ [41 41 41 41]  │ 'AAAA' (bytes 16-19)      │ ← auth + 32 points here!
│ 0x804a02c  │ [41 41 41 41]  │ 'AAAA' (bytes 20-23)      │    (now contains 'A'!)
│ 0x804a030  │ [41 41 41 41]  │ 'AAAA' (bytes 24-27)      │
│ ...        │ ...            │ ...                       │
└─────────────────────────────────────────────────────────┘
```

**Key Point**: auth is still at 0x804a008 (unchanged), but `auth + 32` now reads from the service string!

---

## The Math

```
auth pointer:     0x804a008
auth + 32:        0x804a008 + 0x20 = 0x804a028

service pointer:  0x804a018
service + 16:     0x804a018 + 0x10 = 0x804a028

Therefore: auth + 32 == service + 16
```

When the program checks `*(auth + 32)`, it's actually reading **byte 16 of the service string**!

---

## Visual Representation

```
auth allocation (4 bytes):
[####]
↑
0x804a008

auth + 32 points here:
                                        ↓
[####]...........................[?????]
↑                               ↑
0x804a008                       0x804a028
auth                            auth + 32 (out of bounds!)


service allocation (40+ bytes):
                    [AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA]
                    ↑               ↑
                    0x804a018       0x804a028
                    service         service + 16


Combined view:
[auth][gap][service string starts here: AAAAAAAAAAAAAAAAAAAAAA...]
↑          ↑                                ↑
0x804a008  0x804a018                        0x804a028
auth       service                          auth + 32 = service + 16
```

---

## Why This Works

### 1. Out-of-Bounds Read
The program reads `auth + 32` which is **outside** the auth allocation.

### 2. Sequential Heap Allocation
malloc() allocates memory sequentially, so service comes right after auth (plus metadata).

### 3. Predictable Offsets
Without ASLR, we can calculate exactly where `auth + 32` will land.

### 4. Heap Overlap
By making service long enough, we ensure `auth + 32` falls within the service string.

---

## Common Misunderstandings

### ❌ WRONG: "Service overflows into auth"
```
[auth][service overflow →→→ overwrites auth]
```
This is NOT what happens! Service doesn't overflow backward.

### ✅ CORRECT: "auth + 32 reads from service"
```
[auth]...[service]
      ↑           ↑
      auth        auth + 32 reads here (inside service)
```
The check reads forward from auth, landing in service.

---

## The Exploit in Simple Terms

1. **Allocate auth** → Creates 4-byte allocation at address X
2. **Allocate service** → Creates 40-byte allocation at address X + offset
3. **Calculate overlap** → X + 32 falls inside the service allocation
4. **Trigger login** → Reads `*(X + 32)` which is inside service string
5. **Non-zero check passes** → Shell granted!

---

## Code Walkthrough

```c
// Step 1: Allocate auth (4 bytes at 0x804a008)
auth = malloc(4);

// Step 2: Allocate service (40+ bytes at 0x804a018)
service = strdup("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

// Step 3: Login check
if (*(int *)(auth + 32))  // Reads from 0x804a028
{
    // 0x804a028 is inside the service string!
    // It contains 'AAAA' (0x41414141) - non-zero!
    system("/bin/sh");  // Shell granted!
}
```

---

## Key Takeaway

**We don't overflow service into auth.**  
**We make service long enough so that `auth + 32` reads from service.**

This is a **logic flaw** exploiting **out-of-bounds read**, not a buffer overflow!

