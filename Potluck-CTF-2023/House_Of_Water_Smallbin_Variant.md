# House Of Water - small-bin variant
> Technique overview:
>
> Gain control over `tcache_perthread_struct` by crafting a fake chunk inside it and linking that fake chunk into the __small-bin__ and thereby allocate it.

# Background
The original House of Water technique turns a Use-After-Free vulnerability into control over tcache metadata by crafting a fake chunk and linking it into the unsorted-bin, the linking process abuses the unsorted bin’s doubly linked list, the technique commonly relies on brute-forcing a few ASLR bits and requires "huge chunk" allocations.

This variant applies the same idea while operating through the small bins instead. 
It carefully aligns and links the fake chunk to satisfy small-bin constraints rather than those of the unsorted-bin, eliminating the need for heap leaks or brute-forcing and avoids "huge chunk" allocations while still achieving reliable tcache structure control.

# Prerequisites
One of these primitives:
- Use-After-Free (UAF) 
- Heap Overflow 
- Double Free

__No__ read primitive is required, as this technique is designed to work without leaks.

__No__ brute-forcing or partial ASLR bit leaks are required, as the technique can be implemented without relying on overwriting ASLR-dependent bytes.

# The tcache structure
```c
struct tcache_perthread_struct {
    uint16_t counts[TCACHE_MAX_BINS];
    tcache_entry *entries[TCACHE_MAX_BINS];
};
```
- **Note:** `TCACHE_MAX_BINS = 64`, so the tcache size is calculated as follows:
    `64 × uint16_t` (counts) -> `64 × 2 bytes = 0x80`
    `64 × tcache_entry*` (pointers) -> `64 × 8 bytes = 0x200`
    Total: `0x80 + 0x200 = 0x280 bytes`.

The tcache structure contains two parts -- counts and entries.
The counts array tracks how many entries exist in each tcache bin's linked list stored in the entries array.

The entries linked list is protected with a "protect pointers" mechanism which prevents attackers from partial overwrites or faking pointers into the tcache bin, this protection does not apply to the tcache bins' pointers array.

The tcache itself is stored in the heap as a 0x290-sized chunk (after adding 0x10 of heap metadata to it).

Because libc allocates the tcache structure it is placed at the start of the heap before any other allocation of the program, so any other allocations will be in higher addresses than the tcache.

# Crafting Fake Chunk
In this part, we will discuss how we create that fake chunk both in the original House of Water technique and in the small-bin variant.

## The original technique
To create the fake chunk, we abuse the fact that pointers themselves aren't protected inside the tcache. We craft a fake chunk that matches unsorted bin constraints by creating fake `fd` and `bk` pointers inside the 0x20 & 0x30 tcache bins along with a fake size field presented by the 0x3e0 & 0x3f0 bins counts that placed right above the fd and bk pointers.

**tcache-dump**
```
tcache chunk at heap start ==
                           ||
                           \/
0x61f43a4ec000  0x0000000000000000  0x0000000000000291
0x61f43a4ec010  0x0000000000010001  0x0000000000000000
0x61f43a4ec020  0x0000000000000000  0x0000000000000000
0x61f43a4ec030  0x0000000000000000  0x0000000000000000
0x61f43a4ec040  0x0000000000000000  0x0000000000000000
0x61f43a4ec050  0x0000000000000000  0x0000000000000000
0x61f43a4ec060  0x0000000000000000  0x0000000000000000
0x61f43a4ec070  0x0000000000000000  0x0000000000000000
______
These bytes look very similar to a heap chunk,
it has a size field of 0x10001 along with valid fd & bk pointers.
------------------------------------------------------
0x61f43a4ec080  0x0000000000000000  0x0000000000010001
0x61f43a4ec090  0x000061f43a4ec2a0  0x000061f43a4ec2c0
------------------------------------------------------
0x61f43a4ec0a0  0x0000000000000000  0x0000000000000000
0x61f43a4ec0b0  0x0000000000000000  0x0000000000000000
0x61f43a4ec0c0  0x0000000000000000  0x0000000000000000
0x61f43a4ec0d0  0x0000000000000000  0x0000000000000000
0x61f43a4ec0e0  0x0000000000000000  0x0000000000000000
0x61f43a4ec0f0  0x0000000000000000  0x0000000000000000
0x61f43a4ec100  0x0000000000000000  0x0000000000000000
0x61f43a4ec110  0x0000000000000000  0x0000000000000000
0x61f43a4ec120  0x0000000000000000  0x0000000000000000
```

So now we understand how to craft the fake chunk, the next thing we need to understand is how we link it into the unsorted bin.

The unsorted bin linked list is just a list of chunks of all sizes, linked to each other by their `fd` and `bk` pointers. 
In contrast to the tcache, the unsorted bin doesn't have the "protected pointers" protection, so we can link two chunks into the unsorted bin and into the tcache bin so our fake chunk will point to the unsorted bin chunks like it is part of their list. 
Then we overwrite the unsorted bin entries LSBs to point to our fake chunk.

However, there are a few things to note, the tcache bin holds pointers to the chunks __userdata__ in contrast to the unsorted bin that holds pointers to chunks __metadata__, so there are some ways to bypass it using heap feng shui depending on your primitive and how it works. 
Another problem is that the pointers themselves are more than a single byte offset (e.g., 0x290 instead of 0x90) from the start of the heap. The MSB of this offset is partially controlled by ASLR, so we can calculate only the nibble of that byte.
Therefore, when we overwrite the `fd` & `bk` pointers of the unsorted bin entries, we need to take care of this and brute force the second nibble that belongs to ASLR, which ends with a 1/16 percent success rate.

## The small-bin variant
Here, we bypass the 1/16 brute force by creating our fake chunk at the last 0x200 offsets range near the end of the tcache area, along with another heap chunk immediately after the tcache in that same range (offset 0x290), We'll call that chunk "head chunk".

Then we create another two chunks of the same size as the head chunk and free all the chunks in this order:
1. free(chunk_one)
2. free(head_chunk)
3. free(chunk_two)

This places the head chunk in the middle of the unsorted bin between those two chunks, so the unsorted bin chunks pointers target it. 
Then we sort all those chunks into the small bin and overwrite only the LSB of their fd & bk pointers because their second byte, which is partially controlled by us, has the same value -- 0x2.
**No need to overwrite the ASLR-controlled nibble to make it point to the tcache bin fake chunk.**

Now we need to understand how we can create a fake chunk at the end of the tcache bin such that the offset between it and our controlled heap chunk fits within a single byte.

Please take a look at this dump:

**tcache-dump**
```
tcache chunk at heap start ==
                           ||
                           \/
0x5be9d0e19000	0x0000000000000000	0x0000000000000291
0x5be9d0e19010	0x0000000000000000	0x0007000000000000
0x5be9d0e19020	0x0000000000000000	0x0000000000000000
0x5be9d0e19030	0x0000000000000000	0x0000000000000000
0x5be9d0e19040	0x0000000000000000	0x0000000000000000
....
.....
______
This is the tcache fake chunk which we can create by freeing
two chunks into the 0x320 & 0x330 tcache bins
----------------------------------------------------------
0x5be9d0e19200	0x0000000000000000	0x0000000000000000
0x5be9d0e19210	0x00005be9d0e193f0	0x00005be9d0e19340
0x5be9d0e19220	0x0000000000000000	0x0000000000000000
0x5be9d0e19230	0x0000000000000000	0x0000000000000000
______
This chunk we can allocate via malloc in any size we want. 
Notice the offset between addresses is exactly `0x90` bytes:
0x5be9d0e19290 (controlled) - 0x5be9d0e19200 (fake) = 0x90
allowing single-byte LSB overwrite.
------------------------------------------------------
0x5be9d0e19290	0x0000000000000000	0x0000000000000091	 
0x5be9d0e192a0	0x0000000000000000	0x0000000000000000
0x5be9d0e192b0	0x0000000000000000	0x0000000000000000
0x5be9d0e192c0	0x0000000000000000	0x0000000000000000
0x5be9d0e192d0	0x0000000000000000	0x0000000000000000
0x5be9d0e192e0	0x0000000000000000	0x0000000000000000
0x5be9d0e192f0	0x0000000000000000	0x0000000000000000
0x5be9d0e19300	0x0000000000000000	0x0000000000000000
0x5be9d0e19310	0x0000000000000000	0x0000000000000000
```

As you can see, we can create a fake chunk with `fd` & `bk` but without any `prev_size` / `size` fields, but that doesn't matter when dealing with small bins because small bins don't care about them, just about the `fd` & `bk`.

# Small-bin linking hijack
After linking our three chunks into the unsorted bin, in such a way that the middle chunk in that list is the chunk at the same range of the fake chunk, and after heap feng shui to place the chunks metadata pointers in the tcache-bin instead of the userdata pointers, you should see something like this:

```
tcache chunk at heap start ==
                           ||
                           \/
0x5be9d0e19000	0x0000000000000000	0x0000000000000291
0x5be9d0e19010	0x0000000000000000	0x0007000000000000
0x5be9d0e19020	0x0000000000000000	0x0000000000000000
0x5be9d0e19030	0x0000000000000000	0x0000000000000000
0x5be9d0e19040	0x0000000000000000	0x0000000000000000
....
.....
______
# Fake chunk:
address: 0x5be9d0e19200
- fd: 0x5be9d0e193f0
- bk: 0x5be9d0e19340
----------------------------------------------------------
0x5be9d0e19200	0x0000000000000000	0x0000000000000000
0x5be9d0e19210	0x00005be9d0e193f0	0x00005be9d0e19340
0x5be9d0e19220	0x0000000000000000	0x0000000000000000
0x5be9d0e19230	0x0000000000000000	0x0000000000000000
0x5be9d0e19240	0x0000000000000000	0x0000000000000000
0x5be9d0e19250	0x0000000000000000	0x0000000000000000
0x5be9d0e19260	0x0000000000000000	0x0000000000000000
0x5be9d0e19270	0x0000000000000000	0x0000000000000000
0x5be9d0e19280	0x0000000000000000	0x0000000000000000
______
# Head chunk
address: 0x5be9d0e19290
- fd: 0x5be9d0e193f0
- bk: 0x5be9d0e19340
----------------------------------------------------------
0x5be9d0e19290	0x0000000000000000	0x0000000000000091 <-- unsortedbin[all][1]
0x5be9d0e192a0	0x00005be9d0e193f0	0x00005be9d0e19340
0x5be9d0e192b0	0x0000000000000000	0x0000000000000000
0x5be9d0e192c0	0x0000000000000000	0x0000000000000000
0x5be9d0e192d0	0x0000000000000000	0x0000000000000000
....
.....
```

Now both chunks fd & bk pointers are the same and point to the same chunk. 
The next step is to sort the three chunks into the small bin, which you can achieve by allocating a large chunk larger than these chunks, it will check each one in the unsorted bin and sort them into the small bin.

Then you should have something similar to this inside the smallbin:
```
     0x5be9d0e19340                 0x5be9d0e19290                 0x5be9d0e193f0
    ┌──────────────┐              ┌──────────────┐              ┌──────────────┐
    │  Chunk one   │              │  Head chunk  │              │  Chunk two   │
    │              │              │              │              │              │
    │  fd ─────────┼─────────────►│              │◄─────────────┤───────── bk  │
    │0x5be9d0e19290│              │              │              │0x5be9d0e19290│
    │              │              │              │              │              │
    │              │              │0x5be9d0e193f0|────── fd ───►│              │
    │              │              │              │              │              │
    │              |◄────── bk ───│0x5be9d0e19340│		|              │
    │              │              │              │              │              │
    │  bk          │              │              │              │          fd  │
    │0x735f44803ba0│              │              │              │0x735f44803ba0│
    └──────────────┘              └──────────────┘              └──────────────┘
              │                                                     │  
              └──────────────────── main_arena+224 ─────────────────┘
				    0x735f44803ba0


```

Now we will trigger our UAF primitive and overwrite the LSB of the fd of chunk one with 0x00 and the LSB of the bk of chunk two with 0x00. 
This achieves the same linked list, but instead of the head chunk we will get our fake chunk.

```
UAF Overwrite:
- chunk_one.fd LSB → 0x00 (0x5be9d0e19290 → 0x5be9d0e19200)
- chunk_two.bk LSB → 0x00 (0x5be9d0e19290 → 0x5be9d0e19200)
```
```
     0x5be9d0e19340                 0x5be9d0e19200                 0x5be9d0e193f0
    ┌──────────────┐              ┌──────────────┐              ┌──────────────┐
    │  Chunk one   │              │  Fake chunk  │              │  Chunk two   │
    │              │              │              │              │              │
    │  fd ─────────┼─────────────►│              │◄─────────────┤───────── bk  │
    │0x5be9d0e19200│              │              │              │0x5be9d0e19200│
    │*corrupted fd*│              │              │              │*corrupted bk*│
    │              │              │0x5be9d0e193f0|────── fd ───►│              │
    │              │              │              │              │              │
    │              |◄────── bk ───│0x5be9d0e19340│		|              │
    │              │              │              │              │              │
    │  bk          │              │              │              │          fd  │
    │0x735f44803ba0│              │              │              │0x735f44803ba0│
    └──────────────┘              └──────────────┘              └──────────────┘
              │                                                     │  
              └──────────────────── main_arena+224 ─────────────────┘
				    0x735f44803ba0


*Unlinked from the smallbin*

     0x5be9d0e19290 
    ┌──────────────┐
    │  Head chunk  │
    │              │
    │              |
    │              │ 
    │      fd      │ 
    │0x5be9d0e193f0│ 
    │              │ 
    │              |
    │              │ 
    │      bk      |
    │0x5be9d0e19340│ 
    └──────────────┘   

```

# Allocate the fake chunk
This is the final step, to allocate our fake chunk from the small bins we should first clean the tcache of the corresponding size of the small bin, then the next allocation of that size will move the linked list of the small bins chunks into the tcache bin and secure it with "protect pointers", after which we can allocate it from there and control the tcache structure.
