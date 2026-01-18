# House of Water - RCE with no brute-force

The House of Water is a technique for gaining a stronger primitive of control over the tcache from "weak ones" e.g. double free, heap overflow, or UAF-write.
The technique bypasses safe linking (pointer mangling) of the tcache by focusing not on overwriting tcache pointers, but on crafting a fake chunk inside the tcache structure itself, 
specifically by creating a fake size field using the tcache counts and crafting valid fake `fd` and `bk` pointers using a vulnerability described earlier and set to point to the chunks in the target bin list before linking them into it.

This technique results in a strong primitive that provides control over the tcache structure along with a "bonus" of two libc pointers that casually appear from the unlinking process and end up in the tcache entries.
The bonus can be leveraged to achieve RCE as described in [this article.](https://corgi.rip/posts/leakless_heap_1/)
That article demonstrates how to achieve RCE by using one of the libc pointers that landed in the tcache bins and modifying it to point directly to the stdout structure. 
Then forces a libc leak and use the other pointer to craft an FSOP attack to gain full RCE over the target binary.

However, one drawback of the House of Water technique is that it already requires brute-forcing `1/16` bits of entropy to successfully link the fake chunk from the tcache to the bin list.
Additionally, the RCE method described in the blog requires another `1/16` bits of entropy leading to a combined `1/256` chance of success - about `0.4%`...
It would therefore be ideal to remove this second `1/16` bits of entropy to achieve a clean RCE without any extra brute-forcing beyond the original technique.

The idea is simply to move the libc pointers to larger bins from the `0x20` and `0x30`, for example to larger ones like `0x3e0` and `0x3f0`. 
This way the allocation sizes will overlap the stdout structure so we won’t need to edit these libc pointers and thus avoid brute-forcing ASLR-controlled bits.
This can be done by allocating a chunk of a size that shrinks the `0x10001` chunk to have an `fd` on `0x3e0` and a `bk` on `0x3f0`, allowing us to allocate libc pointers from those bins and overlap the stdout file structure easily without any brute force.
