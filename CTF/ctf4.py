import sys
import re
from PIL import Image

def extract_lsb(filepath):
    img = Image.open(filepath)
    pixels = list(img.getdata())
    bits = []
    for i in pixels:
        bits.append(i & 1)
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = bits[i:i + 8]
        val = int(''.join(str(b) for b in byte), 2)
        if val == 0: 
            break
        chars.append(chr(val) if 32 <= val <= 126 else '\x00')
    message = ''.join(chars).rstrip('\x00')
    print(f" message:   {message}")
    return message


def main():
    filepath = sys.argv[1] if len(sys.argv) > 1 else "stego.png"
    extract_lsb(filepath)

if __name__ == "__main__":
    main()