import string
import itertools
import binascii

def generate_pattern(length):
    pattern = ''.join(''.join(p) for p in itertools.product(string.ascii_uppercase, string.ascii_lowercase, string.digits))
    return pattern[:length]

def find_offset(crash_string):
    pattern = ''.join(''.join(p) for p in itertools.product(string.ascii_uppercase, string.ascii_lowercase, string.digits))
    try:
        return pattern.index(crash_string)
    except ValueError:
        return -1

def hex_to_ascii(hex_str):
    try:
        return binascii.unhexlify(hex_str).decode('latin-1')[::-1]
    except (binascii.Error, UnicodeDecodeError):
        return None

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Buffer Overflow Offset Generator")
    parser.add_argument("-g", "--generate", type=int, help="Generate a cyclic pattern of given length")
    parser.add_argument("-o", "--offset", type=str, help="Find offset of crash string (can be hex like 0x37634136)")
    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
    elif args.generate:
        print(generate_pattern(args.generate))
    elif args.offset:
        if args.offset.startswith("0x"):
            args.offset = hex_to_ascii(args.offset[2:])
        if args.offset:
            offset = find_offset(args.offset)
            if offset != -1:
                print(f"Offset found at: {offset}")
            else:
                print("Pattern not found in generated sequence.")
        else:
            print("Invalid hex string provided.")

