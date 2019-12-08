#!/usr/bin/env python3
import argparse
import struct
import hashlib
import subprocess
import binascii

LENOVO_TPM_OEM_PEI_HEADER = b"\x4C\x00\x65\x00\x6E\x00\x6F\x00\x76\x00\x6F\x00\x54\x00\x70\x00\x6D\x00\x4F\x00\x65\x00\x6D\x00\x50\x00\x65\x00\x69"
INTEL_IMAGE_HEADER = b"\xFF" * 16 + b"\x5a\xa5\xf0"
BROADWELL_BIOS_REGION_OFFSET = 10485760

COLOR_OK = "\033[92m"
COLOR_BLUE = "\033[94m"
COLOR_WARN = "\033[93m"
COLOR_FAIL = "\033[91m"
COLOR_RESET = "\033[0m"

parser = argparse.ArgumentParser(description="Lenovo ThinkPad BIOS signature verification tool")
parser.add_argument("bios_file", help="BIOS file")
parser.add_argument("output_file", help="Output file")
parser.add_argument("--sandy", help="Use if you have Intel Core 2nd/3rd generation ThinkPad", required=False, action='store_true')
args = parser.parse_args()

with open(args.bios_file, "rb") as f:
    data = bytearray(f.read())

if data[0:19] == INTEL_IMAGE_HEADER:
    print(COLOR_BLUE + "Broadwell BIOS image detected!" + COLOR_RESET)
    garbage = data[:BROADWELL_BIOS_REGION_OFFSET]  # I will need this later
    data = data[BROADWELL_BIOS_REGION_OFFSET:]
elif args.sandy:
    print(COLOR_WARN + "Using Sandy/Ivy Bridge compatibility mode" + COLOR_RESET)
    garbage = data[:72]
    data = data[72:]
else:
    garbage = b""

tcpa_offset = data.find(b"TCPABIOS")
if tcpa_offset == -1:
    print(COLOR_FAIL + "Could not find TCPABIOS section" + COLOR_RESET)
    exit(1)

modulus_offset = -1

if args.sandy:
    x = data.find(b"\xFF" * 16 + b"\x12\x04")
    if x != -1:
        modulus_offset = x + 18
else:
    x = data.find(LENOVO_TPM_OEM_PEI_HEADER)
    if x != -1:
        modulus_offset = x + 82
del x

if modulus_offset == -1:
    print(COLOR_FAIL + "Could not find modulus" + COLOR_RESET)

print("[1/6] Calculating hash")

size_offset = tcpa_offset + 56
size = struct.unpack('<q', data[size_offset:size_offset + 3] + b"\x00\x00\x00\x00\x00")[0]  # the easiest way, not the best
hash = hashlib.sha1(data[:size]).hexdigest()

print("[2/6] Replacing hash")

data[tcpa_offset + 32:tcpa_offset + 52] = binascii.unhexlify(hash)

print("[3/6] Generating private key")

subprocess.Popen(["openssl", "genrsa", "-3", "-out", "my_key.pem", "1024"]).wait()

print("[4/6] Signing TCPA block")

tcpa_hash = hashlib.sha1(data[tcpa_offset:tcpa_offset + 107]).hexdigest()
p = subprocess.Popen(["openssl", "rsautl", "-inkey", "my_key.pem", "-sign", "-raw"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
p.stdin.write(b"\x00" * 108 + binascii.unhexlify(tcpa_hash))
p.stdin.close()
tcpa_signature = p.stdout.read()

print("[5/6] Replacing signature")

data[tcpa_offset + 110:tcpa_offset + 238] = tcpa_signature

print("[6/6] Replacing modulus")

p = subprocess.Popen(["openssl", "rsa", "-in", "my_key.pem", "-outform", "der", "-pubout"], stdout=subprocess.PIPE)
pubkey = p.stdout.read()
data[modulus_offset:modulus_offset + 129] = pubkey[28:157]

print(COLOR_BLUE + "Saving resulting file..." + COLOR_RESET)
with open(args.output_file, "wb") as f:
    f.write(garbage + data)

print(COLOR_OK + "Do what you want 'cause a pirate is free, you are a pirate! ( ͡° ͜ʖ ͡°)" + COLOR_RESET)
