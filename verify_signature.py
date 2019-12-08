#!/usr/bin/env python3
import struct
import hashlib
import subprocess
import argparse

LENOVO_TPM_OEM_PEI_HEADER = b"\x4C\x00\x65\x00\x6E\x00\x6F\x00\x76\x00\x6F\x00\x54\x00\x70\x00\x6D\x00\x4F\x00\x65\x00\x6D\x00\x50\x00\x65\x00\x69"
PUB_KEY_HEADER = b"\x30\x81\x9D\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x81\x8B\x00\x30\x81\x87\x02\x81\x81"
PUB_KEY_FOOTER = b"\x02\x01\x03"  # this tells that exponent = 3
INTEL_IMAGE_HEADER = b"\xFF" * 16 + b"\x5a\xa5\xf0"

COLOR_OK = "\033[92m"
COLOR_BLUE = "\033[94m"
COLOR_WARN = "\033[93m"
COLOR_FAIL = "\033[91m"
COLOR_RESET = "\033[0m"

parser = argparse.ArgumentParser(description="Lenovo ThinkPad BIOS signature verification tool")
parser.add_argument("bios_file", help="BIOS file")
parser.add_argument("--sandy", help="Use if you have Intel Core 2nd/3rd generation ThinkPad", required=False, action='store_true')
args = parser.parse_args()

with open(args.bios_file, "rb") as f:
    data = f.read()

if args.sandy:
    print(COLOR_WARN + "Using Sandy/Ivy Bridge compatibility mode" + COLOR_RESET)
    data = data[72:]
elif data[0:19] == INTEL_IMAGE_HEADER:
    print(COLOR_BLUE + "Broadwell BIOS image detected!" + COLOR_RESET)
    # Truncate ME firmware and other Intel's shit, I only want the BIOS region
    data = data[10485760:]

tcpa_offset = data.find(b"TCPABIOS")
if tcpa_offset == -1:
    print(COLOR_FAIL + "Could not find TCPABIOS section" + COLOR_RESET)
    exit(1)

print("Found TCPABIOS section")

hash_offset = tcpa_offset + 32
hash = data[hash_offset:hash_offset + 20].hex()

print("Hash found:", hash)

size_offset = tcpa_offset + 56
size = struct.unpack('<q', data[size_offset:size_offset + 3] + b"\x00\x00\x00\x00\x00")[0]  # the easiest way, not the best

print("Calculating hash")

calculated_hash = hashlib.sha1(data[:size]).hexdigest()

if hash == calculated_hash:
    print(COLOR_OK + "Hashes match!" + COLOR_RESET)
else:
    print(COLOR_FAIL + "Hashes do not match!" + COLOR_RESET)
    print("Calculated hash:", calculated_hash)

print("Veryfing signature")

tcpa_hash = hashlib.sha1(data[tcpa_offset:tcpa_offset + 107]).hexdigest()

signature_offset = tcpa_offset + 110
signature = data[signature_offset:signature_offset + 128]

if args.sandy:
    modulus_offset = data.find(b"\xFF" * 16 + b"\x12\x04") + 18
else:
    lenovo_pei_offset = data.find(LENOVO_TPM_OEM_PEI_HEADER)
    modulus_offset = lenovo_pei_offset + 82

modulus = data[modulus_offset:modulus_offset + 129]

with open("pub_key.der", "wb") as f:
    f.write(PUB_KEY_HEADER + modulus + PUB_KEY_FOOTER)
    f.close()

with open("tcpa_sign", "wb") as f:
    f.write(signature)
    f.close()

sub = subprocess.Popen(["openssl", "rsautl", "-verify", "-inkey", "pub_key.der", "-in", "tcpa_sign", "-pubin", "-keyform", "der", "-raw"],
                       stdout=subprocess.PIPE)

recovered_hash = sub.stdout.read().hex()[-len(tcpa_hash):]

if recovered_hash == tcpa_hash:
    print(COLOR_OK + "Signature is valid!")
else:
    print(COLOR_FAIL + "Signature is NOT valid!")
