#!/usr/bin/env python3
"""
Offline replica of lara/kexploit/pe/dylibbuild.m, for verifying the generated
Mach-O before spending a CI cycle on it.

This exists because the device is a terrible place to find out that a load
command is misaligned: choma rejects the image inside fat_init_from_path and
signdylib.m reports "fat_init_from_path failed (not a Mach-O?)", which reads
like "we built garbage" rather than "one field is 3 bytes off a multiple of 8".

Run:  python3 verify_dylib.py
It writes gen.dylib next to itself and prints every check.
"""

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# ---- constants, mirrored from dylibbuild.m -------------------------------
TEXT_SEG_VMADDR = 0x0000
TEXT_SEG_FILEOFF = 0x0000
TEXT_SEG_FILESIZE = 0x4000
TEXT_SECT_VMADDR = 0x1000
TEXT_SECT_FILEOFF = 0x1000
TEXT_SECT_SIZE = 0x1000
DATA_SEG_VMADDR = 0x4000
DATA_SEG_FILEOFF = 0x4000
DATA_SEG_FILESIZE = 0x4000
IMAGE_SIZE = 0x10000
SIG_FILEOFF = 0xF000
SIG_FILESIZE = 0x1000
LARA_DYLIB_GLOBAL_OFF = 0x0  # was 0x4000 -> global landed past end of image
LARA_DYLIB_MAGIC = 0x10BADF00D
DYLIB_ID = "com.roooot.lara.dylibtest"
LIBSYSTEM = "/usr/lib/libSystem.B.dylib"

VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE = 1, 2, 4

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64_ALL = 0
MH_DYLIB = 6

LC_SEGMENT_64 = 0x19
LC_ID_DYLIB = 0x0D
LC_LOAD_DYLIB = 0x0C
LC_MAIN = 0x80000028
LC_BUILD_VERSION = 0x32
LC_DYLD_INFO_ONLY = 0x80000022
LC_CODE_SIGNATURE = 0x1D
PLATFORM_IOS = 2


def cmd_align8(n):
    """Every 64-bit load command's cmdsize must be a multiple of 8."""
    return (n + 7) & ~7


class Image:
    def __init__(self):
        self.buf = bytearray(IMAGE_SIZE)

    def u32(self, off, val):
        struct.pack_into("<I", self.buf, off, val & 0xFFFFFFFF)

    def u64(self, off, val):
        struct.pack_into("<Q", self.buf, off, val & 0xFFFFFFFFFFFFFFFF)

    def bytes_at(self, off, data):
        self.buf[off:off + len(data)] = data


def build():
    img = Image()
    commands = []  # (name, cmdsize, start_off)

    # ---- mach_header_64 ----
    img.u32(0, MH_MAGIC_64)
    img.u32(4, CPU_TYPE_ARM64)
    img.u32(8, CPU_SUBTYPE_ARM64_ALL)
    img.u32(12, MH_DYLIB)
    img.u32(16, 0)  # ncmds, patched later
    img.u32(20, 0)  # sizeofcmds, patched later
    img.u32(24, 0)  # flags
    img.u32(28, 0)  # reserved

    lc = 32  # sizeof(mach_header_64)

    # ---- LC_SEGMENT_64 __TEXT (one section: __text) ----
    text_cmdsize = 72 + 80
    img.u32(lc + 0, LC_SEGMENT_64)
    img.u32(lc + 4, text_cmdsize)
    img.bytes_at(lc + 8, b"__text".ljust(16, b"\0"))
    img.u64(lc + 24, TEXT_SEG_VMADDR)
    img.u64(lc + 32, TEXT_SEG_FILESIZE)
    img.u64(lc + 40, TEXT_SEG_FILEOFF)
    img.u64(lc + 48, TEXT_SEG_FILESIZE)
    img.u32(lc + 56, VM_PROT_READ | VM_PROT_EXECUTE)
    img.u32(lc + 60, VM_PROT_READ | VM_PROT_EXECUTE)
    img.u32(lc + 64, 1)  # nsects
    img.u32(lc + 68, 0)  # flags
    s = lc + 72
    img.bytes_at(s, b"__text".ljust(16, b"\0"))
    img.bytes_at(s + 16, b"__TEXT".ljust(16, b"\0"))
    img.u64(s + 32, TEXT_SECT_VMADDR)
    img.u64(s + 40, TEXT_SECT_SIZE)
    img.u32(s + 48, TEXT_SECT_FILEOFF)
    img.u32(s + 52, 4)   # align
    img.u32(s + 56, 0)   # reloff
    img.u32(s + 60, 0)   # nreloc
    img.u32(s + 64, 0)   # flags (S_REGULAR)
    img.u32(s + 68, 0)   # reserved1
    img.u32(s + 72, 0)   # reserved2
    img.u32(s + 76, 0)   # reserved3
    commands.append(("LC_SEGMENT_64 __TEXT", text_cmdsize, lc))
    lc += text_cmdsize

    # ---- LC_SEGMENT_64 __DATA (no sections; the magic global lives here) ----
    data_cmdsize = 72
    img.u32(lc + 0, LC_SEGMENT_64)
    img.u32(lc + 4, data_cmdsize)
    img.bytes_at(lc + 8, b"__DATA".ljust(16, b"\0"))
    img.u64(lc + 24, DATA_SEG_VMADDR)
    img.u64(lc + 32, DATA_SEG_FILESIZE)
    img.u64(lc + 40, DATA_SEG_FILEOFF)
    img.u64(lc + 48, DATA_SEG_FILESIZE)
    img.u32(lc + 56, VM_PROT_READ | VM_PROT_WRITE)
    img.u32(lc + 60, VM_PROT_READ | VM_PROT_WRITE)
    img.u32(lc + 64, 0)  # nsects
    img.u32(lc + 68, 0)  # flags
    commands.append(("LC_SEGMENT_64 __DATA", data_cmdsize, lc))
    lc += data_cmdsize

    # ---- LC_ID_DYLIB ----
    idlen = len(DYLIB_ID) + 1
    cmdsize = cmd_align8(24 + idlen)
    img.u32(lc + 0, LC_ID_DYLIB)
    img.u32(lc + 4, cmdsize)
    img.u64(lc + 8, 24)  # dylib.name: file offset, string lives inside this cmd
    img.u32(lc + 16, 0x10000)  # timestamp
    img.u32(lc + 20, 0)        # current_version
    img.u32(lc + 24, 0x10000)  # compatibility_version
    img.bytes_at(lc + 24, DYLIB_ID.encode() + b"\0")
    commands.append(("LC_ID_DYLIB", cmdsize, lc))
    lc += cmdsize

    # ---- LC_LOAD_DYLIB libSystem.B.dylib ----
    deplen = len(LIBSYSTEM) + 1
    cmdsize = cmd_align8(24 + deplen)
    img.u32(lc + 0, LC_LOAD_DYLIB)
    img.u32(lc + 4, cmdsize)
    img.u64(lc + 8, 24)  # dylib.name: file offset, string lives inside this cmd
    img.u32(lc + 16, 0x10000)
    img.u32(lc + 20, 0x10000)
    img.u32(lc + 24, 0x10000)
    img.bytes_at(lc + 24, LIBSYSTEM.encode() + b"\0")
    commands.append(("LC_LOAD_DYLIB libSystem", cmdsize, lc))
    lc += cmdsize

    # ---- LC_MAIN (entry_point_command is 24 bytes, already 8-aligned) ----
    cmdsize = 24
    img.u32(lc + 0, LC_MAIN)
    img.u32(lc + 4, cmdsize)
    img.u64(lc + 8, TEXT_SECT_VMADDR)  # entryoff
    img.u64(lc + 16, 0)                # stacksize
    commands.append(("LC_MAIN", cmdsize, lc))
    lc += cmdsize

    # ---- LC_BUILD_VERSION (fixed 24 bytes + 6 per tool; ntools = 0 -> 24) ----
    cmdsize = 24
    img.u32(lc + 0, LC_BUILD_VERSION)
    img.u32(lc + 4, cmdsize)
    img.u32(lc + 8, PLATFORM_IOS)
    img.u32(lc + 12, 0x000E0000)  # minos 14.0
    img.u32(lc + 16, 0x000E0000)  # sdk 14.0
    img.u32(lc + 20, 0)           # ntools
    commands.append(("LC_BUILD_VERSION", cmdsize, lc))
    lc += cmdsize

    # ---- LC_DYLD_INFO_ONLY (all tables zeroed; no export trie) ----
    cmdsize = 48
    img.u32(lc + 0, LC_DYLD_INFO_ONLY)
    img.u32(lc + 4, cmdsize)
    for i in range(5):
        img.u32(lc + 8 + i * 8, 0)   # off
        img.u32(lc + 12 + i * 8, 0)  # size
    commands.append(("LC_DYLD_INFO_ONLY", cmdsize, lc))
    lc += cmdsize

    # ---- LC_CODE_SIGNATURE (placeholder region; choma overwrites it) ----
    cmdsize = 16
    img.u32(lc + 0, LC_CODE_SIGNATURE)
    img.u32(lc + 4, cmdsize)
    img.u32(lc + 8, SIG_FILEOFF)
    img.u32(lc + 12, SIG_FILESIZE)
    commands.append(("LC_CODE_SIGNATURE", cmdsize, lc))
    lc += cmdsize

    ncmds = len(commands)
    sizeofcmds = lc - 32
    img.u32(16, ncmds)
    img.u32(20, sizeofcmds)

    # dylib id and libSystem path are stored inline in their own load commands

    # ---- constructor: write the magic into the poisoned global ----
    # Mirrors build_ctor() in dylibbuild.m exactly, including the page-relative
    # ADRP: the delta is in 4 KiB pages between the code page and __DATA.
    target = DATA_SEG_VMADDR + LARA_DYLIB_GLOBAL_OFF
    code = TEXT_SECT_FILEOFF
    pc_page = code & ~0xFFF
    page_delta = (target - pc_page) >> 12
    immlo = page_delta & 0x3
    immhi = (page_delta >> 2) & 0x7FFFF
    img.u32(code + 0, 0x90000000 | (immlo << 29) | (immhi << 5))
    img.u32(code + 4, 0x91000000 | ((LARA_DYLIB_GLOBAL_OFF & 0xFFF) << 10) | 1)
    lo = LARA_DYLIB_MAGIC & 0xFFFF
    hi = (LARA_DYLIB_MAGIC >> 16) & 0xFFFF
    img.u32(code + 8, 0x52800000 | (lo << 5) | 2)
    img.u32(code + 12, 0x72A00000 | (hi << 5) | 2)
    img.u32(code + 16, 0xB9000020 | (1 << 5) | 2)
    img.u32(code + 20, 0xD65F03C0)  # ret

    img.u64(DATA_SEG_VMADDR + LARA_DYLIB_GLOBAL_OFF, 0xDEADBEEFDEADBEEF)

    return img.buf, ncmds, sizeofcmds, commands


def check(ncmds, sizeofcmds, commands, blob):
    ok = True

    def bad(msg):
        nonlocal ok
        ok = False
        print("  FAIL  " + msg)

    print("checks:")

    # --- the check that actually bit us (choma __macho_parse) ---
    # choma computes (cmdAlign - 1) & sizeofcmds and rejects if non-zero.
    if (8 - 1) & sizeofcmds:
        bad("sizeofcmds=%d is not a multiple of 8 -- choma will refuse this "
            "image and report 'not a Mach-O?'" % sizeofcmds)
    else:
        print("  ok    sizeofcmds=%d (multiple of 8)" % sizeofcmds)

    for name, size, _off in commands:
        if size % 8:
            bad("%s cmdsize=%d is not a multiple of 8" % (name, size))
    print("  ok    all %d individual cmdsize values are 8-aligned" % len(commands))

    # --- self-consistency ---
    total = sum(size for _n, size, _o in commands)
    if total != sizeofcmds:
        bad("sum of cmdsizes (%d) != sizeofcmds (%d)" % (total, sizeofcmds))
    else:
        print("  ok    sum of cmdsizes == sizeofcmds == %d" % sizeofcmds)

    if ncmds != len(commands):
        bad("ncmds=%d but %d commands emitted" % (ncmds, len(commands)))
    else:
        print("  ok    ncmds=%d matches emitted commands" % ncmds)

    # --- the command area must stay inside the header's declared extent ---
    end = 32 + sizeofcmds
    if end > len(blob):
        bad("load commands run past end of file (%d > %d)" % (end, len(blob)))
    else:
        print("  ok    load commands end at 0x%x, within the %d-byte image"
              % (end, len(blob)))

    # --- segment file ranges must be in bounds (dyld maps fileoff..+filesize) ---
    for name, size, off in commands:
        if name.startswith("LC_SEGMENT_64"):
            fileoff = struct.unpack_from("<Q", blob, off + 40)[0]
            filesize = struct.unpack_from("<Q", blob, off + 48)[0]
            if fileoff + filesize > len(blob):
                bad("%s file range 0x%x+0x%x exceeds the image" %
                    (name, fileoff, filesize))
            else:
                print("  ok    %s file range 0x%x+0x%x in bounds"
                      % (name, fileoff, filesize))

    # --- sections must lie inside their segment ---
    for name, size, off in commands:
        if name == "LC_SEGMENT_64 __TEXT":
            nsects = struct.unpack_from("<I", blob, off + 64)[0]
            seg_lo = struct.unpack_from("<Q", blob, off + 40)[0]
            seg_hi = seg_lo + struct.unpack_from("<Q", blob, off + 48)[0]
            for i in range(nsects):
                so = off + 72 + i * 80
                sa = struct.unpack_from("<Q", blob, so + 32)[0]
                sz = struct.unpack_from("<Q", blob, so + 40)[0]
                if sa < seg_lo or sa + sz > seg_hi:
                    bad("section %d (0x%x+0x%x) escapes its segment" % (i, sa, sz))
                else:
                    print("  ok    section %d 0x%x+0x%x inside __TEXT" % (i, sa, sz))

                # The u32 tail of section_64 is the easiest thing in this file
                # to get wrong, and a skew shows up as a bogus section type.
                soff = struct.unpack_from("<I", blob, so + 48)[0]
                salign = struct.unpack_from("<I", blob, so + 52)[0]
                sflags = struct.unpack_from("<I", blob, so + 64)[0]
                if sflags != 0:
                    bad("section %d flags=0x%x, expected S_REGULAR (0) -- the "
                        "u32 fields are skewed" % (i, sflags))
                else:
                    print("  ok    section %d offset=0x%x align=%d flags=S_REGULAR"
                          % (i, soff, salign))
                if soff + sz > len(blob):
                    bad("section %d file range 0x%x+0x%x exceeds the image"
                        % (i, soff, sz))
                else:
                    print("  ok    section %d file range 0x%x+0x%x in bounds"
                          % (i, soff, sz))

    # --- dylib names must be inline in their load command, offset 24 ---
    for name, size, off in commands:
        if name.startswith("LC_ID_DYLIB") or name.startswith("LC_LOAD_DYLIB"):
            noff = struct.unpack_from("<Q", blob, off + 8)[0]
            end = blob.index(b"\0", off + noff)
            text = blob[off + noff:end].decode()
            if noff >= size:
                bad("%s name.offset %d is outside its %d-byte command"
                    % (name, noff, size))
            elif not text:
                bad("%s name.offset %d resolves to an empty string" % (name, noff))
            else:
                print("  ok    %s name.offset=%d -> %r" % (name, noff, text))

    # --- choma's code-slot arithmetic (csd_code_directory_update_code_slots) ---
    #
    # csd_code_directory_init sets nCodeSlots = align_to_size(streamSize, 0x1000) >> 12,
    # i.e. it counts pages of the WHOLE file, not of __TEXT. For the last slot
    # code_directory_calculate_page_hash() then requires
    #     lastSlotOffset <= dataoff(from LC_CODE_SIGNATURE)
    # and returns failure (0) when that does not hold. get_image_base() treats
    # that 0 as an error, which is the "update_code_slots failed" we saw.
    sig = [c for c in commands if c[0] == "LC_CODE_SIGNATURE"]
    if not sig:
        bad("no LC_CODE_SIGNATURE: choma's page-hash bounds lookup returns "
            "dataoff=0 and the last code slot fails")
    else:
        dataoff = struct.unpack_from("<I", blob, sig[0][2] + 8)[0]
        datasize = struct.unpack_from("<I", blob, sig[0][2] + 12)[0]
        n_slots = ((len(blob) + 0xFFF) // 0x1000)
        last_off = (n_slots - 1) * 0x1000
        if last_off > dataoff:
            bad("last code slot at 0x%x > LC_CODE_SIGNATURE dataoff 0x%x -- "
                "choma will fail hashing it" % (last_off, dataoff))
        else:
            print("  ok    %d code slots, last at 0x%x <= dataoff 0x%x"
                  % (n_slots, last_off, dataoff))
        if dataoff + datasize > len(blob):
            bad("signature region 0x%x+0x%x exceeds the image"
                % (dataoff, datasize))
        else:
            print("  ok    signature region 0x%x+0x%x reserved in the image"
                  % (dataoff, datasize))
        if dataoff < DATA_SEG_VMADDR + DATA_SEG_FILESIZE:
            bad("signature region overlaps __DATA")

    return ok


def main():
    blob, ncmds, sizeofcmds, commands = build()

    with open(os.path.join(HERE, "gen.dylib"), "wb") as f:
        f.write(blob)

    print("built gen.dylib: %d bytes, ncmds=%d, sizeofcmds=%d (0x%x)\n"
          % (len(blob), ncmds, sizeofcmds, sizeofcmds))
    for name, size, off in commands:
        print("  0x%04x  %-28s cmdsize=%d" % (off, name, size))
    print()

    ok = check(ncmds, sizeofcmds, commands, blob)
    print()
    print("RESULT: " + ("all checks passed" if ok else "CHECKS FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
