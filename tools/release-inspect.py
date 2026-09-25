#!/usr/bin/env python3
"""Inspect a release binary and check it is what the release script meant to build.

Usage:
  tools/release-inspect.py FILE --format elf|macho|pe --arch ARCH
                                [--static|--dynamic] [--stripped]
  tools/release-inspect.py FILE            # just describe it

ARCH is the Rust target's architecture as `tools/release.sh` spells it: x86_64, aarch64,
armv7, arm, i686.

`tools/release.sh` calls this on every binary it packages, because a cross-build can go wrong
in ways that still produce a file: the wrong architecture (a stale artifact from another
target directory), a musl target that ended up dynamically linked (then it needs an interpreter
that an Alpine-less host may not have, which is the one thing the musl fallback exists to
promise), a gnu target that came out *static* (then it is not what the glibc flavour is for,
which is to run against the host's glibc and its `malloc_trim` - D07), or an unstripped binary
(the release profile sets
`strip = true`, D24). None of that is visible without reading the headers, and the usual tools
are not portable: macOS has no `readelf`, `file` reports ELF details differently on every
platform, and `otool`/`dumpbin` exist on one platform each. So the three formats a release
produces are parsed here directly; it is only ever the header, never the whole file.

Exit status: 0 if every requested check passed, 1 otherwise (the reason goes to stderr).
"""

import argparse
import struct
import sys

# --------------------------------------------------------------------------------------------
# ELF (Linux, FreeBSD)
# --------------------------------------------------------------------------------------------

# e_machine values (ELF spec); only the ones a kcptun release target uses.
EM = {3: "i686", 40: "arm", 62: "x86_64", 183: "aarch64"}
PT_INTERP = 3
PT_DYNAMIC = 2
DT_NULL = 0
DT_NEEDED = 1


class Bad(Exception):
    """The file is not the format it was claimed to be, or is truncated."""


def read_elf(data):
    """Parse the parts of an ELF header a release cares about.

    Returns a dict with `format`, `arch`, `class`, `interp` (bool), `needed` (list of
    library-name string-table offsets - only whether there are any matters here), `stripped`
    and `kind` (EXEC / DYN).
    """
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise Bad("not an ELF file")
    bits = {1: 32, 2: 64}.get(data[4])
    endian = {1: "<", 2: ">"}.get(data[5])
    if bits is None or endian is None:
        raise Bad(f"bad ELF class/endianness: {data[4]}/{data[5]}")
    if endian != "<":
        # Every target in D22 is little-endian; a big-endian one would need MIPS support.
        raise Bad("big-endian ELF is not a release target")

    if bits == 64:
        (e_type, e_machine, _, _, e_phoff, e_shoff) = struct.unpack_from("<HHIQQQ", data, 16)
        (e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
            "<HHHHH", data, 54
        )
    else:
        (e_type, e_machine, _, _, e_phoff, e_shoff) = struct.unpack_from("<HHIIII", data, 16)
        (e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
            "<HHHHH", data, 42
        )

    interp = False
    needed = 0
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            raise Bad("program header table is past the end of the file")
        if bits == 64:
            (p_type, _, p_offset, _, _, p_filesz) = struct.unpack_from("<IIQQQQ", data, off)
        else:
            (p_type, p_offset, _, _, p_filesz) = struct.unpack_from("<IIIII", data, off)
        if p_type == PT_INTERP:
            interp = True
        elif p_type == PT_DYNAMIC:
            needed += count_dt_needed(data, bits, p_offset, p_filesz)

    return {
        "format": "elf",
        "arch": EM.get(e_machine, f"unknown(e_machine={e_machine})"),
        "bits": bits,
        "kind": {1: "REL", 2: "EXEC", 3: "DYN"}.get(e_type, str(e_type)),
        "interp": interp,
        "needed": needed,
        "stripped": not elf_has_symtab(data, bits, e_shoff, e_shentsize, e_shnum, e_shstrndx),
    }


def count_dt_needed(data, bits, offset, size):
    """Count DT_NEEDED entries in a PT_DYNAMIC segment: the shared libraries required."""
    entry = 16 if bits == 64 else 8
    fmt = "<Qq" if bits == 64 else "<Ii"
    n = 0
    for off in range(offset, min(offset + size, len(data) - entry + 1), entry):
        (d_tag, _) = struct.unpack_from(fmt, data, off)
        if d_tag == DT_NULL:
            break
        if d_tag == DT_NEEDED:
            n += 1
    return n


def elf_has_symtab(data, bits, e_shoff, e_shentsize, e_shnum, e_shstrndx):
    """Whether the file still carries a `.symtab` section, i.e. was *not* stripped."""
    if e_shoff == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
        return False  # no section headers at all: stripped as far as this matters
    # The section-header string table, to read section names from.
    strtab_hdr = e_shoff + e_shstrndx * e_shentsize
    if strtab_hdr + e_shentsize > len(data):
        raise Bad("section header table is past the end of the file")
    if bits == 64:
        (_, _, _, _, str_off, str_size) = struct.unpack_from("<IIQQQQ", data, strtab_hdr)
    else:
        (_, _, _, _, str_off, str_size) = struct.unpack_from("<IIIIII", data, strtab_hdr)
    names = data[str_off : str_off + str_size]

    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if off + e_shentsize > len(data):
            raise Bad("section header table is past the end of the file")
        (sh_name,) = struct.unpack_from("<I", data, off)
        end = names.find(b"\0", sh_name)
        if names[sh_name:end] == b".symtab":
            return True
    return False


# --------------------------------------------------------------------------------------------
# Mach-O (macOS)
# --------------------------------------------------------------------------------------------

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE  # big-endian in the file
CPU_TYPE = {0x01000007: "x86_64", 0x0100000C: "aarch64"}
LC_LOAD_DYLIB = 0x0C


def read_macho(data):
    """Parse a thin or universal Mach-O: architectures and the dylibs it needs."""
    if len(data) < 32:
        raise Bad("not a Mach-O file")
    (be_magic,) = struct.unpack_from(">I", data, 0)
    if be_magic in (FAT_MAGIC, 0xCAFEBABF):
        # A universal binary (`lipo -create`): describe every slice.
        (nfat,) = struct.unpack_from(">I", data, 4)
        arches, dylibs = [], set()
        wide = be_magic == 0xCAFEBABF
        for i in range(nfat):
            # fat_arch:    cputype:i32 cpusubtype:i32 offset:u32 size:u32 align:u32   (20 bytes)
            # fat_arch_64: cputype:i32 cpusubtype:i32 offset:u64 size:u64 align:u32
            #              reserved:u32                                              (32 bytes)
            off = 8 + i * (32 if wide else 20)
            if wide:
                (cputype, _, offset, _, _, _) = struct.unpack_from(">iiQQII", data, off)
            else:
                (cputype, _, offset, _, _) = struct.unpack_from(">iiIII", data, off)
            slice_info = read_macho(data[offset:])
            arches.append(slice_info["arch"])
            dylibs |= set(slice_info["dylibs"])
            _ = cputype
        return {
            "format": "macho",
            "arch": "+".join(arches),
            "universal": True,
            "dylibs": sorted(dylibs),
        }

    (magic,) = struct.unpack_from("<I", data, 0)
    if magic != MH_MAGIC_64:
        raise Bad(f"not a 64-bit Mach-O file (magic {magic:#x})")
    (cputype, _, _, ncmds, _, _) = struct.unpack_from("<iiiIII", data, 4)
    dylibs = []
    off = 32
    for _ in range(ncmds):
        if off + 8 > len(data):
            raise Bad("load commands are past the end of the file")
        (cmd, cmdsize) = struct.unpack_from("<II", data, off)
        if cmdsize < 8:
            raise Bad("bad load-command size")
        if cmd == LC_LOAD_DYLIB:
            (name_off,) = struct.unpack_from("<I", data, off + 8)
            raw = data[off + name_off : off + cmdsize]
            dylibs.append(raw.split(b"\0", 1)[0].decode("utf-8", "replace"))
        off += cmdsize
    return {
        "format": "macho",
        "arch": CPU_TYPE.get(cputype & 0xFFFFFFFF, f"unknown(cputype={cputype:#x})"),
        "universal": False,
        "dylibs": dylibs,
    }


# --------------------------------------------------------------------------------------------
# PE (Windows)
# --------------------------------------------------------------------------------------------

PE_MACHINE = {0x8664: "x86_64", 0xAA64: "aarch64", 0x014C: "i686"}


def read_pe(data):
    """Parse the COFF header of a PE executable: the machine it targets."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise Bad("not a PE file (no MZ header)")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise Bad("not a PE file (no PE signature)")
    (machine, _, _, _, _, _, characteristics) = struct.unpack_from(
        "<HHIIIHH", data, e_lfanew + 4
    )
    return {
        "format": "pe",
        "arch": PE_MACHINE.get(machine, f"unknown(machine={machine:#x})"),
        "executable": bool(characteristics & 0x0002),  # IMAGE_FILE_EXECUTABLE_IMAGE
    }


# --------------------------------------------------------------------------------------------


def describe(info):
    """A one-line summary, the line `tools/release.sh` prints for every packaged binary."""
    if info["format"] == "elf":
        link = "static" if not info["interp"] and info["needed"] == 0 else "dynamic"
        strip = "stripped" if info["stripped"] else "with symbols"
        return f"ELF{info['bits']} {info['arch']} {info['kind']}, {link}, {strip}"
    if info["format"] == "macho":
        kind = "universal" if info["universal"] else "thin"
        libs = ", ".join(info["dylibs"]) or "none"
        return f"Mach-O {kind} {info['arch']}, dylibs: {libs}"
    return f"PE {info['arch']}" + ("" if info["executable"] else " (not an executable image)")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("file")
    ap.add_argument("--format", choices=("elf", "macho", "pe"), help="required file format")
    ap.add_argument("--arch", help="required architecture (x86_64, aarch64, armv7, arm, i686)")
    ap.add_argument(
        "--static", action="store_true", help="ELF only: require no interpreter and no DT_NEEDED"
    )
    ap.add_argument(
        "--dynamic",
        action="store_true",
        help="ELF only: require an interpreter (the default gnu/glibc artifacts, D07)",
    )
    ap.add_argument("--stripped", action="store_true", help="ELF only: require no .symtab")
    args = ap.parse_args()

    with open(args.file, "rb") as fh:
        data = fh.read()

    readers = {"elf": read_elf, "macho": read_macho, "pe": read_pe}
    try:
        if args.format:
            info = readers[args.format](data)
        else:
            for reader in readers.values():
                try:
                    info = reader(data)
                    break
                except Bad:
                    continue
            else:
                raise Bad("not an ELF, Mach-O or PE file")
    except Bad as exc:
        print(f"release-inspect: {args.file}: {exc}", file=sys.stderr)
        return 1

    print(f"{args.file}: {describe(info)}")

    problems = []
    if args.arch:
        # armv7 and arm are both EM_ARM; the ELF header cannot tell them apart without reading
        # the build attributes, so accept `arm` for either and let the archive name carry it.
        want = {"armv7": "arm"}.get(args.arch, args.arch)
        if info["arch"] != want:
            problems.append(f"architecture is {info['arch']}, expected {want}")
    if args.static:
        if info["format"] != "elf":
            problems.append("--static only applies to ELF binaries")
        elif info["interp"] or info["needed"]:
            problems.append(
                f"not statically linked (interpreter: {info['interp']}, "
                f"DT_NEEDED entries: {info['needed']})"
            )
    if args.dynamic:
        if info["format"] != "elf":
            problems.append("--dynamic only applies to ELF binaries")
        elif not info["interp"]:
            problems.append("statically linked, expected a dynamically linked binary")
    if args.stripped and info["format"] == "elf" and not info["stripped"]:
        problems.append("not stripped (.symtab is present)")

    for p in problems:
        print(f"release-inspect: {args.file}: {p}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
