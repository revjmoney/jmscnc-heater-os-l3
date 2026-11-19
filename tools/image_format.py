"""Bounded, metadata-preserving support for Bitmain legacy uImage/newc rootfs."""
import gzip
import io
import pathlib
import struct
import zlib
from dataclasses import dataclass

MAX_IMAGE = 64 * 1024 * 1024
MAX_ROOTFS = 128 * 1024 * 1024


@dataclass
class Entry:
    name: str
    fields: list
    data: bytes


def unpack_image(blob):
    if len(blob) < 64 or len(blob) > MAX_IMAGE:
        raise ValueError("Invalid image size")
    header = list(struct.unpack(">7I4B32s", blob[:64]))
    if header[0] != 0x27051956 or header[7:11] != [5, 2, 3, 1]:
        raise ValueError("Expected Linux ARM gzip ramdisk uImage")
    checked = bytearray(blob[:64])
    checked[4:8] = bytes(4)
    if zlib.crc32(checked) & 0xffffffff != header[1]:
        raise ValueError("uImage header CRC mismatch")
    payload = blob[64:64 + header[3]]
    if len(payload) != header[3] or zlib.crc32(payload) & 0xffffffff != header[6]:
        raise ValueError("uImage payload CRC mismatch")
    with gzip.GzipFile(fileobj=io.BytesIO(payload)) as gz:
        rootfs = gz.read(MAX_ROOTFS + 1)
    if len(rootfs) > MAX_ROOTFS:
        raise ValueError("Rootfs exceeds size limit")
    return header, read_cpio(rootfs)


def safe_name(name):
    if name.startswith("./"):
        name = name[2:]
    if name == ".":
        return name
    p = pathlib.PurePosixPath(name)
    if not name or p.is_absolute() or ".." in p.parts or "\\" in name or "\x00" in name:
        raise ValueError("Unsafe cpio name")
    return str(p)


def read_cpio(data):
    result = []
    seen = set()
    offset = 0
    while offset + 110 <= len(data):
        magic = data[offset:offset + 6]
        if magic not in (b"070701", b"070702"):
            raise ValueError("Expected newc cpio")
        fields = [int(data[offset + 6 + i * 8:offset + 14 + i * 8], 16) for i in range(13)]
        size, namesize = fields[6], fields[11]
        offset += 110
        if not 1 <= namesize <= 4096 or offset + namesize > len(data):
            raise ValueError("Invalid cpio filename")
        raw_name = data[offset:offset + namesize]
        if raw_name[-1:] != b"\0":
            raise ValueError("Unterminated cpio filename")
        name = safe_name(raw_name[:-1].decode("utf-8"))
        offset = (offset + namesize + 3) & ~3
        if offset + size > len(data):
            raise ValueError("Truncated cpio member")
        contents = data[offset:offset + size]
        offset = (offset + size + 3) & ~3
        if magic == b"070702" and sum(contents) & 0xffffffff != fields[12]:
            raise ValueError("Cpio checksum mismatch")
        if name == "TRAILER!!!":
            return result
        if name in seen:
            raise ValueError("Duplicate cpio path: " + name)
        seen.add(name)
        result.append(Entry(name, fields, contents))
        if len(result) > 50000:
            raise ValueError("Too many rootfs entries")
    raise ValueError("Missing cpio trailer")


def write_cpio(entries):
    out = bytearray()
    trailer = Entry("TRAILER!!!", [0] * 13, b"")
    for entry in list(entries) + [trailer]:
        safe_name(entry.name)
        name = entry.name.encode("utf-8") + b"\0"
        fields = list(entry.fields)
        fields[6], fields[11], fields[12] = len(entry.data), len(name), 0
        out.extend(b"070701" + b"".join(("%08x" % n).encode("ascii") for n in fields))
        out.extend(name)
        out.extend(bytes((-len(out)) % 4))
        out.extend(entry.data)
        out.extend(bytes((-len(out)) % 4))
    out.extend(bytes((-len(out)) % 512))
    return bytes(out)


def pack_image(header, entries):
    compressed = gzip.compress(write_cpio(entries), compresslevel=9, mtime=0)
    h = list(header)
    h[1] = 0
    h[3] = len(compressed)
    h[6] = zlib.crc32(compressed) & 0xffffffff
    raw = struct.pack(">7I4B32s", *h)
    h[1] = zlib.crc32(raw) & 0xffffffff
    return struct.pack(">7I4B32s", *h) + compressed


def put(entries, name, data, mode=0o100644):
    name = safe_name(name)
    for parent in reversed(pathlib.PurePosixPath(name).parents):
        p = str(parent)
        if p != "." and not any(e.name == p for e in entries):
            put(entries, p, b"", 0o40755)
    old = next((e for e in entries if e.name == name), None)
    if old:
        old.data = data
        old.fields[1] = mode
        old.fields[4] = 1
    else:
        fields = [0] * 13
        fields[0] = max([e.fields[0] for e in entries] or [0]) + 1
        fields[1], fields[4] = mode, 1
        entries.append(Entry(name, fields, data))
