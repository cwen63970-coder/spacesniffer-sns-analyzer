#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_example.py — generate a small synthetic .sns snapshot for testing.

Writes a valid SpaceSniffer snapshot (community-documented layout) so that
sns_analyze.py can be exercised without a real multi-GB export:

    python make_example.py example.sns
    python sns_analyze.py example.sns --output out --lang en
"""

import base64
import sys

T_ROOT, T_FILE, T_DIR = b'\x04\x01', b'\x04\x02', b'\x04\x03'
T_FREE, T_UNKNOWN = b'\x04\x04', b'\x04\x05'
MISC = 30  # unknown trailing bytes in the fixed payload


def write_node(out, kind, name, size, disk=None, children=()):
    """kind: b'\\x04\\x01' root | b'\\x04\\x02' file | b'\\x04\\x03' dir"""
    enc = base64.b64encode(name.encode('utf-16-le'))
    out += kind
    out += len(enc).to_bytes(4, 'little')
    out += enc
    out += int(size).to_bytes(8, 'little')
    out += int(disk if disk is not None else size).to_bytes(8, 'little')
    out += b'\x00' * MISC
    if kind in (T_FILE,):
        out += b'\x01\x00'                      # file tail
    else:
        for c in children:
            out += c
        out += b'\x01\x00'                      # dir tail (after children)
    return out


def file_node(name, size, disk=None):
    return write_node(b'', T_FILE, name, size, disk)


def dir_node(name, size, children=()):
    return write_node(b'', T_DIR, name, size, None, children)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'example.sns'

    MB = 1024 ** 2
    docs = dir_node('Documents', 3 * MB, [
        file_node('report.docx', 2 * MB),
        file_node('notes.txt', 1 * MB),
    ])
    cache = dir_node('Cache', 7 * MB, [
        file_node('blob_a.bin', 4 * MB),
        file_node('blob_b.bin', 3 * MB),
    ])
    media = dir_node('Media', 9 * MB, [
        file_node('clip.mp4', 9 * MB),
    ])
    top_file = file_node('pagefile.sys', 16 * MB)

    children = [docs, cache, media, top_file]
    tree_total = 3 * MB + 7 * MB + 9 * MB + 16 * MB

    capacity = 128 * MB
    free = capacity - tree_total

    out = write_node(b'', T_ROOT, 'C:\\', capacity, capacity, children)
    # footer pseudo-records
    out = write_node(out, T_FREE, 'Free Space', free, free)
    out = write_node(out, T_UNKNOWN, 'Unknown (not yet scanned) Space', 0, 0)

    with open(path, 'wb') as fh:
        fh.write(out)
    print(f'wrote {path}: {len(out)} bytes, tree total = {tree_total} bytes, free = {free} bytes')


if __name__ == '__main__':
    main()