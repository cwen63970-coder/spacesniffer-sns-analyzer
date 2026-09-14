#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sns_analyze.py — complete analyzer for SpaceSniffer .sns snapshot files.

The .sns export format is NOT officially documented. This implementation is
based on community reverse-engineering (jerrylususu/SpaceSniffer_Format and
zhkgo.github.io/2024/04/30/snsData) plus first-hand verification against a
real 244 MB C: drive snapshot.

Verified record layout (little-endian):
    node   = type(2) + namelen(4) + base64name + fixed(46) [+ children if dir] + tail(01 00)
    type   = 04 01/02 01  root(drive)     04 02/02 02  file
             04 03/02 03  directory       04 04       Free Space (footer)
             04 05        Unknown Space (footer)
    name   = base64(UTF-16LE)              fixed = logical size(8) + disk size(8) + 30B misc
    files are followed by tail 01 00; a directory's 01 00 comes after its children.
    root record size = drive CAPACITY; footer 'Free Space' record = free bytes.

Usage:
    python sns_analyze.py snapshot.sns [--output DIR] [--top N] [--big-min MIB]
                          [--subtree "PATH1;PATH2"] [--lang zh|en] [--json]

Outputs (into --output dir):
    report.md            human-readable analysis report (English or Chinese)
    top_files.csv        largest N files
    extensions.csv       extension histogram
    dirs.csv             children of 'big' directories (> = --big-min MiB)
    summary.json         aggregate numbers
    subtree_<x>.csv      full subtree listing for each --subtree path

No third-party dependencies (Python 3.8+).
"""

import argparse
import base64
import csv
import heapq
import json
import os
import sys
import time

T_ROOT = b'\x04\x01'
T_FILE = b'\x04\x02'
T_DIR = b'\x04\x03'
T_FREE = b'\x04\x04'
T_UNKNOWN = b'\x04\x05'
FIXED = 46  # fixed payload length after the name field

# --- name decoding --------------------------------------------------------


def decode_name(raw: bytes) -> str:
    """base64(UTF-16LE) name → str. Tolerant fallbacks for odd encodings."""
    for validate in (True, False):
        try:
            return base64.b64decode(raw, validate=validate).decode('utf-16-le')
        except Exception:
            continue
    return raw.decode('ascii', errors='replace')


def sanitize(s: str) -> str:
    return ''.join(c if ord(c) >= 32 else '?' for c in s)


def norm_path(parts):
    """Join path parts with single backslashes; strip root's trailing '\'."""
    if not parts:
        return ''
    head = parts[0].rstrip('\\')
    tail = parts[1:]
    return '\\'.join([head] + tail)


# --- single-pass parser ----------------------------------------------------


class Snapshot:
    def __init__(self, path, big_min_mib=256.0):
        self.path = path
        self.big_min = int(big_min_mib * 1024 * 1024)
        self.data = open(path, 'rb').read()
        self.N = len(self.data)
        # stats
        self.n_files = 0
        self.n_dirs = 0
        self.max_depth = 0
        self.sum_file_log = 0
        self.sum_file_disk = 0
        self.root_name = ''
        self.root_log = 0
        self.root_disk = 0
        self.free_log = 0
        self.unknown_log = 0
        # extras
        self.top_level = []          # (name, log, disk, isdir)
        self.dir_children = {}       # parent path -> [(name, log, disk, isdir)] (big dirs only)
        self.big_dirs = set()
        self.disc = []               # (full path, own, childsum) where own != childsum
        self.ext = {}                # ext -> [count, size]
        self.noext = [0, 0]
        self.heap = []               # top files: (-log-size, seq, path, disk) via heapq
        self.heap_cap = 600
        self.subtrees = []           # (root_label, [(path, log, disk, isdir)]) when requested

    # -- stream helpers --
    def _seek_node(self, pos):
        """Read node header+name at pos. Returns (type_bytes, name, name_end, pos_after_name)."""
        t = self.data[pos:pos + 2]
        nlen = int.from_bytes(self.data[pos + 2:pos + 6], 'little')
        name = sanitize(decode_name(self.data[pos + 6:pos + 6 + nlen]))
        return t, name, pos + 6 + nlen

    def _fixed(self, name_end):
        f = name_end
        log = int.from_bytes(self.data[f:f + 8], 'little')
        disk = int.from_bytes(self.data[f + 8:f + 16], 'little')
        return log, disk

    def parse(self, top_files=600, subtrees=None):
        d, N, FIX = self.data, self.N, FIXED
        self.heap_cap = top_files
        pos = 0
        path_parts = []
        open_dirs = 0
        # stack for discrepancy check: [name, own_size, children_sum]
        dstack = []
        self.sub_roots = [s.rstrip('\\') for s in (subtrees or [])]
        sub_roots = self.sub_roots

        def in_subtree(p):
            return any(p == r or p.startswith(r + '\\') for r in sub_roots)

        while pos < N:
            b2 = d[pos:pos + 2]
            if b2 == b'\x01\x00':
                if open_dirs <= 0:
                    raise ValueError(f'orphan tail marker at offset {pos}')
                name, own, csum = dstack.pop()
                open_dirs -= 1
                path_parts.pop()
                if own - csum:
                    # only root is expected to differ (root = capacity)
                    self.disc.append((norm_path(path_parts + [name]), own, csum))
                if dstack:
                    dstack[-1][2] += own
                pos += 2
                continue
            if b2 == b'\x00\x00':
                raise ValueError(f'unexpected 00 00 at offset {pos}')
            if pos + 6 > N:
                raise ValueError(f'truncated header at offset {pos}')
            t, name, name_end = self._seek_node(pos)
            log, disk = self._fixed(name_end)
            depth = len(path_parts)
            full = norm_path(path_parts + [name])

            if t in (T_FILE, b'\x02\x02'):
                self.n_files += 1
                self.sum_file_log += log
                self.sum_file_disk += disk
                heapq.heappush(self.heap, (log, self.n_files, full, disk))
                if len(self.heap) > self.heap_cap:
                    heapq.heappop(self.heap)  # min-heap: drops the smallest so far
                if '.' in name:
                    e = name.rsplit('.', 1)[1].lower()
                    rec = self.ext.setdefault(e, [0, 0])
                else:
                    rec = self.noext
                rec[0] += 1
                rec[1] += log
                if depth == 1:
                    self.top_level.append((name, log, disk, False))
                else:
                    pk = norm_path(path_parts)
                    if pk in self.big_dirs:
                        self.dir_children.setdefault(pk, []).append((name, log, disk, False))
                if dstack:
                    dstack[-1][2] += log
                if sub_roots:  # record all nodes under subtree roots (dirs handled below)
                    pass
                if in_subtree(full):
                    self.subtrees.append((full, log, disk, False))
                pos = name_end + FIXED + 2
                continue

            if t in (T_FREE, T_UNKNOWN):
                if t == T_FREE:
                    self.free_log = log
                else:
                    self.unknown_log = log
                pos = name_end + FIXED + 2
                continue

            if t in (T_DIR, b'\x02\x03'):
                self.n_dirs += 1
            elif t in (T_ROOT, b'\x02\x01'):
                self.root_log, self.root_disk = log, disk
                self.root_name = name if name else 'C:'
            else:
                raise ValueError(f'unknown record type {t.hex()} at offset {pos}')

            if depth == 1:
                self.top_level.append((name, log, disk, True))
            else:
                pk = norm_path(path_parts)
                if pk in self.big_dirs:
                    self.dir_children.setdefault(pk, []).append((name, log, disk, True))
            path_parts.append(name)
            open_dirs += 1
            dstack.append([name, log, 0])
            if log >= self.big_min:
                self.big_dirs.add(norm_path(path_parts))
            if in_subtree(full):
                self.subtrees.append((full, log, disk, True))
            if dstack and len(dstack) > 1:
                pass  # children sum is accumulated when the child finishes
            self.max_depth = max(self.max_depth, len(path_parts))
            pos = name_end + FIXED

        if open_dirs:
            raise ValueError(f'parse ended with {open_dirs} unclosed directories')
        if pos != N:
            raise ValueError(f'parse ended at {pos} of {N} bytes')
        return self


# --- report rendering (zh / en) -------------------------------------------


def fmt_size(b, zh=False):
    gb = 'GiB'
    if b >= 1024 ** 3:
        return f'{b / 1024 ** 3:,.2f} {gb}'
    if b >= 1024 ** 2:
        return f'{b / 1024 ** 2:,.1f} MiB'
    if b >= 1024:
        return f'{b / 1024:,.0f} KiB'
    return f'{b} B'


def render(snap, lang='zh', topn=50):
    L = []
    A = L.append
    root = snap.root_log or 1
    used = snap.root_log - (snap.free_log or 0)
    root_path = norm_path([snap.root_name or 'C:'])
    root_delta = next((own - csum for p, own, csum in snap.disc if p == root_path), 0)
    rule = '---'
    if lang == 'zh':
        A(f'# C 盘空间分析报告（SpaceSniffer 快照）\n')
        A('> 来源：`%s`（%d 字节）。大小默认指逻辑大小（文件字节数 / 目录递归合计）；占比相对整盘容量。'
          '根记录大小 = 整盘容量；"Free Space" 页脚记录 = 空闲空间。' % (snap.path, snap.N))
        A('\n## 总览\n')
        A('| 项目 | 大小 | 占整盘 |\n|---|---|---|')
        A(f'| 总容量（根记录） | **{fmt_size(snap.root_log)}** | 100.0% |')
        A(f'| 空闲空间 | {fmt_size(snap.free_log)} | {snap.free_log / root * 100:.1f}% |')
        A(f'| 已用空间 | **{fmt_size(used)}** | {used / root * 100:.1f}% |')
        A(f'| 文件数 / 目录数 | {snap.n_files:,} / {snap.n_dirs:,} | — |')
        A(f'| 最大目录深度 | {snap.max_depth} | — |')
        A(f'| 树内文件大小合计 | {fmt_size(snap.sum_file_log)} | — |')
        A(f'| 树合计 − 已用 | {fmt_size(snap.sum_file_log - used)}（正常误差） | — |')
        A('\n## 一级目录\n')
        A('| 名称 | 逻辑大小 | 占比 | 磁盘占用 | 类型 |\n|---|---|---|---|---|')
        for name, log, disk, isdir in sorted(snap.top_level, key=lambda x: -x[1]):
            A(f'| {name} | {fmt_size(log)} | {log / root * 100:.1f}% | {fmt_size(disk)} | {"目录" if isdir else "文件"} |')
        A('\n## 目录一致性校验（差额定位）\n')
        A('> 逐目录核对"自报大小 = 子项合计"。根节点是特例（记录的是整盘容量，差额 = 容量 − 树合计 = 空闲 + 误差）。')
        bad = [d for d in snap.disc if d[0] != root_path]
        if bad:
            A('| 目录 | 自报 | 子项合计 | 差额 |\n|---|---|---|---|')
            for p, own, csum in sorted(bad, key=lambda x: -(x[1] - x[2]))[:20]:
                A(f'| `{p}` | {fmt_size(own)} | {fmt_size(csum)} | **{fmt_size(own - csum)}** |')
        else:
            A(f'✅ 所有目录自洽（根差额 {fmt_size(root_delta)} = 容量 − 树合计，属预期，非异常）。')
        A('\n## 扩展名排行\n')
        A('| 扩展名 | 数量 | 大小合计 | 占比 |\n|---|---|---|---|')
        rows = sorted(snap.ext.items(), key=lambda kv: -kv[1][1])[:30]
        for e, (c, s) in rows:
            A(f'| {e} | {c:,} | {fmt_size(s)} | {s / root * 100:.1f}% |')
        A(f'| (无扩展名) | {snap.noext[0]:,} | {fmt_size(snap.noext[1])} | {snap.noext[1] / root * 100:.1f}% |')
        A('\n## 最大文件\n')
        A('| 大小 | 磁盘占用 | 路径 |\n|---|---|---|')
        for log, seq, p, disk in sorted(snap.heap, reverse=True)[:topn]:
            A(f'| {fmt_size(log)} | {fmt_size(disk)} | `{p}` |')
        if snap.subtrees:
            A('\n## 子树清单（--subtree）\n')
            A('| 大小 | 类型 | 路径 |\n|---|---|---|')
            for p, log, disk, isdir in sorted(snap.subtrees, key=lambda x: -x[1]):
                A(f'| {fmt_size(log)} | {"目录" if isdir else "文件"} | `{p}` |')
    else:
        A(f'# Disk space report (SpaceSniffer snapshot)\n')
        A(f'> Source: `{snap.path}` ({snap.N} bytes). Sizes are logical '
          '(file bytes / recursive dir totals); percentages relative to drive capacity. '
          'Root record size = drive CAPACITY; "Free Space" footer record = free space.')
        A('\n## Overview\n')
        A('| item | size | % of drive |\n|---|---|---|')
        A(f'| capacity (root record) | **{fmt_size(snap.root_log)}** | 100.0% |')
        A(f'| free | {fmt_size(snap.free_log)} | {snap.free_log / root * 100:.1f}% |')
        A(f'| used | **{fmt_size(used)}** | {used / root * 100:.1f}% |')
        A(f'| files / dirs | {snap.n_files:,} / {snap.n_dirs:,} | — |')
        A(f'| max depth | {snap.max_depth} | — |')
        A(f'| sum of file sizes | {fmt_size(snap.sum_file_log)} | — |')
        A(f'| sum − used | {fmt_size(snap.sum_file_log - used)} (normal drift) | — |')
        A('\n## Top-level entries\n')
        A('| name | logical | % | disk | type |\n|---|---|---|---|---|')
        for name, log, disk, isdir in sorted(snap.top_level, key=lambda x: -x[1]):
            A(f'| {name} | {fmt_size(log)} | {log / root * 100:.1f}% | {fmt_size(disk)} | {"dir" if isdir else "file"} |')
        A('\n## Directory consistency check\n')
        bad = [d for d in snap.disc if d[0] != root_path]
        if bad:
            A('| path | own | children sum | delta |\n|---|---|---|---|')
            for p, own, csum in sorted(bad, key=lambda x: -(x[1] - x[2]))[:20]:
                A(f'| `{p}` | {fmt_size(own)} | {fmt_size(csum)} | **{fmt_size(own - csum)}** |')
        else:
            A(f'OK: every directory is self-consistent. Root delta {fmt_size(root_delta)} '
              '= capacity - tree total (expected: free space + drift).')
        A('\n## Extensions\n')
        A('| ext | count | size | % |\n|---|---|---|---|')
        for e, (c, s) in sorted(snap.ext.items(), key=lambda kv: -kv[1][1])[:30]:
            A(f'| {e} | {c:,} | {fmt_size(s)} | {s / root * 100:.1f}% |')
        A(f'| (no ext) | {snap.noext[0]:,} | {fmt_size(snap.noext[1])} | {snap.noext[1] / root * 100:.1f}% |')
        A('\n## Largest files\n')
        A('| size | disk | path |\n|---|---|---|')
        for log, seq, p, disk in sorted(snap.heap, reverse=True)[:topn]:
            A(f'| {fmt_size(log)} | {fmt_size(disk)} | `{p}` |')
        if snap.subtrees:
            A('\n## Subtree listing (--subtree)\n')
            A('| size | type | path |\n|---|---|---|')
            for p, log, disk, isdir in sorted(snap.subtrees, key=lambda x: -x[1]):
                A(f'| {fmt_size(log)} | {"dir" if isdir else "file"} | `{p}` |')
    return '\n'.join(L)


# --- CLI -------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(
        description='Analyze a SpaceSniffer .sns snapshot (community-documented format).')
    ap.add_argument('input', help='path to the .sns snapshot file')
    ap.add_argument('--output', '-o', default='.', help='output directory (default: cwd)')
    ap.add_argument('--top', type=int, default=600, help='keep top N files (default 600)')
    ap.add_argument('--big-min', type=float, default=256.0,
                    help='record children of dirs >= N MiB for drill-down (default 256)')
    ap.add_argument('--subtree', default=None,
                    help='semicolon-separated path prefixes to fully list, e.g. "C:\\$Recycle.Bin;C:\\ProgramData\\NVIDIA Corporation"')
    ap.add_argument('--lang', choices=['zh', 'en'], default='zh', help='report language (default zh)')
    ap.add_argument('--json', action='store_true', help='also write summary.json')
    args = ap.parse_args()

    if not os.path.exists(args.input):
        sys.exit(f'input not found: {args.input}')
    os.makedirs(args.output, exist_ok=True)

    t0 = time.time()
    try:
        snap = Snapshot(args.input, big_min_mib=args.big_min).parse(
            top_files=args.top,
            subtrees=[s.strip() for s in args.subtree.split(';')] if args.subtree else None)
    except ValueError as e:
        sys.exit(f'parse error: {e}')

    used = snap.root_log - (snap.free_log or 0)
    print(f'parsed {snap.path} in {time.time() - t0:.1f}s')
    print(f'  files={snap.n_files:,}  dirs={snap.n_dirs:,}  max_depth={snap.max_depth}')
    print(f'  capacity={fmt_size(snap.root_log)}  free={fmt_size(snap.free_log)}  used={fmt_size(used)}')
    print(f'  sum(file sizes)={fmt_size(snap.sum_file_log)}  delta vs used={fmt_size(snap.sum_file_log - used)}')
    bad = [d for d in snap.disc if d[0] != snap.root_name.rstrip('\\')]
    print(f'  directory consistency: {"OK" if not bad else str(len(bad)) + " discrepancies (see report)"}')

    base = os.path.join(args.output, 'report.md')
    open(base, 'w', encoding='utf-8').write(render(snap, lang=args.lang))
    print(f'  wrote {base}')

    def csvw(name, header, rows):
        p = os.path.join(args.output, name)
        with open(p, 'w', encoding='utf-8-sig', newline='') as fh:
            w = csv.writer(fh)
            w.writerow(header)
            w.writerows(rows)
        print(f'  wrote {p}')

    csvw('top_files.csv', ['size_logical', 'size_disk', 'path'],
         [(log, dk, p) for log, s, p, dk in sorted(snap.heap, reverse=True)])
    csvw('extensions.csv', ['ext', 'count', 'size_logical'],
         sorted(snap.ext.items(), key=lambda kv: -kv[1][1]) + [('(no ext)', snap.noext[0], snap.noext[1])])
    csvw('dirs.csv', ['parent', 'name', 'log', 'disk', 'isdir'],
         [(pk, n, l, dk, int(k)) for pk, items in snap.dir_children.items()
          for (n, l, dk, k) in items])
    if snap.subtrees:
        for label in snap.sub_roots:
            lab = label.rsplit('\\', 1)[-1].replace(' ', '_') or 'root'
            rows = [(p, l, dk, 'dir' if k else 'file') for p, l, dk, k in snap.subtrees
                    if p.startswith(label)]
            csvw(f'subtree_{lab}.csv', ['path', 'log', 'disk', 'type'], rows)

    if args.json:
        with open(os.path.join(args.output, 'summary.json'), 'w', encoding='utf-8') as fh:
            json.dump({
                'root': snap.root_name,
                'capacity': snap.root_log,
                'free': snap.free_log,
                'used': used,
                'files': snap.n_files,
                'dirs': snap.n_dirs,
                'max_depth': snap.max_depth,
                'sum_file_log': snap.sum_file_log,
                'sum_file_disk': snap.sum_file_disk,
                'top_level': snap.top_level,
            }, fh, ensure_ascii=False, indent=1)
        print('  wrote summary.json')


if __name__ == '__main__':
    main()