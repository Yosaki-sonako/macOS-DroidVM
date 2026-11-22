#!/usr/bin/env python3
"""从模板生成 vmpkg manifest，注入 payload 的 size 和 sha256。

模板里的 disks/boots 的 path 必须为空、size 为占位值；本脚本按 archive_path
绑定实际文件，算出真实 size 和 sha256 后写回，得到可直接交给 vmpkg_tool.py
pack 的 manifest。
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

CHUNK = 1 << 20


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        while data := handle.read(CHUNK):
            digest.update(data)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template', type=Path, required=True)
    parser.add_argument('--payload', action='append', default=[], metavar='ARCHIVE=PATH',
                        help='archive_path 到实际文件的映射，可多次')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()

    paths = {}
    for item in args.payload:
        archive, sep, path = item.partition('=')
        if not sep or archive in paths:
            parser.error('--payload 必须用唯一的 ARCHIVE=PATH 形式')
        paths[archive] = Path(path)

    manifest = json.loads(args.template.read_text())
    if manifest.get('format') != 'vmpkg' or manifest.get('manifest_version') != 1:
        raise ValueError('仅支持 v1 vmpkg 模板')
    manifest['compression'] = 'ZSTD'

    declared = {}
    for kind in ('disks', 'boots'):
        for row in manifest[kind]:
            archive = row.get('archive_path')
            if not archive or archive not in paths:
                raise ValueError(f'缺少 --payload 映射: {archive}')
            if row.get('path'):
                raise ValueError(f'{archive} 的 path 必须为空，由导入器赋值')
            path = paths[archive]
            if not path.is_file() or path.is_symlink():
                raise ValueError(f'不是普通文件: {path}')
            row['size'] = path.stat().st_size
            row['sha256'] = sha256(path)
            declared[archive] = row

    if set(declared) != set(paths):
        raise ValueError('--payload 映射与模板声明的 disks/boots 不一致')

    args.output.write_text(json.dumps(manifest, ensure_ascii=False, indent=4) + '\n')
    print(json.dumps({'status': 'manifest_written', 'path': str(args.output),
                      'payloads': {a: {'size': r['size'], 'sha256': r['sha256']}
                                   for a, r in declared.items()}},
                     ensure_ascii=False, indent=2))


if __name__ == '__main__':
    sys.exit(main())
