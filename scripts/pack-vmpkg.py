#!/usr/bin/env python3
"""Pack a macOS 27.2 VM (boot.img + data-pcie.img + edk2-macos.fd) into a split .vmpkg.

The package format mirrors DroidVM's VMExportTask exactly:
  - header (24 bytes): "VMPKG\\0" + u16 manifestVersion + u16 appVersionCode +
    u16 manifestSize + u16 compression + u16 volumeCount + i64 dataSize
  - manifest.json (the PackageManifest), zero-padded to alignment
  - the compressed data stream = zstd(ustar tar of [manifest.json, disks..., boots...])
  - split across <out>.001, <out>.002, ... with a volume index in the master <out>.vmpkg

The VM config is the author's k27 PCI layout (MACOS_DATA_PCI=1, MACOS_VIRTIO_GPU=1,
snd/media off), matching the FDT the phone dumps: PCI data disk + MMIO GPU + drm2kgsl 64 MB.
"""
import argparse
import io
import json
import struct
import subprocess
import sys
import tarfile
import time
import zlib
from pathlib import Path

HEADER_SIZE = 24
MAGIC = b"VMPKG\0"
MANIFEST_NAME = "manifest.json"
COMPRESSION_ZSTD = 3          # Compression.ZSTD.type
MANIFEST_VERSION = 1          # no BACKING_CHAIN feature -> base
APP_VERSION_CODE = 1          # importer only checks header/manifest agree
APP_VERSION = "1.0"
APP_BUILD_TYPE = "release"
VOLUME_SUFFIX_DIGITS = 3
DEFAULT_VOLUME_SIZE = 500 * 1024 * 1024


def align_up(n, a=8):
    return (n + a - 1) // a * a


def build_vm_config(width=1280, height=720):
    """The k27 PCI VM definition, disks[] left empty (the importer rebuilds it)."""
    screen = {
        "enabled": True,
        "exporter": "native",
        "width": width,
        "height": height,
        "refresh_rate": 60,
        "dpi_h": 160,
        "dpi_v": 160,
        "input_enabled": True,
        "transport_cap": "gpu",
    }
    simplefb = dict(screen, poll_hz=60)
    simplefb.pop("refresh_rate", None)
    simplefb.pop("dpi_h", None)
    simplefb.pop("dpi_v", None)
    return {
        "name": "macOS 27.2 (PCI + GPU)",
        "backend": "crosvm",
        "hypervisor": "gunyah",
        "memory_mb": 5120,
        "memory_auto": False,
        "cpu_count": 8,
        "cpu_topology_auto": True,
        "virtio_transport": "pci",
        "pci_msi": True,
        "prepare_lend_mthp": "chunked",
        "hugepages": True,
        "pmu": True,
        "balloon": False,
        "disks": [],
        # disks are attached via the disks[] array (PCI --block); the GPU rides MMIO.
        "extra_options": ["--virtio-mmio-gpu"],
        "boot": {
            "protocol": "uefi",
            "uefi": {"firmware": "edk2-macos.fd", "vars": "", "vars_enabled": True},
        },
        "gpu_backend": "gpu_virglrenderer",
        "gpu_mode": "native",
        "gpu_api": "drm2kgsl",
        "gpu_provider": "drm2kgsl",
        "gpu_drm2kgsl_pool_mb": 64,
        "gpu_host_pool_mb": 64,
        "gpu_guest_pool_mb": 1024,
        "gpu_guest_prealloc_mb": 1024,
        "gpu_udmabuf": True,
        "screens": {"gpu-0": screen, "simplefb": simplefb},
        "networks": [],
        "peripherals": [],
    }


def build_manifest(vm, disks, boots):
    return {
        "manifest_version": MANIFEST_VERSION,
        "format": "vmpkg",
        "created_at": int(time.time() * 1000),
        "app_version": APP_VERSION,
        "app_version_code": APP_VERSION_CODE,
        "app_build_type": APP_BUILD_TYPE,
        "compression": "zstd",
        "vm": vm,
        "disks": disks,
        "boots": boots,
        "networks": [],
    }


def disk_entry(index, path, readonly=False, bus="virtio"):
    size = Path(path).stat().st_size
    return {
        "index": index,
        "readonly": readonly,
        "bus": bus,
        "path": path,
        "name": Path(path).name,
        "format": "raw",
        "size": size,
        "archive_path": Path(path).name,
        "attached": True,
    }


def boot_entry(path, kind):
    return {
        "archive_path": Path(path).name,
        "name": Path(path).name,
        "path": path,
        "kind": kind,
        "size": Path(path).stat().st_size,
    }


def tar_bytes(files):
    """files: list of (arcname, filepath). Returns the ustar tar as bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for arcname, path in files:
            tar.add(path, arcname=arcname, recursive=False)
    return buf.getvalue()


def zstd_compress(data):
    p = subprocess.run(
        ["zstd", "-q", "-c", "-T0"], input=data, stdout=subprocess.PIPE, check=True
    )
    return p.stdout


def build_header(manifest_size, data_size, volume_count):
    hdr = bytearray(HEADER_SIZE)
    hdr[0:6] = MAGIC
    struct.pack_into("<H", hdr, 6, MANIFEST_VERSION)
    struct.pack_into("<H", hdr, 8, APP_VERSION_CODE)
    struct.pack_into("<H", hdr, 10, manifest_size)
    struct.pack_into("<H", hdr, 12, COMPRESSION_ZSTD)
    struct.pack_into("<H", hdr, 14, volume_count)
    struct.pack_into("<Q", hdr, 16, data_size)
    return bytes(hdr)


def volume_name(base, index):
    return f"{base}.{index:0{VOLUME_SUFFIX_DIGITS}d}"


def write_split(out_base, manifest_bytes, compressed, volume_size):
    """Slice the compressed stream into sub-volumes and write the metadata master."""
    entries = []
    offset = 0
    idx = 1
    while offset < len(compressed):
        chunk = compressed[offset:offset + volume_size]
        vname = volume_name(out_base, idx)
        with open(vname, "wb") as f:
            f.write(chunk)
        entries.append({"index": idx, "size": len(chunk), "crc32": zlib.crc32(chunk)})
        offset += len(chunk)
        idx += 1
    data_size = len(compressed)
    index = {
        "magic": "VMPV",
        "version": 1,
        "data_size": data_size,
        "volumes": entries,
    }
    index_bytes = json.dumps(index, separators=(",", ":")).encode()
    with open(out_base + ".vmpkg", "wb") as master:
        master.write(build_header(len(manifest_bytes), data_size, len(entries)))
        master.write(b"\0" * (align_up(HEADER_SIZE) - HEADER_SIZE))
        master.write(manifest_bytes)
        master.write(b"\0" * (align_up(len(manifest_bytes)) - len(manifest_bytes)))
        master.write(index_bytes)
    return len(entries), data_size


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--boot", required=True)
    ap.add_argument("--data", required=True, help="data-pcie.img (folded raw APFS)")
    ap.add_argument("--firmware", required=True, help="edk2-macos.fd")
    ap.add_argument("--out", required=True, help="output base path (e.g. out/macos-27.2)")
    ap.add_argument("--volume-size", type=int, default=DEFAULT_VOLUME_SIZE)
    ap.add_argument("--width", type=int, default=1280)
    ap.add_argument("--height", type=int, default=720)
    args = ap.parse_args()

    out_base = args.out
    Path(out_base).parent.mkdir(parents=True, exist_ok=True)

    vm = build_vm_config(args.width, args.height)
    disks = [disk_entry(0, args.boot), disk_entry(1, args.data)]
    boots = [boot_entry(args.firmware, "uefi")]
    manifest = build_manifest(vm, disks, boots)
    manifest_bytes = json.dumps(manifest, indent=2).encode()
    if len(manifest_bytes) > 0xFFFF:
        raise SystemExit(f"manifest too large: {len(manifest_bytes)} bytes")

    # tar: manifest.json first, then disks, then boots (same order VMExportTask packs).
    files = [(MANIFEST_NAME, None)]
    tar_entries = [(MANIFEST_NAME, manifest_bytes)]
    tar_entries += [(d["archive_path"], d["path"]) for d in disks]
    tar_entries += [(b["archive_path"], b["path"]) for b in boots]

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for arcname, content in tar_entries:
            if isinstance(content, bytes):
                ti = tarfile.TarInfo(arcname)
                ti.size = len(content)
                ti.mode = 0o644
                ti.mtime = int(time.time())
                tar.addfile(ti, io.BytesIO(content))
            else:
                tar.add(content, arcname=arcname, recursive=False)
    tar_data = buf.getvalue()

    compressed = zstd_compress(tar_data)
    n, data_size = write_split(out_base, manifest_bytes, compressed, args.volume_size)

    print(f"{out_base}.vmpkg + {n} volumes: {data_size} compressed bytes "
          f"(tar {len(tar_data)}), disks {len(disks)}, boots {len(boots)}")


if __name__ == "__main__":
    main()
