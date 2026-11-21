#!/usr/bin/env python3
"""Pack a macOS 27.2 VM (boot.img + data-pcie.img + edk2-macos.fd) into a split .vmpkg.

The package format mirrors DroidVM's VMExportTask exactly:
  - header (24 bytes): "VMPKG" + u16 manifestVersion + u16 appVersionCode +
    u16 manifestSize + u16 compression + u16 volumeCount + i64 dataSize
  - manifest.json (the PackageManifest), zero-padded to 0x1000 (page) alignment
  - volume index JSON (VolumeIndex: magic "VMPV", version, data_size, volumes[])
  - the compressed data stream = zstd(ustar tar of [manifest.json, disks..., boots...])
  - split across <out>.001, <out>.002, ... with the volume index in the master <out>.vmpkg

The tar uses GNU format so the 48 GiB data-pcie.img (a sparse raw APFS image) gets a
GNU base-256 size field (DroidVM's TarReader reads exactly that; 11 octal digits top
out at 8 GiB). Packing is streamed: tar -> zstd stdin -> zstd stdout -> sub-volumes,
so the 48 GiB image is never buffered whole.

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
MAGIC = b"VMPKG"
MANIFEST_NAME = "manifest.json"
COMPRESSION_ZSTD = 3          # Compression.ZSTD.type
MANIFEST_VERSION = 1          # no BACKING_CHAIN feature -> base
APP_VERSION_CODE = 1          # importer only checks header/manifest agree
APP_VERSION = "1.0"
APP_BUILD_TYPE = "release"
VOLUME_SUFFIX_DIGITS = 3
VOLUME_MAGIC = "VMPV"
VOLUME_VERSION = 1
VOLUME_MAX_COUNT = 999
DEFAULT_VOLUME_SIZE = 1900 * 1024 * 1024


ALIGN = 0x1000  # DroidVM BinaryUtils.alignUp/alignUpStrict default to 0x1000 (4096), NOT 8


def align_up(n, a=ALIGN):
    return (n + a - 1) & ~(a - 1)


def align_up_strict(n, a=ALIGN):
    aligned = align_up(n, a)
    return aligned + a if aligned == n else aligned


def build_vm_config(width=1280, height=720):
    """The k27 PCI VM definition; disks[] left empty (the importer rebuilds it from manifest.disks)."""
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
        "protected_vm": "pseudo_unprotected",
        "hugepages": True,
        "pmu": True,
        "rng": True,
        "smt": True,
        "balloon": False,
        "sandbox": False,
        "swiotlb_mb": 256,
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
        "display_blit_provider": "TURNIP",
        "screens": {"gpu-0": screen, "simplefb": simplefb},
        "networks": [],
        "peripherals": [],
        # media/snd off: the phone's crosvm may lack --virtio-mmio-media; keep the FDT 1-window.
        "vpu_enabled": False,
        "vpu_codec_enabled": False,
        "vpu_host_pool_mb": 8,
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


def build_header(manifest_size, data_size, volume_count):
    hdr = bytearray(HEADER_SIZE)
    hdr[0:5] = MAGIC
    struct.pack_into("<H", hdr, 6, MANIFEST_VERSION)
    struct.pack_into("<H", hdr, 8, APP_VERSION_CODE)
    struct.pack_into("<H", hdr, 10, manifest_size)
    struct.pack_into("<H", hdr, 12, COMPRESSION_ZSTD)
    struct.pack_into("<H", hdr, 14, volume_count)
    struct.pack_into("<Q", hdr, 16, data_size)
    return bytes(hdr)


def volume_name(base, index):
    return f"{base}.{index:0{VOLUME_SUFFIX_DIGITS}d}"


def write_master(out_base, manifest_bytes, data_size, entries):
    index = {
        "magic": VOLUME_MAGIC,
        "version": VOLUME_VERSION,
        "data_size": data_size,
        "volumes": entries,
    }
    index_bytes = json.dumps(index, separators=(",", ":")).encode()
    ms = len(manifest_bytes)
    # Master layout (matches DroidVM VMExportTask + VolumeSet.discover):
    #   header(24) | pad to 0x1000 | manifest(ms) | pad to dataStart | volume index JSON
    # dataStart = alignUpStrict(alignUp(HEADER_SIZE) + manifestSize). The header's dataSize is a
    # 0 placeholder (multi-volume packages only know it after streaming; VolumeSet carries the
    # real value), so PackageInput.open(in, set.dataSize()) overrides it on import.
    data_start = align_up_strict(align_up(HEADER_SIZE) + ms)
    with open(out_base + ".vmpkg", "wb") as master:
        master.write(build_header(ms, 0, len(entries)))
        master.write(b"\0" * (align_up(HEADER_SIZE) - HEADER_SIZE))
        master.write(manifest_bytes)
        master.write(b"\0" * (data_start - (align_up(HEADER_SIZE) + ms)))
        master.write(index_bytes)


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
    volume_size = args.volume_size

    vm = build_vm_config(args.width, args.height)
    disks = [disk_entry(0, args.boot), disk_entry(1, args.data)]
    boots = [boot_entry(args.firmware, "uefi")]
    manifest = build_manifest(vm, disks, boots)
    manifest_bytes = json.dumps(manifest, indent=2).encode()
    if len(manifest_bytes) > 0xFFFF:
        raise SystemExit(f"manifest too large: {len(manifest_bytes)} bytes")

    # Streamed pack: tar (GNU format, so >8 GiB sizes use base-256) -> zstd stdin ->
    # zstd stdout -> fixed sub-volumes. Never buffers the 48 GiB data image whole.
    zstd_proc = subprocess.Popen(
        ["zstd", "-q", "-c", "-T0"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    )
    with tarfile.open(fileobj=zstd_proc.stdin, mode="w|", format=tarfile.GNU_FORMAT) as tar:
        ti = tarfile.TarInfo(MANIFEST_NAME)
        ti.size = len(manifest_bytes)
        ti.mode = 0o644
        ti.mtime = int(time.time())
        tar.addfile(ti, io.BytesIO(manifest_bytes))
        for d in disks:
            tar.add(d["path"], arcname=d["archive_path"], recursive=False)
        for b in boots:
            tar.add(b["path"], arcname=b["archive_path"], recursive=False)
    zstd_proc.stdin.close()

    entries = []
    data_size = 0
    idx = 1
    pending = bytearray()
    while True:
        chunk = zstd_proc.stdout.read(1024 * 1024)
        if not chunk:
            break
        pending.extend(chunk)
        while len(pending) >= volume_size:
            piece = bytes(pending[:volume_size])
            del pending[:volume_size]
            vname = volume_name(out_base, idx)
            with open(vname, "wb") as f:
                f.write(piece)
            entries.append({"index": idx, "size": len(piece), "crc32": zlib.crc32(piece)})
            data_size += len(piece)
            idx += 1
            if idx > VOLUME_MAX_COUNT:
                raise SystemExit(f"too many volumes; raise --volume-size")
    if pending:
        piece = bytes(pending)
        vname = volume_name(out_base, idx)
        with open(vname, "wb") as f:
            f.write(piece)
        entries.append({"index": idx, "size": len(piece), "crc32": zlib.crc32(piece)})
        data_size += len(piece)
    zstd_proc.stdout.close()
    rc = zstd_proc.wait()
    if rc != 0:
        raise SystemExit(f"zstd failed with exit code {rc}")

    write_master(out_base, manifest_bytes, data_size, entries)

    print(f"{out_base}.vmpkg + {len(entries)} volumes: {data_size} compressed bytes, "
          f"disks {len(disks)}, boots {len(boots)}")


if __name__ == "__main__":
    main()
