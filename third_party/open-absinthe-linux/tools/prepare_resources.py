#!/usr/bin/env python3
"""Prepare separately supplied public NAC resources; never reads account state."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import tempfile
import urllib.request


RESOURCES = (
    (
        "IMDAppleServices",
        "https://raw.githubusercontent.com/JJTech0130/nacserver/2b12660e66db922c9fc09642a2d05144c7f5e955/IMDAppleServices",
        "74c2a8fe826a478f14f6e17b3709a8b315e8c0e0e34e3fba6b9c4eee2f4516e9",
        6_222_784,
    ),
    (
        "cert-1.0.plist",
        "https://static.ess.apple.com/identity/validation/cert-1.0.plist",
        "6ef3521ed899be820e132a6d8c53cac955267c2c3f862684477524be91dc3a06",
        3_474,
    ),
)
FAIRPLAY_IDS = (
    "4056631661436364584235346952193",
    "4056631661436364584235346952194",
    "4056631661436364584235346952195",
    "4056631661436364584235346952196",
    "4056631661436364584235346952197",
    "4056631661436364584235346952198",
    "4056631661436364584235346952199",
    "4056631661436364584235346952200",
    "4056631661436364584235346952201",
    "4056631661436364584235346952208",
)


def checked_bytes(path: Path, digest: str, size: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Expected a regular public resource: {path}")
    data = path.read_bytes()
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"Resource checksum or size mismatch: {path}")
    return data


def write_new(path: Path, data: bytes) -> None:
    # A hard link publishes atomically and refuses to replace an existing file.
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".resource-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            stream.close()
            temporary.chmod(0o644)
            path.hardlink_to(temporary)
        finally:
            temporary.unlink(missing_ok=True)


def fetch_resource(destination: Path, resource: tuple[str, str, str, int]) -> None:
    name, url, digest, size = resource
    path = destination / name
    if path.exists() or path.is_symlink():
        checked_bytes(path, digest, size)
        print(f"Verified existing public resource: {name}")
        return
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(size + 1)
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"Downloaded resource checksum or size mismatch: {name}")
    write_new(path, data)
    print(f"Downloaded and verified public resource: {name}")


def prepare_fairplay() -> None:
    # Match the retained Corten Makefile's build-time legacy fallback. These
    # public compile inputs do not prove current Apple certificate compatibility.
    protocol_root = Path(__file__).resolve().parents[3]
    source = protocol_root / "certs" / "legacy-fairplay"
    destination = protocol_root / "certs" / "fairplay"
    destination.mkdir(parents=True, exist_ok=True)
    for suffix in ("crt", "pem"):
        original = source / f"fairplay.{suffix}"
        if original.is_symlink() or not original.is_file():
            raise ValueError(f"Expected public legacy certificate: {original}")
        data = original.read_bytes()
        for cert_id in FAIRPLAY_IDS:
            target = destination / f"{cert_id}.{suffix}"
            if target.exists() or target.is_symlink():
                if target.is_symlink() or not target.is_file() or target.read_bytes() != data:
                    raise ValueError(f"Existing FairPlay input differs; refusing to replace: {target}")
            else:
                write_new(target, data)
    print("Prepared public legacy FairPlay compile inputs; runtime compatibility is unverified.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True,
                        help="Absolute directory for public resources, separate from private account state")
    parser.add_argument("--prepare-legacy-fairplay-fallback", action="store_true",
                        help="Materialize the public legacy certificate includes required by rustpush")
    args = parser.parse_args()
    if not args.destination.is_absolute():
        parser.error("--destination must be an absolute path")
    if args.destination.is_symlink():
        parser.error("--destination must not be a symlink")
    args.destination.mkdir(parents=True, exist_ok=True)
    for resource in RESOURCES:
        fetch_resource(args.destination, resource)
    if args.prepare_legacy_fairplay_fallback:
        prepare_fairplay()
    print(f"Set OPEN_ABSINTHE_BINARY={args.destination / 'IMDAppleServices'}")


if __name__ == "__main__":
    main()
