#!/usr/bin/env python3
"""Verify final closed guest results against their downloaded SHA256 manifest."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath


def verify(root, manifest):
    root = root.resolve(strict=True)
    missing, mismatched, unsafe, seen = [], [], [], set()
    for line in manifest.read_text(encoding="utf-8-sig").splitlines():
        digest, separator, name = line.partition("  ")
        if not separator or len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest):
            unsafe.append(line[:200])
            continue
        logical = PurePosixPath(name)
        if logical.is_absolute() or ".." in logical.parts or "\\" in name or ":" in name:
            unsafe.append(name)
            continue
        key = logical.as_posix()
        if key in seen:
            unsafe.append("duplicate:" + key)
            continue
        seen.add(key)
        target = root.joinpath(*logical.parts)
        if not target.is_file():
            missing.append(key)
            continue
        if not target.resolve(strict=True).is_relative_to(root) or target.is_symlink():
            unsafe.append(key)
            continue
        with target.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual.lower() != digest.lower():
            mismatched.append(key)
    extra = sorted(path.relative_to(root).as_posix() for path in root.rglob("*")
                   if path.is_file() and path.resolve() != manifest.resolve()
                   and path.relative_to(root).as_posix() not in seen)
    return {"manifest": str(manifest), "root": str(root), "listed_files": len(seen),
            "missing": missing, "mismatched": mismatched, "unsafe": unsafe, "unlisted_local_files": extra,
            "verified": bool(seen) and not missing and not mismatched and not unsafe}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = verify(args.root, args.manifest)
    if args.out:
        args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(not result["verified"])


if __name__ == "__main__":
    main()
