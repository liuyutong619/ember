#!/usr/bin/env python

import os
import shutil
import argparse
import lief


def is_pe_file(path: str) -> bool:
    """Return True if the file at ``path`` is a PE binary."""
    try:
        binary = lief.parse(path, name="PE", raw=True)
        return binary is not None and binary.format == lief.EXE_FORMATS.PE
    except Exception:
        return False


def main() -> None:
    prog = "filter_pe_files"
    descr = "Copy PE files from a directory to a destination directory using LIEF"
    parser = argparse.ArgumentParser(prog=prog, description=descr)
    parser.add_argument("src", help="Source directory with mixed files")
    parser.add_argument("dest", help="Destination directory for PE files")
    args = parser.parse_args()

    if not os.path.exists(args.src) or not os.path.isdir(args.src):
        parser.error(f"Source directory {args.src} does not exist")
    os.makedirs(args.dest, exist_ok=True)

    for entry in os.scandir(args.src):
        if entry.is_file():
            path = entry.path
            if is_pe_file(path):
                shutil.copy2(path, os.path.join(args.dest, entry.name))


if __name__ == "__main__":
    main()
