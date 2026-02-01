#!/usr/bin/env python3
"""
Validates backup integrity by comparing Manifest.db entries with actual files on disk.

This script checks if all files referenced in Manifest.db exist physically in backup
directory structure (backup_dir/XX/XX/fileID). Useful for verifying backup completeness
and detecting missing files.

Usage:
    python3 tools/verify-manifest.py /path/to/backup/directory

Exit codes:
    0 - All referenced files exist
    1 - Manifest.db not found
    2 - Missing files detected
"""

import os
import sqlite3
import argparse
from pathlib import Path


def verify_files_exist(backup_dir: str) -> bool:
    """
    Verifies that all files referenced in Manifest.db exist in backup directory.

    Checks each fileID in Files table against physical file structure:
    backup_dir/fileID[:2]/fileID[2:4]/fileID

    Args:
        backup_dir: Path to iOS backup directory

    Returns:
        True if all referenced files exist, False otherwise
    """
    manifest_db_path = os.path.join(backup_dir, "Manifest.db")

    if not os.path.exists(manifest_db_path):
        print(f"[ERROR] Manifest.db not found in {backup_dir}")
        return False

    conn = sqlite3.connect(manifest_db_path)
    cursor = conn.cursor()

    missing = []
    cursor.execute("SELECT fileID, domain, relativePath FROM Files")

    for file_id, domain, rel_path in cursor:
        # Construct physical file path
        path = os.path.join(backup_dir, file_id[:2], file_id[2:4], file_id)

        if not os.path.exists(path):
            missing.append((file_id, domain, rel_path))

    conn.close()

    if missing:
        print(f"[!] {len(missing)} referenced files do not exist:")
        for fid, dom, path in missing[:10]:
            print(f"    {dom}::{path} (ID: {fid})")
        if len(missing) > 10:
            print(f"    ... and {len(missing) - 10} more missing files")
    else:
        print("[OK] All referenced files exist physically")

    return len(missing) == 0


def main():
    """Main entry point for script."""
    parser = argparse.ArgumentParser(
        description="Verify iOS backup integrity by comparing manifest with physical files."
    )
    parser.add_argument("dir", help="iOS backup directory path")

    args = parser.parse_args()
    backup_directory = args.dir

    # Check if Manifest.db exists
    manifest_db_path = os.path.join(backup_directory, "Manifest.db")
    if not os.path.exists(manifest_db_path):
        print("[ERROR] Manifest.db not found in specified directory.")
        exit(1)

    # Verify all files exist
    all_files_exist = verify_files_exist(backup_directory)

    if all_files_exist:
        exit(0)
    else:
        exit(2)


if __name__ == "__main__":
    main()
