#!/usr/bin/env python3
"""
Lists all encrypted files in backup with encryption key previews.

This script scans Manifest.db and extracts all files that have EncryptionKey
metadata, displaying their file paths, file IDs, key lengths, and key previews.

Usage:
    python3 tools/dump-enckeys2.py /path/to/Manifest.db

Requirements:
    - Manifest.db must be decrypted first
"""

import sqlite3
import plistlib
import sys
from pathlib import Path


def extract_encryption_keys(manifest_db_path: str) -> list:
    """
    Extracts all files that have EncryptionKey in their metadata.

    Args:
        manifest_db_path: Path to Manifest.db file

    Returns:
        List of dictionaries containing file metadata and encryption key information
    """
    conn = sqlite3.connect(manifest_db_path)
    cursor = conn.cursor()

    encrypted_files = []

    # Select necessary fields
    cursor.execute("""
        SELECT fileID, domain, relativePath, file
        FROM Files
        WHERE file IS NOT NULL
    """)

    for row in cursor:
        file_id, domain, rel_path, file_blob = row

        if not file_blob:
            continue

        try:
            # Parse the binary plist from 'file' column
            plist_data = plistlib.loads(file_blob)

            # Check if it has EncryptionKey
            # Structure is usually an array or dict with 'EncryptionKey' key
            encryption_key = None

            if isinstance(plist_data, dict):
                encryption_key = plist_data.get('EncryptionKey')
            elif isinstance(plist_data, list) and len(plist_data) > 0:
                # Some formats use array where certain index contains the dict
                if isinstance(plist_data[0], dict):
                    encryption_key = plist_data[0].get('EncryptionKey')

            if encryption_key:
                # Key is usually bytes
                key_hex = encryption_key.hex() if isinstance(encryption_key, bytes) else str(encryption_key)
                encrypted_files.append({
                    'fileID': file_id,
                    'domain': domain,
                    'path': rel_path,
                    'key_length': len(encryption_key) if isinstance(encryption_key, bytes) else len(str(encryption_key)),
                    'key_preview': key_hex[:32] + "..." if len(key_hex) > 32 else key_hex
                })

        except Exception as e:
            # Some blobs may not be valid plists or are corrupted
            print(f"Error parsing {domain}::{rel_path}: {e}")
            continue

    conn.close()

    # Generate report
    print(f"\nTotal files with EncryptionKey: {len(encrypted_files)}")
    print("-" * 80)

    for entry in encrypted_files[:20]:  # Show first 20
        print(f"File: {entry['path']}")
        print(f"  Domain: {entry['domain']}")
        print(f"  FileID: {entry['fileID']}")
        print(f"  Key Length: {entry['key_length']} bytes")
        print(f"  Key Preview: {entry['key_preview']}")
        print()

    if len(encrypted_files) > 20:
        print(f"... and {len(encrypted_files) - 20} more files")

    return encrypted_files


def main():
    """Main entry point for script."""
    if len(sys.argv) < 2:
        print("Usage: python3 dump-enckeys2.py /path/to/Manifest.db")
        sys.exit(1)

    manifest_db_path = sys.argv[1]

    if not Path(manifest_db_path).exists():
        print(f"Error: Manifest.db not found at {manifest_db_path}")
        sys.exit(1)

    extract_encryption_keys(manifest_db_path)


if __name__ == "__main__":
    main()
