#!/usr/bin/env python3
"""
Analyzes file blob metadata in Manifest.db, reporting field statistics and encryption key types.

This script scans all file entries in Manifest.db and provides:
- Field occurrence statistics across all file blobs
- EncryptionKey type distribution (UID references vs inline bytes)

Usage:
    python3 tools/check-manifestdb.py /path/to/backup/Manifest.db

Output:
    - Field occurrence statistics (e.g., Size, Mode, InodeNumber, EncryptionKey, etc.)
    - EncryptionKey type distribution
"""

import sys
import sqlite3
import plistlib
from pathlib import Path
from collections import Counter


def analyze_manifest_fields(db_path: Path):
    """
    Analyzes field statistics and encryption key types in Manifest.db.

    Args:
        db_path: Path to Manifest.db file

    Returns:
        Tuple of (field_counts, enc_key_types, total_files)
    """
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Sample ALL fields from file blobs
    cursor.execute("SELECT file FROM Files WHERE file IS NOT NULL")
    rows = cursor.fetchall()

    field_counts = Counter()
    enc_key_types = Counter()
    total = 0

    for (blob,) in rows:
        try:
            total += 1
            plist = plistlib.loads(blob)
            objects = plist.get('$objects', [])

            for obj in objects:
                if isinstance(obj, dict) and '$class' in obj:
                    # Count all fields present
                    for key in obj.keys():
                        if not key.startswith('$'):
                            field_counts[key] += 1

                    # Check EncryptionKey type if present
                    if 'EncryptionKey' in obj:
                        enc_key = obj['EncryptionKey']
                        if isinstance(enc_key, plistlib.UID):
                            enc_key_types['UID reference'] += 1
                        elif isinstance(enc_key, bytes):
                            enc_key_types['inline bytes'] += 1
                        else:
                            enc_key_types[type(enc_key).__name__] += 1
                    break
        except Exception as e:
            pass

    conn.close()

    return field_counts, enc_key_types, total


def print_report(field_counts: Counter, enc_key_types: Counter, total: int):
    """
    Prints formatted field analysis report.

    Args:
        field_counts: Counter of field occurrences
        enc_key_types: Counter of EncryptionKey types
        total: Total number of files analyzed
    """
    print("=== Fields Present in File Blobs ===")
    for field, count in field_counts.most_common():
        print(f"  {field}: {count}/{total}")
    print()
    print("=== EncryptionKey Types ===")
    for enc_type, count in enc_key_types.most_common():
        print(f"  {enc_type}: {count}")


def main():
    """Main entry point for the script."""
    if len(sys.argv) != 2:
        print("Usage: python3 check-manifestdb.py /path/to/Manifest.db")
        sys.exit(1)

    db_path = Path(sys.argv[1])

    if not db_path.exists():
        print(f"Error: Manifest.db not found at {db_path}")
        sys.exit(1)

    field_counts, enc_key_types, total = analyze_manifest_fields(db_path)
    print_report(field_counts, enc_key_types, total)


if __name__ == "__main__":
    main()
