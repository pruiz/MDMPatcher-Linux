#!/usr/bin/env python3
"""
Extracts and displays encryption key information from sample files in Manifest.db.

This script connects to a decrypted Manifest.db and displays EncryptionKey information
from the first few files, showing the structure and format of encryption metadata.

Usage:
    python3 tools/dump-enckeys.py --db /path/to/Manifest.db

Requirements:
    - Manifest.db must be decrypted first
"""

import argparse
import sqlite3
import plistlib
from pathlib import Path


def main():
    """Main entry point for script."""
    parser = argparse.ArgumentParser(
        description='Extract encryption keys from iOS backup Manifest.db'
    )
    parser.add_argument('--db', required=True, help='Path to Manifest.db file')
    args = parser.parse_args()

    # Connect to decrypted manifest (Must be decrypted first!)
    conn = sqlite3.connect(args.db)
    cursor = conn.cursor()

    # Find files that are typically encrypted (e.g., one from HomeDomain)
    cursor.execute("SELECT fileID, relativePath, file FROM Files WHERE file IS NOT NULL LIMIT 5")

    for row in cursor.fetchall():
        fileid = row[0]
        relative_path = row[1]
        blob_data = row[2]

        try:
            # Load the binary plist
            plist_content = plistlib.loads(blob_data)

            # 1. Direct attempt (Standard format)
            if 'EncryptionKey' in plist_content:
                print("Found at root level!")
                print(f"Key: {plist_content['EncryptionKey'].hex()}")

            # 2. Attempt in protection dictionary (iOS 13+)
            # Sometimes it's inside a field called 'ProtectionInfo'
            if 'ProtectionInfo' in plist_content:
                print("Found in ProtectionInfo")
                # Wrapped key is usually here

            # If you don't see it, print keys to see structure
            print(f"Keys found at {fileid} - {relative_path}: {plist_content.keys()} -- {plist_content.get('ProtectionInfo', None)}")

        except Exception as e:
            print(f"Error parsing BLOB: {e}")

    conn.close()


if __name__ == "__main__":
    main()
