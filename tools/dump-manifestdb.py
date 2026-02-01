#!/usr/bin/env python3
"""
Analyzes Manifest.db to detect hard links, symbolic links, and report file metadata.

This script scans an iOS backup's Manifest.db database and provides:
- Field statistics for file blobs
- Hard link detection (multiple files sharing same InodeNumber)
- Symbolic link detection (Target field or symlink mode)
- Files without InodeNumber
- ConfigurationProfiles link analysis

Usage:
    python3 tools/dump-manifestdb.py /path/to/backup/Manifest.db

Output:
    - Field occurrence statistics
    - EncryptionKey type distribution
    - Hard link groups (shared inodes)
    - Symbolic links with targets
    - Files missing InodeNumber
    - ConfigurationProfiles analysis
"""

import sys
import sqlite3
import plistlib
from pathlib import Path
from collections import Counter, defaultdict


def analyze_manifest(db_path: Path):
    """
    Analyzes Manifest.db for links and metadata patterns.

    Args:
        db_path: Path to Manifest.db file

    Returns:
        Tuple of (field_counts, enc_key_types, inode_groups, symlinks, no_inode_files)
    """
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Get structured data from Files table
    cursor.execute("SELECT fileID, domain, relativePath, file FROM Files WHERE file IS NOT NULL")
    rows = cursor.fetchall()

    # Field analysis counters
    field_counts = Counter()
    enc_key_types = Counter()

    # Link detection structures
    inode_groups = defaultdict(list)  # inode -> [(fileID, domain, path), ...]
    symlinks = []  # [(fileID, domain, path, target), ...]
    link_candidates = []  # Entries with Target field
    no_inode_files = []  # Files without InodeNumber

    total = 0

    for fileID, domain, rel_path, blob in rows:
        try:
            total += 1
            plist = plistlib.loads(blob)

            # Handle both $objects[] format and direct dict
            file_data = None
            if '$objects' in plist:
                objects = plist.get('$objects', [])
                for obj in objects:
                    if isinstance(obj, dict) and '$class' in obj:
                        file_data = obj
                        break
            elif isinstance(plist, dict):
                file_data = plist

            if not file_data:
                continue

            # Count fields (original code)
            for key in file_data.keys():
                if not key.startswith('$'):
                    field_counts[key] += 1

            # Check EncryptionKey type
            if 'EncryptionKey' in file_data:
                enc_key = file_data['EncryptionKey']
                if isinstance(enc_key, plistlib.UID):
                    enc_key_types['UID reference'] += 1
                elif isinstance(enc_key, bytes):
                    enc_key_types['inline bytes'] += 1
                else:
                    enc_key_types[type(enc_key).__name__] += 1

            # LINK DETECTION

            # 1. Hard Links: Group by InodeNumber
            if 'InodeNumber' in file_data:
                inode = file_data['InodeNumber']
                if inode:  # Only if it has a value
                    inode_groups[inode].append({
                        'fileID': fileID,
                        'domain': domain,
                        'path': rel_path,
                        'birth': file_data.get('Birth', 'N/A')
                    })
            else:
                no_inode_files.append({
                    'fileID': fileID,
                    'domain': domain,
                    'path': rel_path
                })

            # 2. Symbolic Links: Look for Target field
            if 'Target' in file_data or 'LinkTarget' in file_data:
                target = file_data.get('Target') or file_data.get('LinkTarget')
                symlinks.append({
                    'fileID': fileID,
                    'domain': domain,
                    'path': rel_path,
                    'target': target
                })

            # 3. Also detect by Mode (symlinks have mode 0o120xxx)
            if 'Mode' in file_data:
                mode = file_data['Mode']
                # S_IFLNK = 0o120000 in Unix
                if mode & 0o120000 == 0o120000:
                    if not any(s['fileID'] == fileID for s in symlinks):
                        symlinks.append({
                            'fileID': fileID,
                            'domain': domain,
                            'path': rel_path,
                            'target': file_data.get('Target', 'UNKNOWN'),
                            'mode': oct(mode)
                        })

        except Exception as e:
            pass

    conn.close()

    return field_counts, enc_key_types, inode_groups, symlinks, no_inode_files, total


def analyze_configuration_profiles_links(db_path: Path, inode_groups: dict):
    """
    Analyzes ConfigurationProfiles entries for link patterns.

    Args:
        db_path: Path to Manifest.db file
        inode_groups: Pre-computed inode groups from analyze_manifest()
    """
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Search for ConfigurationProfiles
    cursor.execute("""
        SELECT fileID, domain, relativePath, file
        FROM Files
        WHERE relativePath LIKE '%ConfigurationProfiles%'
        AND file IS NOT NULL
    """)

    print(f"\n=== ConfigurationProfiles Link Analysis ===")

    for fileID, domain, rel_path, blob in cursor:
        try:
            plist = plistlib.loads(blob)
            file_data = None
            if '$objects' in plist:
                objects = plist.get('$objects', [])
                for obj in objects:
                    if isinstance(obj, dict) and '$class' in obj:
                        file_data = obj
                        break
            elif isinstance(plist, dict):
                file_data = plist

            if file_data and 'InodeNumber' in file_data:
                inode = file_data['InodeNumber']
                count = len(inode_groups.get(inode, []))
                if count > 1:
                    print(f"  [LINKED] {rel_path}")
                    print(f"     Inode: {inode} (shared with {count-1} other files)")
                else:
                    print(f"  [unique] {rel_path} (Inode: {inode})")

        except:
            pass

    conn.close()


def print_report(field_counts: Counter, enc_key_types: Counter,
                inode_groups: dict, symlinks: list,
                no_inode_files: list, total: int):
    """
    Prints formatted analysis report.

    Args:
        field_counts: Counter of field occurrences
        enc_key_types: Counter of EncryptionKey types
        inode_groups: Dict mapping inodes to file lists
        symlinks: List of symlink entries
        no_inode_files: List of files without InodeNumber
        total: Total files processed
    """
    # ORIGINAL REPORT
    print("=== Fields Present in File Blobs ===")
    for field, count in field_counts.most_common():
        print(f"  {field}: {count}/{total}")
    print()
    print("=== EncryptionKey Types ===")
    for enc_type, count in enc_key_types.most_common():
        print(f"  {enc_type}: {count}")

    # HARD LINKS REPORT (multiple files, same inode)
    print(f"\n=== Hard Links Detected (shared InodeNumber) ===")
    hardlink_count = 0
    for inode, files in inode_groups.items():
        if len(files) > 1:  # If more than one file shares the same inode
            hardlink_count += 1
            print(f"\n  Inode {inode} ({len(files)} links):")
            for f in files:
                print(f"    [{f['domain']}] {f['path']}")
                print(f"       fileID: {f['fileID'][:16]}... | Birth: {f['birth']}")

    if hardlink_count == 0:
        print("  No hard links detected (all files have unique InodeNumbers)")

    # SYMBOLIC LINKS REPORT
    print(f"\n=== Symbolic Links Detected ===")
    if symlinks:
        for link in symlinks:
            print(f"\n  [{link['domain']}] {link['path']}")
            print(f"    -> {link['target']}")
            print(f"    fileID: {link['fileID'][:16]}...")
            if 'mode' in link:
                print(f"    mode: {link['mode']}")
    else:
        print("  No symbolic links detected")

    # FILES WITHOUT INODE REPORT
    print(f"\n=== Files without InodeNumber ===")
    if no_inode_files:
        for f in no_inode_files:
            print(f"  [{f['domain']}] {f['path']} (fileID: {f['fileID'][:16]}...)")

    # FILES WITH INODE=0 REPORT
    zero_inode_files = [f for f in inode_groups.get(0, [])]
    if zero_inode_files:
        print(f"\n=== Files with InodeNumber = 0 ===")
        for f in zero_inode_files:
            print(f"  [{f['domain']}] {f['path']} (fileID: {f['fileID'][:16]}...)")


def main():
    """Main entry point for the script."""
    if len(sys.argv) != 2:
        print("Usage: python3 dump-manifestdb.py /path/to/Manifest.db")
        sys.exit(1)

    db_path = Path(sys.argv[1])

    if not db_path.exists():
        print(f"Error: Manifest.db not found at {db_path}")
        sys.exit(1)

    field_counts, enc_key_types, inode_groups, symlinks, no_inode_files, total = analyze_manifest(db_path)

    print_report(field_counts, enc_key_types, inode_groups, symlinks, no_inode_files, total)
    analyze_configuration_profiles_links(db_path, inode_groups)


if __name__ == "__main__":
    main()
