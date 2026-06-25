#!/usr/bin/env python3
"""
Tool Name:   integrity-check
Description: Log File Integrity Monitor — detects tampering via SHA-256 hashing
Author:      Dipesh
Version:     1.0
Usage:
    ./integrity-check init <path>          # Initialize hash store for a file or directory
    ./integrity-check check <path>         # Check integrity of a file or directory
    ./integrity-check update <path>        # Re-hash and update stored hash for a file/dir
    ./integrity-check list                 # List all tracked files and their status
    ./integrity-check reset                # Wipe the entire hash store (re-initialize from scratch)
"""

import argparse
import hashlib
import json
import os
import sys
import stat
import hmac
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, List

# ── Config ──────────────────────────────────────────────────────────────────
HASH_STORE_PATH = Path.home() / ".integrity_check" / "hashstore.json"
HASH_ALGORITHM  = "sha256"
CHUNK_SIZE      = 65536   # 64 KB read chunks for large file support

# ANSI color codes for terminal output
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ── Hashing ──────────────────────────────────────────────────────────────────
def compute_hash(filepath: Path) -> Optional[str]:
    """Compute SHA-256 hash of a file in chunks (handles large files)."""
    h = hashlib.new(HASH_ALGORITHM)
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                h.update(chunk)
        return h.hexdigest()
    except PermissionError:
        print(f"{YELLOW}[WARN]{RESET} Permission denied: {filepath}")
        return None
    except FileNotFoundError:
        print(f"{YELLOW}[WARN]{RESET} File not found: {filepath}")
        return None
    except OSError as e:
        print(f"{YELLOW}[WARN]{RESET} Could not read {filepath}: {e}")
        return None

# ── Hash Store I/O ────────────────────────────────────────────────────────────
def load_store() -> dict:
    """Load the hash store from disk. Returns empty dict if not initialized."""
    if not HASH_STORE_PATH.exists():
        return {}
    try:
        with open(HASH_STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"{RED}[ERROR]{RESET} Failed to read hash store: {e}")
        sys.exit(1)

def save_store(store: dict) -> None:
    """Persist hash store to disk with restrictive permissions (owner read/write only)."""
    HASH_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(HASH_STORE_PATH, "w", encoding="utf-8") as f:
            json.dump(store, f, indent=2)
        # Lock down permissions: chmod 600
        os.chmod(HASH_STORE_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        print(f"{RED}[ERROR]{RESET} Failed to write hash store: {e}")
        sys.exit(1)

# ── File Collection ───────────────────────────────────────────────────────────
def collect_files(path: Path) -> List[Path]:
    """Collect all readable files from a path (file or directory, recursive)."""
    if path.is_file():
        return [path.resolve()]
    elif path.is_dir():
        files = sorted(
            f.resolve() for f in path.rglob("*")
            if f.is_file() and not f.is_symlink()
        )
        if not files:
            print(f"{YELLOW}[WARN]{RESET} No files found in directory: {path}")
        return files
    else:
        print(f"{RED}[ERROR]{RESET} Path does not exist or is not accessible: {path}")
        sys.exit(1)

# ── Commands ──────────────────────────────────────────────────────────────────
def cmd_init(path: Path, force: bool = False) -> None:
    """Initialize hash store with hashes of all files at the given path."""
    store = load_store()
    files = collect_files(path)

    initialized = 0
    skipped     = 0

    for filepath in files:
        key = str(filepath)
        if key in store and not force:
            print(f"  {YELLOW}[SKIP]{RESET}  Already tracked: {filepath}")
            skipped += 1
            continue

        file_hash = compute_hash(filepath)
        if file_hash:
            store[key] = {
                "hash":        file_hash,
                "algorithm":   HASH_ALGORITHM,
                "initialized": datetime.now().isoformat(),
                "last_checked": None,
                "last_updated": None,
            }
            print(f"  {GREEN}[INIT]{RESET}  {filepath}")
            initialized += 1

    save_store(store)
    print(f"\n{BOLD}Hashes stored successfully.{RESET}")
    print(f"  Initialized : {initialized}")
    if skipped:
        print(f"  Skipped     : {skipped}  (already tracked — use --force to re-init)")

def cmd_check(path: Path) -> None:
    """Compare current hashes against stored baseline."""
    store = load_store()
    if not store:
        print(f"{RED}[ERROR]{RESET} Hash store is empty. Run 'init' first.")
        sys.exit(1)

    files   = collect_files(path)
    results = {"unmodified": [], "modified": [], "new": [], "missing": []}

    for filepath in files:
        key       = str(filepath)
        cur_hash  = compute_hash(filepath)
        if cur_hash is None:
            continue

        if key not in store:
            results["new"].append(filepath)
            print(f"  {CYAN}[NEW]{RESET}       {filepath}  — not in baseline")
        elif cur_hash == store[key]["hash"]:
            results["unmodified"].append(filepath)
            print(f"  {GREEN}[OK]{RESET}        {filepath}")
            print(f"              Status: Unmodified")
            # Update last_checked timestamp
            store[key]["last_checked"] = datetime.now().isoformat()
        else:
            results["modified"].append(filepath)
            print(f"  {RED}[TAMPERED]{RESET}  {filepath}")
            print(f"              Status: {RED}Modified (Hash mismatch){RESET}")
            print(f"              Expected : {store[key]['hash']}")
            print(f"              Got      : {cur_hash}")
            store[key]["last_checked"] = datetime.now().isoformat()

    # Check for files in store that no longer exist on disk
    checked_keys = {str(f) for f in files}
    for key in store:
        if key.startswith(str(path.resolve())) and key not in checked_keys:
            results["missing"].append(key)
            print(f"  {RED}[MISSING]{RESET}   {key}  — tracked file no longer exists!")

    save_store(store)

    # Summary
    total = sum(len(v) for v in results.values())
    print(f"\n{BOLD}── Summary ────────────────────────────────{RESET}")
    print(f"  Files checked  : {total}")
    print(f"  {GREEN}Unmodified{RESET}     : {len(results['unmodified'])}")
    print(f"  {RED}Modified{RESET}       : {len(results['modified'])}")
    print(f"  {RED}Missing{RESET}        : {len(results['missing'])}")
    print(f"  {CYAN}New (untracked){RESET}: {len(results['new'])}")

    if results["modified"] or results["missing"]:
        print(f"\n{RED}{BOLD}⚠  INTEGRITY VIOLATIONS DETECTED{RESET}")
        sys.exit(2)   # Non-zero exit for scripting / SIEM alerting

def cmd_update(path: Path) -> None:
    """Re-hash file(s) and update the stored baseline."""
    store = load_store()
    files = collect_files(path)
    updated = 0

    for filepath in files:
        key      = str(filepath)
        new_hash = compute_hash(filepath)
        if new_hash is None:
            continue

        action = "Updated" if key in store else "Added"
        store[key] = {
            "hash":         new_hash,
            "algorithm":    HASH_ALGORITHM,
            "initialized":  store.get(key, {}).get("initialized", datetime.now().isoformat()),
            "last_checked": store.get(key, {}).get("last_checked"),
            "last_updated": datetime.now().isoformat(),
        }
        print(f"  {GREEN}[{action.upper()}]{RESET}  {filepath}")
        updated += 1

    save_store(store)
    print(f"\n{BOLD}Hash updated successfully.{RESET}  ({updated} file(s))")

def cmd_list() -> None:
    """List all tracked files with their metadata."""
    store = load_store()
    if not store:
        print("Hash store is empty. Run 'init <path>' to start tracking.")
        return

    print(f"\n{BOLD}{'File':<70}  {'Algorithm':<8}  {'Initialized':<20}  {'Last Checked':<20}{RESET}")
    print("─" * 130)
    for filepath, meta in sorted(store.items()):
        initialized  = meta.get("initialized", "—")[:19]
        last_checked = meta.get("last_checked") or "—"
        if last_checked != "—":
            last_checked = last_checked[:19]
        algo = meta.get("algorithm", "sha256")
        exists_marker = "" if Path(filepath).exists() else f"  {RED}[MISSING]{RESET}"
        print(f"  {filepath:<70}  {algo:<8}  {initialized:<20}  {last_checked:<20}{exists_marker}")

    print(f"\n{BOLD}Total tracked files: {len(store)}{RESET}")
    print(f"Store location     : {HASH_STORE_PATH}")

def cmd_reset() -> None:
    """Wipe the entire hash store after confirmation."""
    if not HASH_STORE_PATH.exists():
        print("Hash store does not exist. Nothing to reset.")
        return

    store = load_store()
    count = len(store)
    confirm = input(f"{YELLOW}This will remove all {count} stored hashes. Type 'YES' to confirm: {RESET}")
    if confirm.strip() != "YES":
        print("Aborted.")
        return

    HASH_STORE_PATH.unlink()
    print(f"{GREEN}Hash store reset. All {count} entries removed.{RESET}")

# ── Entry Point ───────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="integrity-check",
        description="Log File Integrity Monitor — detect tampering via SHA-256 hashing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  init <path>     Compute and store baseline hashes for a file or directory
  check <path>    Verify current hashes against baseline
  update <path>   Re-hash and refresh stored hash for a file or directory
  list            Display all tracked files and their metadata
  reset           Wipe the entire hash store

Examples:
  ./integrity-check init /var/log
  ./integrity-check check /var/log/syslog
  ./integrity-check update /var/log/auth.log
  ./integrity-check list
  ./integrity-check reset
        """
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # init
    p_init = subparsers.add_parser("init", help="Initialize hash baseline")
    p_init.add_argument("path", type=Path, help="File or directory to hash")
    p_init.add_argument("--force", action="store_true",
                        help="Re-initialize already-tracked files")

    # check
    p_check = subparsers.add_parser("check", help="Verify file integrity")
    p_check.add_argument("path", type=Path, help="File or directory to check")

    # update
    p_update = subparsers.add_parser("update", help="Update stored hash")
    p_update.add_argument("path", type=Path, help="File or directory to re-hash")

    # list
    subparsers.add_parser("list", help="List all tracked files")

    # reset
    subparsers.add_parser("reset", help="Wipe entire hash store")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "init":
        cmd_init(args.path, force=args.force)
    elif args.command == "check":
        cmd_check(args.path)
    elif args.command == "update":
        cmd_update(args.path)
    elif args.command == "list":
        cmd_list()
    elif args.command == "reset":
        cmd_reset()

if __name__ == "__main__":
    main()
