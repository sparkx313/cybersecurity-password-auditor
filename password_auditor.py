"""Offline password policy audit; never accepts a password as a command-line argument."""

from __future__ import annotations

import argparse
import getpass
import sys
import warnings
from pathlib import Path


class AuditError(ValueError):
    """Raised when hidden input or a local blocklist cannot be read."""


def load_blocklist(path: Path | None) -> set[str]:
    if path is None:
        return set()
    try:
        entries = path.expanduser().read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError) as exc:
        raise AuditError(f"Could not read local blocklist: {exc}") from exc
    return {entry for entry in entries if entry and not entry.lstrip().startswith("#")}


def audit_password(password: str, minimum_length: int, blocklist: set[str]) -> list[str]:
    issues = []
    length = len(password)
    if length < minimum_length:
        issues.append(f"Password is {length} Unicode code points; minimum is {minimum_length}.")
    if password in blocklist:
        issues.append("Password exactly matches an entry in the supplied local blocklist.")
    return issues


def read_hidden_password() -> str:
    if not sys.stdin.isatty():
        raise AuditError("Password audit requires an interactive terminal; password input is never read from a pipe.")
    with warnings.catch_warnings(record=True) as observed:
        warnings.simplefilter("always", getpass.GetPassWarning)
        try:
            password = getpass.getpass("Password to audit (input hidden): ")
        except (EOFError, KeyboardInterrupt) as exc:
            raise AuditError("Password input was cancelled.") from exc
    if any(issubclass(item.category, getpass.GetPassWarning) for item in observed):
        raise AuditError("Could not disable terminal echo; refusing to audit this input.")
    return password


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check a password against a length policy and an optional local blocklist."
    )
    parser.add_argument(
        "--mode",
        choices=("single-factor", "mfa"),
        default="single-factor",
        help="single-factor uses a 15-code-point minimum; mfa uses 8",
    )
    parser.add_argument(
        "--blocklist",
        type=Path,
        help="optional local file with one exact password per line",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    minimum_length = 15 if args.mode == "single-factor" else 8
    try:
        blocklist = load_blocklist(args.blocklist)
        password = read_hidden_password()
        issues = audit_password(password, minimum_length, blocklist)
    except AuditError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    # Do not print, hash, persist, or transmit the password.
    print(f"Mode: {args.mode}")
    print(f"Length: {len(password)} Unicode code points (minimum {minimum_length})")
    if args.blocklist:
        print(f"Local blocklist entries checked: {len(blocklist)}")
    if issues:
        print("Policy check failed:")
        for issue in issues:
            print(f"- {issue}")
        return 1
    print("Policy check passed. This does not establish that the password is secret or uncompromised.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())