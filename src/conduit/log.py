from __future__ import annotations

_verbose: bool = False


def set_verbose(enabled: bool) -> None:
    global _verbose
    _verbose = enabled


def is_verbose() -> bool:
    return _verbose


def info(msg: str) -> None:
    """Action in progress."""
    print(f"[*] {msg}")


def ok(msg: str) -> None:
    """Success or result."""
    print(f"[+] {msg}")


def warn(msg: str) -> None:
    """Warning or non-fatal error."""
    print(f"[!] {msg}")


def detail(msg: str) -> None:
    """Detail line, only shown in verbose mode."""
    if _verbose:
        print(f"    {msg}")


def cmd(parts: list[str]) -> None:
    """Log a shell command (always shown in verbose, prefix with $)."""
    if _verbose:
        import shlex
        print(f"  $ {' '.join(shlex.quote(x) for x in parts)}")


def always(msg: str) -> None:
    """Detail line shown regardless of verbose mode."""
    print(f"    {msg}")
