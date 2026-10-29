"""Reader/writer advisory lock on a persistent lock file.

Parsers hold a *shared* lock while they read a clone; a refresh holds an *exclusive* lock,
so ``checkout --force`` never changes files under a running parse. Properties:

* the lock file is created once and never deleted: no create/delete churn (which on Amazon
  S3 Files would become S3 objects, versions and delete markers);
* locks are advisory and die with the process, so a crashed holder cannot leave a stale
  lock. There is no stale-lock cleanup to get wrong;
* POSIX uses ``flock`` (EFS / NFSv4 / S3 Files implement it with byte-range locks);
  Windows uses ``LockFileEx``.

One lock per repo_key, never per blob: S3 Files caps locks per file and per mount.
"""

from __future__ import annotations

import contextlib
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import IO

from trigpoint.errors import LockTimeoutError

_POLL_SECONDS = 0.05

if sys.platform == "win32":  # pragma: no cover - exercised on Windows only
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class _Overlapped(ctypes.Structure):
        _fields_ = (
            ("Internal", ctypes.c_void_p),
            ("InternalHigh", ctypes.c_void_p),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        )

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.LockFileEx.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_Overlapped),
    )
    _kernel32.LockFileEx.restype = wintypes.BOOL
    _kernel32.UnlockFileEx.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_Overlapped),
    )
    _kernel32.UnlockFileEx.restype = wintypes.BOOL
    _FAIL_IMMEDIATELY = 0x1
    _EXCLUSIVE = 0x2
    _BUSY_ERRORS = frozenset({32, 33, 997})  # sharing/lock violation, io pending

    def _try_lock(fh: IO[bytes], exclusive: bool) -> bool:
        handle = msvcrt.get_osfhandle(fh.fileno())
        flags = _FAIL_IMMEDIATELY | (_EXCLUSIVE if exclusive else 0)
        if _kernel32.LockFileEx(handle, flags, 0, 1, 0, ctypes.byref(_Overlapped())):
            return True
        err = ctypes.get_last_error()
        if err in _BUSY_ERRORS:
            return False
        raise ctypes.WinError(err)

    def _unlock(fh: IO[bytes]) -> None:
        handle = msvcrt.get_osfhandle(fh.fileno())
        _kernel32.UnlockFileEx(handle, 0, 1, 0, ctypes.byref(_Overlapped()))

else:
    import fcntl

    def _try_lock(fh: IO[bytes], exclusive: bool) -> bool:
        op = (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB
        try:
            fcntl.flock(fh.fileno(), op)
        except BlockingIOError:
            return False
        return True

    def _unlock(fh: IO[bytes]) -> None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


class RepoLock:
    """Shared/exclusive lock over one repository directory."""

    def __init__(self, path: Path) -> None:
        self._path = path

    @contextlib.contextmanager
    def shared(self, timeout: float = 120.0) -> Iterator[None]:
        with self._hold(exclusive=False, timeout=timeout):
            yield

    @contextlib.contextmanager
    def exclusive(self, timeout: float = 120.0) -> Iterator[None]:
        with self._hold(exclusive=True, timeout=timeout):
            yield

    @contextlib.contextmanager
    def _hold(self, *, exclusive: bool, timeout: float) -> Iterator[None]:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # "a+b": readable and writable (NFS needs write access for an exclusive lock),
        # created if missing, never truncated.
        fh = self._path.open("a+b")
        try:
            deadline = time.monotonic() + timeout
            while not _try_lock(fh, exclusive):
                if time.monotonic() >= deadline:
                    kind = "exclusive" if exclusive else "shared"
                    raise LockTimeoutError(f"timed out after {timeout}s waiting for {kind} lock")
                time.sleep(_POLL_SECONDS)
            try:
                yield
            finally:
                _unlock(fh)
        finally:
            fh.close()
