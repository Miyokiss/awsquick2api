"""OS-released account lock shared by gateway processes using one data directory."""
from __future__ import annotations

import asyncio
import hashlib
import os
import time
from contextlib import asynccontextmanager


@asynccontextmanager
async def credential_lock(directory, account_id, timeout=120):
    folder = directory / 'auth-locks'
    folder.mkdir(exist_ok=True)
    path = folder / (hashlib.sha256(account_id.encode()).hexdigest() + '.lock')
    with path.open('a+b') as handle:
        if path.stat().st_size == 0:
            handle.write(b'0')
            handle.flush()
        deadline = time.monotonic() + timeout
        while True:
            try:
                handle.seek(0)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError('Credential refresh lock timed out') from None
                await asyncio.sleep(.05)
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
