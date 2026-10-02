"""Small bounded subprocess runner; no shell, no unbounded output capture."""
import os
import selectors
import signal
import subprocess
import time


class ProcessError(RuntimeError):
    pass


def run_bounded(argv, timeout=30, max_bytes=1024 * 1024, cwd=None, env=None, accepted=(0,)):
    started = time.monotonic()
    process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
    selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    try:
        while selector.get_map():
            if time.monotonic() - started >= timeout:
                raise ProcessError(f'process timeout after {timeout}s')
            for key, _ in selector.select(min(0.1, max(0.001, timeout - (time.monotonic() - started)))):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output[key.data].extend(chunk)
                if sum(len(part) for part in output.values()) > max_bytes:
                    raise ProcessError(f'process output exceeds {max_bytes} bytes')
        code = process.wait(timeout=max(0.01, timeout - (time.monotonic() - started)))
        if code not in accepted:
            detail = bytes(output['stderr']).decode('utf-8', errors='replace')[-2000:]
            raise ProcessError(f'process exited {code}: {detail}')
        return bytes(output['stdout']).decode('utf-8', errors='replace')
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        process.stdout.close()
        process.stderr.close()
