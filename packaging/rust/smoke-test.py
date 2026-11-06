#!/usr/bin/env python3
"""Check an installed GPUI executable using a disposable state directory."""

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--expect-account", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    for flag in ("--help", "--version"):
        command = [str(binary), flag]
        if sys.platform == "darwin":
            command.insert(0, "/usr/bin/env")
        subprocess.run(command, check=True, capture_output=True, timeout=30)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with tempfile.TemporaryDirectory(prefix="scimtest-gpui-smoke-") as directory:
        directory = Path(directory)
        state = directory / "state.db"
        lock = directory / "state.db.lock"
        env = os.environ.copy()
        env.pop("PORT", None)
        env.pop("SCIMTEST_PORT", None)
        env["SCIMTEST_STATE_FILE"] = str(state)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        previous_url = None
        for launch in range(2):
            command = [str(binary), "--no-open"]
            if launch == 0:
                command += ["--port", str(port)]
            with (directory / "desktop.log").open("w+") as log:
                process = subprocess.Popen(command, env=env, stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            raise RuntimeError("desktop exited during startup")
                        try:
                            metadata = json.loads(lock.read_bytes())
                            request = urllib.request.Request(
                                metadata["url"] + "/-/ready",
                                headers={"X-Scimtest-Instance-Token": metadata["token"]},
                            )
                            with opener.open(request, timeout=1) as response:
                                if response.status == 204:
                                    break
                        except (OSError, ValueError, KeyError, urllib.error.URLError):
                            time.sleep(0.1)
                    else:
                        raise RuntimeError("private readiness check did not succeed")
                    if previous_url and previous_url != metadata["url"]:
                        raise RuntimeError("restart changed the saved port")
                    previous_url = metadata["url"]
                    if args.expect_account and not metadata.get("github_account_required"):
                        raise RuntimeError("release does not require GitHub enrollment")
                    if sys.platform.startswith("linux"):
                        deadline = time.monotonic() + 30
                        while time.monotonic() < deadline:
                            window = subprocess.run(
                                ["xdotool", "search", "--pid", str(process.pid), "--name", "scimtest"],
                                capture_output=True,
                            )
                            if window.returncode == 0 and window.stdout.strip():
                                break
                            if process.poll() is not None:
                                raise RuntimeError("desktop exited before opening its window")
                            time.sleep(0.1)
                        else:
                            raise RuntimeError("native GPUI window did not appear")
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as pending:
                        # Keep an unfinished request open during bounded shutdown.
                        pending.sendall(b"GET /-/ready HTTP/1.1\r\nHost: localhost\r\n")
                        time.sleep(0.5)
                        process.send_signal(signal.SIGTERM)
                        if process.wait(timeout=10) != 0:
                            raise RuntimeError("desktop shutdown failed")
                    if lock.read_bytes():
                        raise RuntimeError("desktop did not clear its instance metadata")
                except Exception:
                    log.seek(0)
                    print(log.read(), file=sys.stderr)
                    raise
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
    print("GPUI startup, readiness, saved-port restart, and shutdown passed")


if __name__ == "__main__":
    main()
