"""Verify hosted Go/Rust browser workflows using disposable local fixtures."""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.request


def command(args, directory, log):
    result = subprocess.run(args, cwd=directory, capture_output=True, text=True)
    log.write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed; see {log}")
    return result.stdout


def verify(root, output, backend):
    session = f"scimtest-hosted-{backend.lower()}-{os.getpid()}"
    ready = output / f"{backend.lower()}-ready.json"
    fixture_log = output / f"{backend.lower()}-fixture.log"
    environment = os.environ.copy()
    environment.update({
        "GOFLAGS": "-mod=readonly",
        "SCIMTEST_HOSTED_BROWSER_READY": str(ready),
        "SCIMTEST_HOSTED_BROWSER_BACKEND": backend,
    })
    info = None
    browser_open = False
    with fixture_log.open("w") as log:
        fixture = subprocess.Popen([
            "cargo", "test", "-p", "scimtest-server", "--lib", "--locked",
            "run_hosted_browser_fixture", "--", "--ignored", "--nocapture",
        ], cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True)
        try:
            deadline = time.monotonic() + 120
            while not ready.exists():
                if fixture.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f"Fixture did not start; see {fixture_log}")
                time.sleep(0.05)
            info = json.loads(ready.read_text())
            info["artifacts"] = str(output)
            command(["playwright-cli", f"-s={session}", "open"], output,
                    output / f"{backend.lower()}-browser-open.log")
            browser_open = True
            source = Path(__file__).with_name("workflow.js").read_text()
            script = output / f"{backend.lower()}-workflow.js"
            script.write_text(source.replace("__INFO__", json.dumps(info)))
            text = command([
                "playwright-cli", f"-s={session}", "run-code",
                f"--filename={script}",
            ], output, output / f"{backend.lower()}-workflow.log")
            result = json.loads(text.split("### Result\n", 1)[1].splitlines()[0])
            if not result["passed"] or result["errors"]:
                raise RuntimeError(f"Browser checks failed for {backend}")
            (output / f"{backend.lower()}-result.json").write_text(
                json.dumps(result, indent=2) + "\n")
        finally:
            browser_error = None
            if browser_open:
                try:
                    command(["playwright-cli", f"-s={session}", "close"], output,
                            output / f"{backend.lower()}-browser-close.log")
                except (OSError, RuntimeError) as error:
                    browser_error = error
            if info and fixture.poll() is None:
                request = urllib.request.Request(info["control"],
                    data=b'{"action":"stop"}', headers={
                        "Authorization": "Bearer " + info["control_token"],
                        "Content-Type": "application/json",
                    })
                try:
                    with urllib.request.urlopen(request, timeout=5) as response:
                        if json.load(response) != {"stopped": True}:
                            raise RuntimeError("Fixture did not accept shutdown")
                except (OSError, RuntimeError):
                    os.killpg(fixture.pid, signal.SIGTERM)
            try:
                status = fixture.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(fixture.pid, signal.SIGKILL)
                fixture.wait()
                raise RuntimeError(f"Fixture did not stop; see {fixture_log}")
            if status:
                raise RuntimeError(f"Fixture failed; see {fixture_log}")
            if info and Path(info["state"]).exists():
                raise RuntimeError("Disposable server state was not removed")
            if browser_error:
                raise browser_error
    return backend


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--backend", choices=["Go", "Rust", "both"], default="both")
    args = parser.parse_args()
    if not shutil.which("playwright-cli"):
        raise SystemExit("playwright-cli is required")
    root = Path(__file__).resolve().parents[4]
    parent = (args.output_dir or root / "build/rust-hosted-browser").resolve()
    parent.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
    backends = ["Go", "Rust"] if args.backend == "both" else [args.backend]
    completed = [verify(root, output, backend) for backend in backends]
    (output / "complete.json").write_text(json.dumps({
        "passed": True, "backends": completed,
        "provider": "local HTTP stub", "disposable_state_removed": True,
    }, indent=2) + "\n")
    print(output)


if __name__ == "__main__":
    main()
