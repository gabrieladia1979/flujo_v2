"""Start a temporary loopback API and exercise the existing pilot Add-in client.

Uses real JS token signing and real XGBoost. No external services or email sends.
The temporary API process is always stopped. GGUF generation uses offline fallback.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--addin", type=Path, default=ROOT.parent / "Add_in_PFI_hybrid_pilot")
    parser.add_argument("--output", type=Path, default=ROOT / "reports/addin_contract_20261126.json")
    args = parser.parse_args()
    node = shutil.which("node.exe") or shutil.which("node")
    if not node:
        raise RuntimeError("Node.js is required to exercise the real Add-in client")
    with socket.socket() as available:
        available.bind(("127.0.0.1", 0))
        port = available.getsockname()[1]
    environment = os.environ.copy()
    environment.update(PHISHARG_TOKEN_KEY=secrets.token_hex(32), PHISHARG_REPLAY_TABLE="",
        PHISHARG_ENV="development", PHISHARG_CORS_ORIGINS="https://add-in-pfi-hybrid.vercel.app")
    for name in ("AWS_EXECUTION_ENV", "ECS_CONTAINER_METADATA_URI_V4"):
        environment.pop(name, None)
    command = ("from services import slm_client; slm_client.MODEL_PATH='__contract_offline__.gguf'; "
               f"import uvicorn; uvicorn.run('main:app',host='127.0.0.1',port={port},log_level='warning')")
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen([sys.executable, "-c", command], cwd=ROOT, env=environment,
            stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            deadline = time.monotonic() + 45
            url = f"http://127.0.0.1:{port}"
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("Temporary backend stopped before readiness")
                try:
                    with urllib.request.urlopen(url + "/api/v1/health", timeout=1) as response:
                        if json.load(response)["classifier"]["loaded"]:
                            break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("Temporary backend did not become ready")
            result = subprocess.run([node, str(args.addin / "scripts/probe-audit-backend.cjs"), url],
                cwd=args.addin, env=environment, capture_output=True, text=True, timeout=90)
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or "Add-in contract probe failed")
            report = json.loads(result.stdout)
            report["limits"] = ["Loopback transport; no live AWS or Outlook session.",
                                 "Four authored diagnostic emails; not a production accuracy estimate.",
                                 "SLM generation replaced by its offline fallback."]
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
            print(json.dumps(report, ensure_ascii=False))
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
