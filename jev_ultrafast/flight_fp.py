"""flight_fp: Python shim over the `flightfp` Go binary.

Prefers the compiled Go fingerprinter (parallel sha256, no GIL);
falls back to hashlib so callers never depend on the binary.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def find_bin() -> Path | None:
    here = Path(__file__).resolve()
    for cand in (
        here.parent.parent / "flightfp" / "flightfp",
        here.parent.parent / "flightfp" / "flightfp.exe",
    ):
        if cand.is_file():
            return cand
    found = shutil.which("flightfp")
    return Path(found) if found else None


def fingerprint_dir(directory: str | Path, ext: str = ".json") -> dict[str, str] | None:
    exe = find_bin()
    if exe is None:
        return None
    try:
        proc = subprocess.run(
            [str(exe), "--dir", str(directory), "--ext", ext],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    out: dict[str, str] = {}
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "name" in obj and "sha256" in obj:
            out[obj["name"]] = obj["sha256"]
    return out


def sha_bytes(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()
