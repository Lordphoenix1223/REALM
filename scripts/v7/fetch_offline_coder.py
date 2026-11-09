#!/usr/bin/env python3
"""Fetch checksum-pinned public CPU assets. No inference API or authority.

Use only a fresh, task-owned Linux directory with at least 4 GiB free.
Downloads are public, unauthenticated and cannot change cloud billing.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import tarfile
import urllib.request

MODELS = {
    "coder-1.5b": {
        "name": "qwen2.5-coder-1.5b-instruct-q4_k_m.gguf",
        "url": "https://huggingface.co/Qwen/Qwen2.5-Coder-1.5B-Instruct-GGUF/resolve/f86cb2c1fa58255f8052cc32aeede1b7482d4361/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf",
        "bytes": 1117320768,
        "sha256": "cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046",
        "license": "Apache-2.0",
    },
    "qwen3-4b": {
        "name": "Qwen3-4B-Q4_K_M.gguf",
        "url": "https://huggingface.co/Qwen/Qwen3-4B-GGUF/resolve/bc640142c66e1fdd12af0bd68f40445458f3869b/Qwen3-4B-Q4_K_M.gguf",
        "bytes": 2497280256,
        "sha256": "7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5",
        "license": "Apache-2.0",
    },
    "coder-7b": {
        "name": "qwen2.5-coder-7b-instruct-q4_k_m.gguf",
        "url": "https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct-GGUF/resolve/13fb94bfda8c8cf22497dc57b78f391a9acb426a/qwen2.5-coder-7b-instruct-q4_k_m.gguf",
        "bytes": 4683073536,
        "sha256": "509287f78cb4d4cf6b3843734733b914b2c158e43e22a7f4bf5e963800894d3c",
        "license": "Apache-2.0",
    },
}
RUNTIME = {
        "name": "llama-b11541-bin-ubuntu-x64.tar.gz",
        "url": "https://github.com/ggml-org/llama.cpp/releases/download/b11541/llama-b11541-bin-ubuntu-x64.tar.gz",
        "bytes": 17809316,
        "sha256": "36ca310be4405acb7ba59b32dbdce32bb9cd7b1ef95358997b7eaed2c6f0188b",
        "license": "MIT",
}


def assets_for(model):
    return (MODELS[model], RUNTIME)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", required=True, type=pathlib.Path)
    ap.add_argument("--model", choices=sorted(MODELS), default="coder-1.5b")
    args = ap.parse_args()
    assets = assets_for(args.model)
    if not args.root.is_absolute() or args.root.exists():
        ap.error("a fresh absolute task-owned --root is required")
    required = max(4 * 1024**3, sum(a['bytes'] for a in assets) + 512 * 1024**2)
    if shutil.disk_usage(args.root.parent).free < required:
        ap.error("insufficient free space for pinned assets and staging margin: refuse download")
    args.root.mkdir(mode=0o700)
    report = {"authority": "NONE", "assets": [], "runtime_tested": False}
    for asset in assets:
        path = args.root / asset["name"]
        h = hashlib.sha256()
        count = 0
        with urllib.request.urlopen(asset["url"], timeout=60) as response, path.open("xb") as f:
            os.chmod(path, 0o600)
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > asset["bytes"]:
                    raise ValueError("oversized public asset; preserve failed download")
                h.update(chunk)
                f.write(chunk)
            f.flush()
            os.fsync(f.fileno())
        if count != asset["bytes"] or h.hexdigest() != asset["sha256"]:
            raise ValueError("public asset checksum mismatch; preserve failed download")
        report["assets"].append(asset)
        (args.root / "assets.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"verified_download": asset["name"], "sha256": h.hexdigest()}), flush=True)
    runtime = args.root / "runtime"
    runtime.mkdir(mode=0o700)
    with tarfile.open(args.root / assets[1]["name"], "r:gz") as archive:
        archive.extractall(runtime, filter="data")
    # This is acquisition evidence, never model success or containment evidence.
    print(json.dumps({"runtime_files": sorted(str(p.relative_to(runtime)) for p in runtime.rglob("*") if p.is_file())}), flush=True)


if __name__ == "__main__":
    main()
