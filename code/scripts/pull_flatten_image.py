#!/usr/bin/env python3
"""Download a Docker Hub image and flatten all layer uids/gids to 0 for rootless runc."""

from __future__ import annotations

import json
import sys
import tarfile
import urllib.request
from pathlib import Path


def token(repo: str) -> str:
    url = (
        "https://auth.docker.io/token?service=registry.docker.io"
        f"&scope=repository:{repo}:pull"
    )
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.loads(r.read().decode())["token"]


def get_json(url: str, tok: str, accept: str) -> dict:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {tok}", "Accept": accept})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


def download(url: str, tok: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {tok}"})
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(req, timeout=600) as r, dest.open("wb") as f:
        while True:
            chunk = r.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)


def flatten_layer(src: Path, dest_root: Path) -> None:
    with tarfile.open(src, "r:*") as tf:
        for member in tf.getmembers():
            member.uid = 0
            member.gid = 0
            member.uname = "root"
            member.gname = "root"
            # Skip dangerous absolute/parent paths
            name = member.name.lstrip("./")
            if name.startswith("/") or ".." in Path(name).parts:
                continue
            if member.isdev() or member.isfifo() or member.ischr() or member.isblk():
                continue
            try:
                tf.extract(member, path=dest_root, set_attrs=False)
            except PermissionError:
                continue


def pull(repo: str, tag: str, out_root: Path) -> Path:
    tok = token(repo)
    accept = (
        "application/vnd.docker.distribution.manifest.list.v2+json,"
        "application/vnd.oci.image.index.v1+json,"
        "application/vnd.docker.distribution.manifest.v2+json,"
        "application/vnd.oci.image.manifest.v1+json"
    )
    manifest = get_json(f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}", tok, accept)
    if manifest.get("mediaType", "").endswith("manifest.list.v2+json") or "manifests" in manifest:
        # pick amd64
        chosen = None
        for m in manifest["manifests"]:
            plat = m.get("platform") or {}
            if plat.get("architecture") in {"amd64", "x86_64"} and plat.get("os", "linux") == "linux":
                chosen = m["digest"]
                break
        if not chosen:
            chosen = manifest["manifests"][0]["digest"]
        manifest = get_json(
            f"https://registry-1.docker.io/v2/{repo}/manifests/{chosen}",
            tok,
            "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json",
        )
    layers = manifest.get("layers") or []
    if not layers:
        raise SystemExit(f"no layers in manifest keys={list(manifest)}")
    rootfs = out_root / "rootfs"
    rootfs.mkdir(parents=True, exist_ok=True)
    blobs = out_root / "blobs"
    for i, layer in enumerate(layers):
        digest = layer["digest"]
        blob_path = blobs / digest.replace(":", "_")
        if not blob_path.exists():
            print(f"downloading layer {i+1}/{len(layers)} {digest}", flush=True)
            download(f"https://registry-1.docker.io/v2/{repo}/blobs/{digest}", tok, blob_path)
        print(f"extracting {blob_path.name}", flush=True)
        flatten_layer(blob_path, rootfs)
    (out_root / "image.json").write_text(json.dumps({"repo": repo, "tag": tag, "layers": len(layers)}, indent=2))
    print(f"rootfs ready at {rootfs}")
    return rootfs


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("usage: pull_flatten_image.py <repo> <tag> <out_dir>", file=sys.stderr)
        raise SystemExit(2)
    pull(sys.argv[1], sys.argv[2], Path(sys.argv[3]))
