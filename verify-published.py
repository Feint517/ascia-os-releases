#!/usr/bin/env python3
"""Assert the published manifest describes artifacts that actually exist (Step 3.4).

    python3 verify-published.py [stable.manifest.json ...]

Run in CI on every push to this repository. It reads only public artifacts and needs **no secrets**,
which is the point: the manifest signing key stays on the machine that builds the OS, and this
still catches a manifest that lies.

What it checks, and why each one has a way of going wrong:

* **the bundle exists at the URL the manifest names** — the ordering trap. Publish the manifest
  before uploading the asset and every appliance sees a release it cannot download.
* **its size and sha256 match** — a re-uploaded or truncated asset leaves the manifest describing
  bytes that are no longer there. Appliances would download it and fail the digest check, which
  looks like corruption rather than a publishing mistake.
* **the signature verifies against the ASCIA root** — catches a manifest edited after signing, and
  a signature that was never regenerated after the manifest changed.

The digest is computed by streaming, so a wrong `size` cannot make this quietly load a multi-GB file
into memory.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import sys
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = pathlib.Path(__file__).with_name("ascia-root.crt.pem")
MAX_BYTES = 4 * 1024**3


def fetch_digest(url: str) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    with urllib.request.urlopen(url, timeout=120) as r:
        while chunk := r.read(1024 * 1024):
            n += len(chunk)
            if n > MAX_BYTES:
                raise SystemExit(f"FAIL: {url} exceeds {MAX_BYTES} bytes; refusing to keep reading")
            h.update(chunk)
    return h.hexdigest(), n


def check_signature(manifest: pathlib.Path) -> str:
    sig_path = manifest.with_suffix(manifest.suffix + ".sig")
    if not sig_path.exists():
        raise SystemExit(f"FAIL: {manifest.name} has no signature at {sig_path.name}")
    side = json.loads(sig_path.read_text())
    leaf = x509.load_pem_x509_certificate(side["certificate"].encode())
    root = x509.load_pem_x509_certificate(ROOT.read_bytes())
    root.public_key().verify(
        leaf.signature, leaf.tbs_certificate_bytes, padding.PKCS1v15(), leaf.signature_hash_algorithm
    )
    leaf.public_key().verify(
        base64.b64decode(side["signature"]),
        manifest.read_bytes(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )
    cn = leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return cn[0].value if cn else "<unnamed>"


def main(argv: list[str]) -> int:
    targets = [pathlib.Path(a) for a in argv] or sorted(
        pathlib.Path(__file__).parent.glob("*.manifest.json")
    )
    if not targets:
        print("FAIL: no manifest found to verify")
        return 1

    failures = 0
    for path in targets:
        print(f"== {path.name}")
        try:
            print(f"   signature ok, signed by {check_signature(path)}")
        except SystemExit:
            raise
        except Exception as exc:
            # `InvalidSignature` stringifies to nothing, so reporting `{exc}` alone produces
            # "FAIL signature:" and leaves a person with no idea what to do. Name the likely cause.
            detail = str(exc) or type(exc).__name__
            print(f"   FAIL signature: {detail}")
            print("      The manifest and its .sig disagree. Either the manifest was edited after")
            print("      signing, or it was regenerated without re-signing. Re-run feed/publish.sh")
            print("      rather than editing either file by hand.")
            failures += 1
            continue

        doc = json.loads(path.read_text())
        for rel in doc["releases"]:
            try:
                digest, size = fetch_digest(rel["url"])
            except Exception as exc:
                print(f"   FAIL {rel['version']}: bundle unreachable — {exc}")
                failures += 1
                continue
            if size != rel["size"]:
                print(f"   FAIL {rel['version']}: size {size} != manifest {rel['size']}")
                failures += 1
            elif digest != rel["sha256"]:
                print(f"   FAIL {rel['version']}: sha256 {digest[:16]}… != {rel['sha256'][:16]}…")
                failures += 1
            else:
                print(f"   {rel['version']} ok — {size} bytes, sha256 {digest[:16]}…")

    print("\nFAILURES:", failures) if failures else print("\nall published artifacts check out")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
