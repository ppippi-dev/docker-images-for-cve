# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# PUBLIC REPOSITORY RULES
# - Track Dockerfile files only. Never commit organization data, configuration,
#   hostnames, credentials, certificates, logs, scan reports, SBOMs or image TARs.
# - Use public upstream artifacts only; pin images by digest and Python wheels
#   by version + SHA-256. Record each dependency change here for review.
# - No local COPY/ADD, host-directory build mounts, private package indexes or
#   secret-valued ARG/ENV. Build from stdin with an empty context (command below).
# - Keep tests, reports and exported images outside this repository. Never use
#   CVE ignores, severity filtering or --ignore-unfixed to claim a clean image.
# - Re-scan every candidate with a fresh vulnerability DB. Any finding or scan
#   error blocks release/import. This recipe is not a permanent zero-CVE claim.
# - Preserve upstream license notices; an image contains multiple licenses.
#
# Build (linux/amd64 only; no local build context is sent):
#   docker build --platform linux/amd64 -t litellm-cve:1.106.6-r1 - < Dockerfile
# Optional HTTPS proxy CA: add --secret id=build_ca,src=/path/to/combined-ca.pem
# The CA is a temporary BuildKit mount, never copied into an image layer.
# External release gate (run outside this repository; Trivy 0.76.1 verified):
#   trivy image --scanners vuln --ignorefile '' --ignore-unfixed=false \
#     --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL --exit-code 1 \
#     litellm-cve:1.106.6-r1
# Run API/authentication, streaming, UI and fresh/existing DB checks as well.
# Export only the exact validated image ID/digest, and re-scan before import.
#
# Baseline: public v1.106.6, linux/amd64, Trivy 0.76.1;
# vulnerability DB updated 2026-11-03T19:16:30Z: 10 OS + 33 Python findings.
# OS fixes: libexpat1 2.9.0-r0 -> 2.10.0-r0;
#   py3-pip-wheel 26.2.2-r0 -> 26.2.2-r2;
#   python-3.13{,-base} 3.13.17_git20261023-r1 -> 3.13.18_git20261030-r0.
# Main venv fixes: ddtrace 4.11.0 -> 4.15.6 (+ ddtrace-internal 0.1.0);
#   dnspython 2.8.0 -> 2.9.0; filelock 3.32.7 -> 4.2.4;
#   pyasn1 0.6.4 -> 0.6.5; pypdf 6.21.2 -> 6.21.4; tornado 6.5.10 -> 6.6.
# Admin venv fixes: PyJWT 2.14.0 -> 2.15.0;
#   opentelemetry-api 1.44.0 -> 1.45.1.
# Fix references are the public advisories for these versions and upstream:
# https://github.com/BerriAI/litellm/commit/dacaaad72ed25663ad7f40941c48f653a45289be

FROM ghcr.io/astral-sh/uv:0.11.7@sha256:240fb85ab0f263ef12f492d8476aa3a2e4e1e333f7d67fbdd923d00a506a516a AS uv
FROM ghcr.io/berriai/litellm:v1.106.6@sha256:37e2dafb088a7723beb998590682957386dfc83ffea1848486f8e0e5cfac0b06

ARG TARGETARCH
LABEL org.opencontainers.image.source="https://github.com/ppippi-dev/docker-images-for-cve" \
      org.opencontainers.image.version="1.106.6-r1" \
      org.opencontainers.image.description="Custom dependency remediation of LiteLLM 1.106.6 for linux/amd64; requires a fresh vulnerability scan before use"

# uv exists only during this RUN; it is not installed in the resulting image.
# Keep the upstream USER, PATH, ENTRYPOINT, CMD and application payload intact.
RUN --mount=from=uv,source=/uv,target=/run/uv \
    --mount=type=secret,id=build_ca,target=/etc/ssl/certs/ca-certificates.crt <<'SH'
set -eu
test "$TARGETARCH" = amd64
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

/app/.venv/bin/python - <<'PY'
import hashlib, importlib.metadata as m, json
from pathlib import Path
assert m.version("litellm") == "1.106.6"
root = Path(m.distribution("litellm").locate_file("litellm"))
hashes = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
          for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts}
assert hashes and any("_experimental/out/" in p for p in hashes)
assert any("rust_bridge/" in p and p.endswith(".so") for p in hashes)
Path("/tmp/litellm-payload-before.json").write_text(json.dumps(hashes))
PY

apk add --no-cache --repositories-file /dev/null \
    --repository https://packages.wolfi.dev/os \
    libexpat1=2.10.0-r0 \
    py3-pip-wheel=26.2.2-r2 \
    python-3.13=3.13.18_git20261030-r0 \
    python-3.13-base=3.13.18_git20261030-r0

cat > /tmp/patch-main.txt <<'REQ'
ddtrace==4.15.6 --hash=sha256:2185df0b730e4bb78dfe40cf61b7e242d4b81724cea4f496ca5a0ae0f5427309
ddtrace-internal==0.1.0 --hash=sha256:8eeac4a812e003cebafc8be35ef05103ae2b132893dfbcee00a67f4af81404a2
dnspython==2.9.0 --hash=sha256:9a4aedb833c3c1b49214d04d44d3032ab7a9135f7c1d29a549b4ff78fd82fda9
filelock==4.2.4 --hash=sha256:301241438c57936ef93f4243a94f2559022268bfcf9b375a9a72eb0f8db8358e
pyasn1==0.6.5 --hash=sha256:4017b0fce125096b8573b39c989fdb1a4b19cf761e683398184550fea0e66587
pypdf==6.21.4 --hash=sha256:33e4fb41ca352810eb4e9838aa0d82d6888a5f8bf682f43e99cce5faa666255c
tornado==6.6 --hash=sha256:11bb97c00981eb8254e55bd6a5ad960c983ae343fef8ae3ae5584cd1fb70236a
REQ
cat > /tmp/patch-admin.txt <<'REQ'
PyJWT==2.15.0 --hash=sha256:7a3742debf6b879e912dbb9819ceec1594be812452b78c5f2e2dfc56564954f8
opentelemetry-api==1.45.1 --hash=sha256:b31553efa588ae44bc306f863c785c5333a9ecc091248c6ee68b4b6c87fdedfb
REQ

# No dependency re-resolution: every added/replaced wheel is explicitly pinned.
# The final checks below reject incompatible installed dependency combinations.
/run/uv --no-config --no-cache pip install --python /app/.venv/bin/python \
    --index-url https://pypi.org/simple --only-binary :all: --no-deps \
    --require-hashes -r /tmp/patch-main.txt
/run/uv --no-config --no-cache pip install --python /opt/liteadmin/bin/python \
    --index-url https://pypi.org/simple --only-binary :all: --no-deps \
    --require-hashes -r /tmp/patch-admin.txt

# Explicit backport of upstream PR #49137's filelock dependency bound.
# This changes only the declared supported range, with the fixed library really
# installed above. It neither changes a package version to evade scanning nor
# rebuilds/replaces LiteLLM's Python code, compiled Rust extension or bundled UI.
# Reinstalling upstream LiteLLM would undo this backport and requires re-review.
/app/.venv/bin/python - <<'PY'
import base64, csv, hashlib, importlib.metadata as m, json, sys
from pathlib import Path
assert sys.version_info >= (3, 11)
dist = m.distribution("litellm")
assert dist.version == "1.106.6"
relative = next(p for p in dist.files if str(p) == "litellm-1.106.6.dist-info/METADATA")
metadata = Path(dist.locate_file(relative))
record = metadata.with_name("RECORD")
assert not record.with_name("RECORD.jws").exists()
assert not record.with_name("RECORD.p7s").exists()
old = b"Requires-Dist: filelock>=3.16.1,<4.0\n"
new = b"Requires-Dist: filelock>=3.16.1,<5\n"
content = metadata.read_bytes()
assert content.count(old) == 1, "Unexpected upstream dependency metadata"
content = content.replace(old, new)
rows = list(csv.reader(record.read_text().splitlines()))
matches = [row for row in rows if row[0] == str(relative)]
assert len(matches) == 1, "Unexpected upstream RECORD"
matches[0][1:] = ["sha256=" + base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip("="), str(len(content))]
metadata.write_bytes(content)
with record.open("w", newline="") as f:
    csv.writer(f).writerows(rows)
root = Path(dist.locate_file("litellm"))
after = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
         for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts}
assert after == json.loads(Path("/tmp/litellm-payload-before.json").read_text()), "Application payload changed"
assert m.version("filelock") == "4.2.4"
PY

/run/uv --no-config pip check --python /app/.venv/bin/python
/run/uv --no-config pip check --python /opt/liteadmin/bin/python
rm /tmp/patch-main.txt /tmp/patch-admin.txt /tmp/litellm-payload-before.json
SH
