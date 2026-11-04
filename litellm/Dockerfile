# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# REDISTRIBUTION HOLD
# Experimental OSS-only rebuild of LiteLLM 1.106.6: Enterprise source/package
# is removed and the Python/Rust wheel + UI are rebuilt from the pinned source.
# Core source changes are limited to the Enterprise dependency removal and the
# documented upstream filelock bound. Enterprise license gates are not bypassed.
# This does not make the complete image MIT-licensed: its OS, Python, Rust and
# JavaScript dependencies retain their own license/source-distribution duties.
# CI builds and validates only. Do not publish until redistribution review is
# complete; a successful CVE scan or functional test is not license clearance.
#
# PUBLIC REPOSITORY RULES
# - Track <open-source-name>/Dockerfile and reviewed build workflows only.
#   Never commit organization data, configuration,
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
#   docker build --platform linux/amd64 -t litellm-cve:1.106.6-oss-r3 - < litellm/Dockerfile
# Optional HTTPS proxy CA: add --secret id=build_ca,src=/path/to/combined-ca.pem
# The CA is a temporary BuildKit mount, never copied into an image layer.
# Supplementary public scan (run outside this repository; Trivy 0.76.1):
#   trivy image --scanners vuln --ignorefile '' --ignore-unfixed=false \
#     --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL --exit-code 1 \
#     litellm-cve:1.106.6-oss-r3
# The destination's approved scanner must also accept the exact image. Trivy
# alone does not establish acceptance by a different scanner or policy.
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
FROM ghcr.io/berriai/litellm:v1.106.6@sha256:37e2dafb088a7723beb998590682957386dfc83ffea1848486f8e0e5cfac0b06 AS upstream

# Only MIT UI directory + root LICENSE are extracted; enterprise/ never enters.
FROM --platform=$BUILDPLATFORM node:24.19.0-alpine3.24@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS oss-ui-builder
ENV NEXT_TELEMETRY_DISABLED=1 npm_config_fund=false npm_config_audit=false
ADD --checksum=sha256:17e8963fdf67cbfa8091628b1b9a42feb16553fcd9aa5d327963f1ab7727cfd2 \
    https://codeload.github.com/BerriAI/litellm/tar.gz/61c6ab78393ef45683dd7d963d2a315bd845e20b /tmp/litellm-source.tar.gz
ADD --checksum=sha256:43c653384c39617756846ad405705061a78fb6bbddb2ced57ab79fb92e8af2a7 \
    https://registry.npmjs.org/npm/-/npm-11.10.0.tgz /tmp/npm.tar.gz
COPY <<'OSS_UI_NOTICES' /tmp/prepare_artifact.mjs
// Offline preparation; application source and license gates remain unchanged.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
const ui = path.resolve(process.argv[2] ?? process.cwd());
const license = path.resolve(process.argv[3] ?? path.join(ui, "LICENSE.litellm.txt"));
const auditPath = path.resolve(process.argv[4] ?? path.join(ui, "ui-artifact-audit.json"));
const out = path.join(ui, "out");
const lockBytes = fs.readFileSync(path.join(ui, "package-lock.json"));
const sha = (data) => crypto.createHash("sha256").update(data).digest("hex");
if (sha(lockBytes) !== "e198baf51e5e84ea03989f45560d1fe29be14bf1498d0b7256298f1efb4da34a") {
  throw new Error("Unexpected v1.106.6 UI package-lock.json");
}
const lock = JSON.parse(lockBytes);
const packages = [];
const notices = [
  "LiteLLM OSS UI third-party license notices",
  "Built from BerriAI/litellm commit 61c6ab78393ef45683dd7d963d2a315bd845e20b.",
  "This conservative inventory includes installed build and application dependencies.",
  "An entry does not imply its package/native binary is in the static browser bundle.",
  "The upstream LiteLLM license is supplied separately as LICENSE.litellm.txt.",
  "",
];
for (const [relative, entry] of Object.entries(lock.packages)) {
  if (!relative.startsWith("node_modules/")) continue;
  const dir = path.join(ui, relative);
  const pkgFile = path.join(dir, "package.json");
  if (!fs.existsSync(pkgFile)) continue;
  const pkg = JSON.parse(fs.readFileSync(pkgFile, "utf8"));
  if (pkg.version !== entry.version) throw new Error("Installed dependency differs from lock: " + relative);
  const licenseFiles = fs.readdirSync(dir).filter((name) =>
    /^(licen[cs]e(?:[._-]|$)|notice(?:[._-]|$)|copying(?:[._-]|$))/i.test(name)
    && fs.statSync(path.join(dir, name)).isFile()
  ).sort();
  const record = {
    path: relative, name: pkg.name, version: pkg.version,
    declared_license: entry.license ?? pkg.license ?? null,
    dev: Boolean(entry.dev), optional: Boolean(entry.optional),
    license_files: licenseFiles,
  };
  packages.push(record);
  notices.push("=".repeat(78), record.name + "@" + record.version,
    "Declared license: " + JSON.stringify(record.declared_license));
  if (licenseFiles.length === 0) notices.push("No top-level license/notice file; see declared license metadata.");
  for (const name of licenseFiles) {
    notices.push("--- " + relative + "/" + name + " ---", fs.readFileSync(path.join(dir, name), "utf8"));
  }
}
fs.copyFileSync(license, path.join(out, "LICENSE.litellm.txt"));
fs.writeFileSync(path.join(out, "THIRD_PARTY_NOTICES.txt"), notices.join("\n") + "\n");
function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))
    .flatMap((entry) => {
      const item = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) throw new Error("Unexpected artifact symlink: " + item);
      return entry.isDirectory() ? walk(item) : [item];
    });
}
const files = walk(out).map((file) => {
  const relative = path.relative(out, file).split(path.sep).join("/");
  if (relative.split("/").some((part) => part === "node_modules" || part === "enterprise")) {
    throw new Error("Unexpected build/commercial source in artifact: " + relative);
  }
  if (/(^|\/)package(-lock)?\.json$/.test(relative)) throw new Error("Source manifest in artifact: " + relative);
  const data = fs.readFileSync(file);
  return { path: relative, bytes: data.length, sha256: sha(data) };
});
for (const required of ["index.html", "login/index.html", "THIRD_PARTY_NOTICES.txt", "LICENSE.litellm.txt"]) {
  if (!files.some((file) => file.path === required)) throw new Error("Missing UI artifact: " + required);
}
const audit = {
  source_commit: "61c6ab78393ef45683dd7d963d2a315bd845e20b",
  package_lock_sha256: sha(lockBytes),
  application_source_modified: false,
  enterprise_directory_in_build_input: false,
  enterprise_override_executed: false,
  enterprise_feature_license_gates_modified: false,
  scope_note: "MIT UI can contain Enterprise upsell text/conditional UI; this is distinct from commercial enterprise/ source.",
  license_inventory_scope: "All installed lock entries, not a browser-bundle dependency proof or complete legal review.",
  installed_dependencies_without_top_level_license_files: packages.filter((pkg) => pkg.license_files.length === 0).map((pkg) => pkg.path),
  packages, files,
};
fs.writeFileSync(auditPath, JSON.stringify(audit, null, 2) + "\n");
console.log(JSON.stringify({
  artifact_files: files.length, artifact_bytes: files.reduce((sum, file) => sum + file.bytes, 0),
  installed_packages: packages.length,
  missing_top_level_license_files: audit.installed_dependencies_without_top_level_license_files.length,
  audit: auditPath,
}));
OSS_UI_NOTICES
# One RUN prevents vfs from retaining/copying a node_modules-sized intermediate layer.
RUN --mount=type=secret,id=build_ca,target=/etc/ssl/certs/ca-certificates.crt \
    <<'UIBUILD'
set -eu
export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
    mkdir -p /source /opt/npm; \
    tar -xzf /tmp/litellm-source.tar.gz -C /source \
      litellm-61c6ab78393ef45683dd7d963d2a315bd845e20b/ui/litellm-dashboard \
      litellm-61c6ab78393ef45683dd7d963d2a315bd845e20b/LICENSE; \
    mv /source/litellm-61c6ab78393ef45683dd7d963d2a315bd845e20b/ui/litellm-dashboard /ui; \
    cp /source/litellm-61c6ab78393ef45683dd7d963d2a315bd845e20b/LICENSE /ui/LICENSE.litellm.txt; \
    tar -xzf /tmp/npm.tar.gz --strip-components=1 -C /opt/npm; \
    test "$(node --version)" = v24.19.0; \
    test "$(node /opt/npm/bin/npm-cli.js --version)" = 11.10.0; \
    test ! -e /source/litellm-61c6ab78393ef45683dd7d963d2a315bd845e20b/enterprise; \
    cd /ui; \
    echo 'e198baf51e5e84ea03989f45560d1fe29be14bf1498d0b7256298f1efb4da34a  package-lock.json' | sha256sum -c -; \
    node /opt/npm/bin/npm-cli.js ci --prefer-offline --ignore-scripts --no-audit --no-fund; \
    node /opt/npm/bin/npm-cli.js run build; \
    node /tmp/prepare_artifact.mjs /ui /ui/LICENSE.litellm.txt /ui-artifact-audit.json; \
    mkdir /ui-payload; mv /ui/out /ui-payload/out; \
    rm -rf /source /ui /opt/npm /root/.npm /tmp/litellm-source.tar.gz /tmp/npm.tar.gz /tmp/prepare_artifact.mjs; \
    mv /ui-payload /ui
UIBUILD

FROM rust:1.98-slim@sha256:4cd829461bd5c4d511c32e269da9cb8929223b666519d8004e35fc8d1d771ab7 AS oss-wheel-builder
# This immutable builder contains Rust 1.98.1; avoid rustup fetching 1.98.0.
ENV RUSTUP_TOOLCHAIN=1.98.1
RUN --mount=from=uv,source=/uv,target=/usr/local/bin/uv \
    --mount=from=oss-ui-builder,source=/ui/out,target=/run/oss-ui \
    --mount=type=secret,id=build_ca <<'SCRIPT'
set -eu
if [ -s /run/secrets/build_ca ]; then
  export SSL_CERT_FILE=/run/secrets/build_ca REQUESTS_CA_BUNDLE=/run/secrets/build_ca CARGO_HTTP_CAINFO=/run/secrets/build_ca
fi
# Keep the temporary proxy CA separate from files apt may update.
if [ -s /run/secrets/build_ca ]; then
  apt-get -o Acquire::https::CaInfo=/run/secrets/build_ca update
  apt-get -o Acquire::https::CaInfo=/run/secrets/build_ca install -y --no-install-recommends python3 python3-dev pkg-config libssl-dev ca-certificates
else
  apt-get update
  apt-get install -y --no-install-recommends python3 python3-dev pkg-config libssl-dev ca-certificates
fi
mkdir -p /src /wheels
python3 - <<'PY'
import hashlib, json, pathlib, urllib.request
source = 'https://codeload.github.com/BerriAI/litellm/tar.gz/61c6ab78393ef45683dd7d963d2a315bd845e20b'
artifacts = [(source, pathlib.Path('/tmp/source.tar.gz'), '17e8963fdf67cbfa8091628b1b9a42feb16553fcd9aa5d327963f1ab7727cfd2')]
with urllib.request.urlopen('https://pypi.org/pypi/maturin/1.15.0/json', timeout=120) as r:
    data = json.load(r)
name = 'maturin-1.15.0-py3-none-manylinux_2_12_x86_64.manylinux2010_x86_64.musllinux_1_1_x86_64.whl'
entry = next(f for f in data['urls'] if f['filename'] == name)
artifacts.append((entry['url'], pathlib.Path('/tmp') / name, '653020a63525bb224e5ab0adf02e17a2e08bc86dbea7fc1399c9a56d7529b99e'))
for url, path, expected in artifacts:
    with urllib.request.urlopen(url, timeout=120) as src, path.open('wb') as dst:
        digest = hashlib.sha256()
        while chunk := src.read(1024 * 1024):
            digest.update(chunk)
            dst.write(chunk)
    if digest.hexdigest() != expected:
        raise SystemExit('SHA-256 mismatch: ' + str(path))
PY
tar -xzf /tmp/source.tar.gz -C /src --strip-components=1
cd /src
python3 - <<'PY'
from pathlib import Path
p = Path('pyproject.toml')
s = p.read_text()
for before, after in [
    ('    "litellm-enterprise==0.1.76.post1",\n', ''),
    ('    "filelock>=3.16.1,<4.0",', '    "filelock>=3.16.1,<5",'),
]:
    if s.count(before) != 1:
        raise SystemExit('unexpected source manifest: ' + before.strip())
    s = s.replace(before, after, 1)
p.write_text(s)
PY
rm -rf enterprise litellm/proxy/enterprise litellm/proxy/_experimental/out
cp -a /run/oss-ui litellm/proxy/_experimental/out
mkdir -p /source-notices
cp LICENSE pyproject.toml /source-notices/
uv --no-config --no-cache tool run --from /tmp/maturin-1.15.0-py3-none-manylinux_2_12_x86_64.manylinux2010_x86_64.musllinux_1_1_x86_64.whl maturin build --release --locked --interpreter /usr/bin/python3 --out /wheels
rm -rf /src /tmp/source.tar.gz /tmp/maturin-*.whl /root/.cargo/registry /root/.cache/uv /var/lib/apt/lists/*
SCRIPT

# Rebuild both XML bindings against the same patched native libraries. Updating
# only lxml can leave xmlsec's bundled libxml2 behind or create an ABI mismatch.
# CVE-2025-10911: libxml2 2.15.2 contains the upstream fix; use 2.15.4 here.
# https://gitlab.gnome.org/GNOME/libxml2/-/blob/v2.15.4/NEWS
# Only the resulting wheels are used below; compilers and sources stay here.
FROM upstream AS xml-builder
ARG TARGETARCH
RUN --mount=from=uv,source=/uv,target=/run/uv \
    --mount=type=secret,id=build_ca,target=/etc/ssl/certs/ca-certificates.crt <<'SH'
set -eu
test "$TARGETARCH" = amd64
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
apk add --no-cache --repositories-file /dev/null \
    --repository https://packages.wolfi.dev/os \
    build-base=1-r10 pkgconf=3.0.10-r2 python-3.13-dev=3.13.18_git20261030-r0 \
    libxml2-dev=2.15.4-r2 libxslt-dev=1.1.45-r5 xmlsec-dev=1.3.13-r0 \
    xmlsec-openssl=1.3.13-r0
/run/uv --no-config venv --python /usr/bin/python3.13 /opt/xml-build
cat > /tmp/xml-build-requirements.txt <<'REQ'
setuptools==80.9.0 --hash=sha256:062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922
wheel==0.46.3 --hash=sha256:4b399d56c9d9338230118d705d9737a2a468ccca63d5e813e2a4fc7815d8bc4d
setuptools-scm==9.2.0 --hash=sha256:c551ef54e2270727ee17067881c9687ca2aedf179fa5b8f3fab9e8d73bdc421f
packaging==25.0 --hash=sha256:29572ef2b1f17581046b3a2227d5c611fb25ec70ca1ba8554b24b0e69331a484
Cython==3.2.4 --hash=sha256:f81eda419b5ada7b197bbc3c5f4494090e3884521ffd75a3876c93fbf66c9ca8
pkgconfig==1.5.5 --hash=sha256:d20023bbeb42ee6d428a0fac6e0904631f545985a10cdd71a20aa58bc47a4209
REQ
/run/uv --no-config --no-cache pip install --python /opt/xml-build/bin/python \
    --index-url https://pypi.org/simple --only-binary :all: --no-deps \
    --require-hashes -r /tmp/xml-build-requirements.txt
/usr/bin/python3.13 - <<'PY'
import hashlib, io, tarfile, urllib.request
from pathlib import Path
sources = [
    ("https://files.pythonhosted.org/packages/05/3b/aab6728cae887456f409b4d75e8a01856e4f04bd510de38052a47768b680/lxml-6.1.1.tar.gz", "ba96ae44888e0185281e937633a743ea90d5a196c6000f82565ebb0580012d40"),
    ("https://files.pythonhosted.org/packages/49/14/538b75379e6ab8f688f14d8663e2ab138d9c778bac4999d155b5f33c71c1/xmlsec-1.3.17.tar.gz", "f3fac9ae679f66585925cc00c5f6839ae36c1d03157619571dee18acc05b9c01"),
]
Path("/tmp/xml-source").mkdir()
for url, digest in sources:
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    assert hashlib.sha256(data).hexdigest() == digest, "Source hash mismatch"
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        archive.extractall("/tmp/xml-source", filter="data")
PY
# Disable isolation deliberately so both builds use the same lxml headers and
# system libxml2, instead of downloading a second statically bundled wheel.
export CFLAGS="-O2 -g0"
/run/uv --no-config --no-cache build --wheel --no-build-isolation \
    --python /opt/xml-build/bin/python --out-dir /wheels /tmp/xml-source/lxml-6.1.1
/run/uv --no-config --no-cache pip install --python /opt/xml-build/bin/python \
    --no-deps --no-index /wheels/lxml-*.whl
/run/uv --no-config --no-cache build --wheel --no-build-isolation \
    --python /opt/xml-build/bin/python --out-dir /wheels /tmp/xml-source/xmlsec-1.3.17
SH

FROM upstream AS patched

ARG TARGETARCH
LABEL org.opencontainers.image.source="https://github.com/ppippi-dev/docker-images-for-cve" \
      org.opencontainers.image.version="1.106.6-oss-r3" \
      org.opencontainers.image.description="Custom dependency remediation of LiteLLM 1.106.6 for linux/amd64; requires a fresh vulnerability scan before use"

# uv exists only during this RUN; it is not installed in the resulting image.
# Keep the upstream USER, PATH, ENTRYPOINT, CMD and application payload intact.
RUN --mount=from=uv,source=/uv,target=/run/uv \
    --mount=from=xml-builder,source=/wheels,target=/run/xml-wheels \
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
    python-3.13-base=3.13.18_git20261030-r0 \
    libxml2-16=2.15.4-r2 libxslt=1.1.45-r5 xmlsec=1.3.13-r0 \
    xmlsec-openssl=1.3.13-r0

cat > /tmp/patch-main.txt <<'REQ'
ddtrace==4.15.6 --hash=sha256:2185df0b730e4bb78dfe40cf61b7e242d4b81724cea4f496ca5a0ae0f5427309
ddtrace-internal==0.1.0 --hash=sha256:8eeac4a812e003cebafc8be35ef05103ae2b132893dfbcee00a67f4af81404a2
dnspython==2.9.0 --hash=sha256:9a4aedb833c3c1b49214d04d44d3032ab7a9135f7c1d29a549b4ff78fd82fda9
filelock==4.2.4 --hash=sha256:301241438c57936ef93f4243a94f2559022268bfcf9b375a9a72eb0f8db8358e
pyasn1==0.6.5 --hash=sha256:4017b0fce125096b8573b39c989fdb1a4b19cf761e683398184550fea0e66587
pypdf==6.21.4 --hash=sha256:33e4fb41ca352810eb4e9838aa0d82d6888a5f8bf682f43e99cce5faa666255c
tornado==6.6 --hash=sha256:11bb97c00981eb8254e55bd6a5ad960c983ae343fef8ae3ae5584cd1fb70236a
# Vendor fixes: CVE-2026-19407 (aiplatform), CVE-2026-90790 (a2a),
# CVE-2026-49272 (oauthlib). google-genai is aiplatform's updated dependency.
google-cloud-aiplatform==1.165.1 --hash=sha256:93874bd7993d1d901291595df693a8b9d4d7c89b93d4f41f8664d73f088dec89
google-genai==1.66.0 --hash=sha256:7f127a39cf695277104ce4091bb26e417c59bb46e952ff3699c3a982d9c474ee
a2a-sdk==1.1.4 --hash=sha256:b91b0350e1b1a3ef996b76766244523890d6b31b5aaf3f9d69c145fa97c5e0cf
oauthlib==4.0.1 --hash=sha256:498a298876e996301950a5b053d12c31628bb7b895db03666430c69ce182eb61
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
/run/uv --no-config --no-cache pip install --python /app/.venv/bin/python \
    --no-deps --no-index --reinstall /run/xml-wheels/lxml-*.whl /run/xml-wheels/xmlsec-*.whl

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

# Backport public CPython security fixes while retaining the truthful OS version.
# Source hashes guard this exact Wolfi build; stale bytecode is invalidated.
# https://github.com/python/cpython/commit/b234a2b67539f787e191d2ef19a7cbdce32874e7
# https://github.com/python/cpython/commit/2eb2af805c156ca52b316bb4ced5e0ab3971d0ae
# https://github.com/python/cpython/commit/9f52b443c002cccfb54bda0706a9276b6b4a109d
/app/.venv/bin/python -B - <<'PY'
#!/usr/bin/env python3
"""Apply three official CPython fixes to one exact Wolfi Python 3.13.18 build.

Upstream patches (PSF-licensed source remains otherwise unchanged):
  CVE-2025-15367: b234a2b67539f787e191d2ef19a7cbdce32874e7
  CVE-2026-103995: 2eb2af805c156ca52b316bb4ced5e0ab3971d0ae
  Required follow-up: 9f52b443c002cccfb54bda0706a9276b6b4a109d
  https://github.com/python/cpython/commit/<commit-id>

Run with python3 -B. Default mode writes only poplib.py and http/client.py,
then removes only their stale __pycache__ files. --dry-run performs the
same hash/snippet/compilation checks entirely in memory. Reapplication to
an already changed source is deliberately rejected; do not change version
or package metadata to represent this downstream source backport.
"""

import sys

sys.dont_write_bytecode = True

import argparse
import hashlib
from pathlib import Path
import sysconfig


ORIGINAL_SHA256 = {
    "poplib.py": "527e714523264093910a0a0b1a55c6583f952835c89061537fc40ad98c347056",
    "http/client.py": "d12e0060428b8389389db2244f9e1bd7fccae1450d43f74bce91b782498c300a",
}

REPLACEMENTS = {
    "poplib.py": [
        (
            "        line = bytes(line, self.encoding)\n"
            "        self._putline(line)\n",
            "        line = bytes(line, self.encoding)\n"
            "        if re.search(b'[\\x00-\\x1F\\x7F]', line):\n"
            "            raise ValueError('Control characters not allowed in commands')\n"
            "        self._putline(line)\n",
        ),
    ],
    "http/client.py": [
        (
            "# We always set the Content-Length header for these methods because some\n",
            "# RFC 9112: Content-Length = 1*DIGIT and chunk-size = 1*HEXDIG.\n"
            "# int() is more permissive, so we match against the grammar before calling it.\n"
            "_is_legal_content_length = re.compile(r'[0-9]+').fullmatch\n"
            "_is_legal_chunk_size = re.compile(rb'[0-9a-fA-F]+').fullmatch\n"
            "\n"
            "# We always set the Content-Length header for these methods because some\n",
        ),
        (
            '        length = self.headers.get("content-length")\n'
            "        if length and not self.chunked:\n"
            "            try:\n"
            "                self.length = int(length)\n"
            "            except ValueError:\n"
            "                self.length = None\n"
            "            else:\n"
            "                if self.length < 0:  # ignore nonsensical negative lengths\n"
            "                    self.length = None\n"
            "        else:\n"
            "            self.length = None\n",
            '        length = self.headers.get("content-length")\n'
            "        if length is not None:\n"
            "            # RFC 9112, section 5.1: optional whitespace (SP / HTAB) around\n"
            "            # the field value is not part of the value.\n"
            "            length = length.strip(' \\t')\n"
            "        if length and not self.chunked and _is_legal_content_length(length):\n"
            "            self.length = int(length)\n"
            "        else:\n"
            "            self.length = None\n",
        ),
        (
            "            line = line[:i] # strip chunk-extensions\n"
            "        try:\n"
            "            return int(line, 16)\n",
            "            line = line[:i] # strip chunk-extensions\n"
            "        line = line.rstrip()\n"
            "        try:\n"
            "            if not _is_legal_chunk_size(line):\n"
            '                raise ValueError("invalid chunk size")\n'
            "            return int(line, 16)\n",
        ),
    ],
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def prepare(stdlib_dir):
    """Validate both pristine modules and compile all changes before any write."""
    prepared = {}
    for relative, expected in ORIGINAL_SHA256.items():
        path = Path(stdlib_dir) / relative
        original = path.read_bytes()
        actual = sha256(original)
        if actual != expected:
            raise RuntimeError(
                f"Refusing unknown/previously patched source: {path}; "
                f"expected SHA256 {expected}, found {actual}"
            )
        changed = original
        for number, (before, after) in enumerate(REPLACEMENTS[relative], 1):
            before_bytes = before.encode("utf-8")
            count = changed.count(before_bytes)
            if count != 1:
                raise RuntimeError(
                    f"{path}: replacement {number} expected exactly one anchor, found {count}"
                )
            changed = changed.replace(before_bytes, after.encode("utf-8"), 1)
        # compile() does not write bytecode or import/execute the patched modules.
        compile(changed, str(path), "exec", dont_inherit=True)
        prepared[relative] = changed
    return prepared


def apply(stdlib_dir, prepared):
    """Write only the guarded modules, invalidate only their caches, compile again."""
    root = Path(stdlib_dir)
    # Recheck all sources immediately before starting writes.
    for relative, expected in ORIGINAL_SHA256.items():
        if sha256((root / relative).read_bytes()) != expected:
            raise RuntimeError(f"Source changed after preparation: {root / relative}")
    for relative, changed in prepared.items():
        path = root / relative
        path.write_bytes(changed)  # Existing source permissions/license text preserved.
        actual = path.read_bytes()
        if actual != changed:
            raise RuntimeError(f"Post-write content mismatch: {path}")
        compile(actual, str(path), "exec", dont_inherit=True)
        cache_dir = path.parent / "__pycache__"
        for cache in sorted(cache_dir.glob(f"{path.stem}.*.pyc")):
            cache.unlink()
            print(f"REMOVED_STALE_CACHE {cache}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stdlib-dir", type=Path, default=Path(sysconfig.get_path("stdlib")))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    prepared = prepare(args.stdlib_dir)
    for relative, changed in prepared.items():
        print(
            f"PREPARED {relative} "
            f"original_sha256={ORIGINAL_SHA256[relative]} patched_sha256={sha256(changed)}"
        )
    if args.dry_run:
        print("DRY_RUN: hashes, exact anchors and compilation verified; no files changed")
        return
    apply(args.stdlib_dir, prepared)
    print("APPLIED: both guarded sources compile; corresponding stale caches removed")


if __name__ == "__main__":
    main()
PY

# Packaging archives from historical releases are not runtime inputs.
# Preserve installed metadata, licenses, Prisma engines and timezone data.
rm -rf /app/enterprise/dist /app/litellm-proxy-extras/dist

/run/uv --no-config pip check --python /app/.venv/bin/python
/run/uv --no-config pip check --python /opt/liteadmin/bin/python
rm /tmp/patch-main.txt /tmp/patch-admin.txt /tmp/litellm-payload-before.json
SH

# Replace the upstream application with the source-built OSS wheel. Reinstalling
# the original wheel/proxy extra would restore the Enterprise dependency.
FROM patched AS oss-runtime
RUN --mount=from=uv,source=/uv,target=/run/uv \
    --mount=from=oss-wheel-builder,source=/wheels,target=/run/oss-wheels \
    --mount=from=oss-wheel-builder,source=/source-notices,target=/run/source-notices <<'OSS_RUNTIME'
set -eu
/run/uv --no-config pip uninstall --python /app/.venv/bin/python litellm-enterprise
rm -rf /app/enterprise /app/litellm/proxy/_experimental/out
/run/uv --no-config --no-cache pip install --python /app/.venv/bin/python \
    --no-deps --no-index --reinstall /run/oss-wheels/litellm-*.whl
mkdir -p /usr/share/licenses/litellm-oss
cp /run/source-notices/LICENSE /usr/share/licenses/litellm-oss/LICENSE
cp /run/source-notices/pyproject.toml /usr/share/licenses/litellm-oss/pyproject.toml
/app/.venv/bin/python - <<'PYCODE'
import importlib.metadata as m
import importlib.util
from pathlib import Path
from packaging.requirements import Requirement
assert m.version('litellm') == '1.106.6'
assert importlib.util.find_spec('litellm_enterprise') is None
assert all(Requirement(r).name.lower().replace('_', '-') != 'litellm-enterprise'
           for r in m.requires('litellm') or [])
assert not Path('/app/enterprise').exists()
root = Path(m.distribution('litellm').locate_file('litellm'))
assert not (root / 'proxy/enterprise').exists()
assert (root / 'proxy/_experimental/out/THIRD_PARTY_NOTICES.txt').is_file()
from litellm.rust_bridge import _native
print('Source-built OSS wheel and Rust extension verified')
PYCODE
/run/uv --no-config pip check --python /app/.venv/bin/python
/run/uv --no-config pip check --python /opt/liteadmin/bin/python
OSS_RUNTIME

# Export only the patched filesystem. Replaced libraries and removed archives
# are physically absent from the distributable layers, including old layers.
# No package database, license notice or installed version is hidden from scans.
FROM scratch
COPY --from=oss-runtime / /
ENV PATH="/app/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin" \
    SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt" \
    LITELLM_RELEASE_TAG="v1.106.6" \
    PRISMA_BINARY_CACHE_DIR="/opt/prisma/binaries" \
    PRISMA_CLI_PATH="/opt/prisma/binaries/node_modules/.bin/prisma" \
    PRISMA_CLI_QUERY_ENGINE_TYPE="binary" \
    PRISMA_OFFLINE_MODE="true"
LABEL org.opencontainers.image.source="https://github.com/ppippi-dev/docker-images-for-cve" \
      org.opencontainers.image.version="1.106.6-oss-r3" \
      org.opencontainers.image.base.name="ghcr.io/berriai/litellm:v1.106.6" \
      org.opencontainers.image.base.digest="sha256:37e2dafb088a7723beb998590682957386dfc83ffea1848486f8e0e5cfac0b06" \
      org.opencontainers.image.description="Experimental LiteLLM 1.106.6 OSS rebuild with security patches; redistribution review and destination scan required"
WORKDIR /app
USER root
EXPOSE 4000/tcp
ENTRYPOINT ["docker/prod_entrypoint.sh"]
CMD ["--port", "4000"]
