# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# LICENSE NOTES
# Rebuild of open-source vLLM 0.34.0 (Apache-2.0) for linux/amd64 on Amazon
# Linux 2023 minimal. vLLM and every package in /opt/vllm are unmodified public
# PyPI wheels; no source or feature is changed.
# vLLM is Apache-2.0. The image also contains components under other licenses:
# - Amazon Linux RPMs under their own licenses, including GPL/LGPL and PSF
#   (e.g. glibc, gcc, Python). Corresponding sources of the pinned release
#   (one package per call):
#     docker run --rm -w /tmp <base image below> \
#       dnf download --source --releasever=2023.12.20261120 <name>-<version>
# - PyTorch (License-Expression: Apache-2.0 AND Apache-2.0 WITH LLVM-exception
#   AND BSD-2-Clause AND BSD-3-Clause AND BSL-1.0 AND MIT), Triton (MIT) and other
#   wheels under their own licenses, including MPL-2.0 and LGPL (e.g. certifi,
#   pycountry).
# - NVIDIA wheels (nvidia-*), including the CUDA compiler tools (nvidia-cuda-nvcc),
#   NVSHMEM and the CUTLASS DSL native libraries. Most are under NVIDIA license
#   agreements; some are Apache-2.0, MIT or BSD. cuda-toolkit is a metapackage
#   without its own license file.
# Every dist-info license file and /usr/share/licenses are kept in the image;
# see each component's license text for its terms.
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
# - Re-scan every candidate with a fresh vulnerability DB and retain all findings.
#   No runtime/compiler exceptions: every component must satisfy CVSS v3 = 0.
#   Any v3 score > 0, unknown/malformed assessment, or scanner error blocks.
# - Preserve upstream license notices; an image contains multiple licenses.
# - Main publishes each image.version once as v<image.version>; a published
#   version tag is never re-pointed. Raise the rN suffix of image.version
#   (0.34.0-oss-r2 -> -r3) to publish a rebuild of the same vLLM version.
#
# CHANGES AGAINST THE UPSTREAM IMAGE (docker.io/vllm/vllm-openai, Ubuntu 24.04)
# - Base: AL2023 minimal with python3.12, python3.12-devel and gcc only; no CUDA
#   toolkit packages, ffmpeg or build-essential. The CUDA user-space libraries
#   are the PyTorch/NVIDIA wheels; the NVIDIA container runtime injects the
#   driver libraries (libcuda, libnvidia-ml). CUDA 13 wheels need driver >= 580.
# - gcc and Python.h stay: Triton compiles its CUDA launcher
#   (triton/backends/nvidia/driver.c) with $CC, gcc or clang at first kernel use
#   (triton/runtime/build.py) and loads it from its cache under $HOME.
# - Python set = the PyPI resolution of vllm==0.34.0 except setuptools: vLLM declares
#   setuptools<81, whose newest release 80.10.2 has CVE-2026-59890 (fixed in
#   83.0.0) and GHSA-xmj3-9gf7-h52w (fixed in 84.1.0); 84.2.1 is installed.
#   https://github.com/pypa/setuptools/security/advisories/GHSA-h35f-9h28-mq5c
#   https://github.com/pypa/setuptools/security/advisories/GHSA-xmj3-9gf7-h52w
#   setuptools >= 81 has no pkg_resources; vLLM, torch and Triton do not import
#   it (sentry-sdk and supervisor only as a Python < 3.8 fallback).
# - No pip or uv (the OS keeps the ensurepip wheel python3.12-libs requires).
#   Without ffmpeg, torchcodec video/audio decoding is unavailable.
# - User vllm (UID 2000, GID 0, HOME /home/vllm) as in upstream's
#   vllm-openai-nonroot target; numeric USER for runAsNonRoot. Caches resolve
#   under $HOME (.cache, .triton) and /tmp: with a read-only root filesystem
#   mount $HOME and /tmp writable and executable. Usage statistics off; EXPOSE 8000; ENTRYPOINT vllm serve.
# - Working directory /vllm-workspace (the upstream path), owned by root and
#   readable by everyone, so the container also starts under another UID and
#   GID (CI starts it as 65534:65534). Such a user cannot write /home/vllm: set
#   HOME, or the cache variables, to a writable directory. Relative paths
#   resolve against /vllm-workspace, which only root can write (r1 used
#   /home/vllm): pass absolute paths.
#
# Build (linux/amd64 only; no local build context is sent; ~30 GB free disk):
#   docker build --platform linux/amd64 -t vllm-cve:0.34.0-oss-r2 - < vllm/Dockerfile
# Supplementary public scan (run outside this repository):
#   trivy image --scanners vuln --ignorefile '' --ignore-unfixed=false \
#     --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL --exit-code 1 \
#     vllm-cve:0.34.0-oss-r2
# Scan the exact image with your own scanner and policy before use.
#
# Baseline: public vllm/vllm-openai:v0.34.0-x86_64, Trivy 0.76.2, DB 2026-11-24:
#   2,394 findings (2,387 OS, 7 Python); 727 with a fixed version, 1,667 without.
# This recipe, same scanner and DB, 2026-11-25: 0 findings (140 RPMs, 211 Python
#   packages); 4.5 GB compressed, 10.2 GB uncompressed.
#
# Pins: images by digest; RPMs by version (AL2023 repositories are locked to the
# base release); Python: the VLLM_LOCK heredoc (199 wheels, version + SHA-256)
# installed with --require-hashes --no-deps. The build fails if the installed set
# differs from the lock or a dependency other than vllm -> setuptools is unmet.
# Regenerate the lock (inputs and the exclude-newer cut-off are in the lock stage):
#   docker build --platform linux/amd64 --target lock-export \
#     --output type=local,dest=vllm-lock - < vllm/Dockerfile
#   then replace the VLLM_LOCK heredoc body with vllm-lock/requirements.txt.
#
# NOT VERIFIED: GPU inference, CUDA graphs, Triton/FlashInfer kernels on a GPU
# and multi-GPU (NCCL/NVSHMEM). CI checks imports, CUDA wheel libraries, the
# Triton launcher compile, `vllm serve --help` and the scan without a GPU.
# Run a GPU model test (/health, /v1/models, a completion) before use.
# Runtime JIT gap: upstream installs cuda-nvcc, sets CUDA_HOME and downloads
# FlashInfer cubins. Here CUDA_HOME is unset, nvcc is not on PATH (only inside
# the nvidia-cuda-nvcc wheel), there is no C++ compiler and no flashinfer-cubin
# (no release matching flashinfer-python 0.7.3 on PyPI), so vLLM logs
# "FlashInfer kernels are disabled" and FlashInfer JIT/cubin and DeepGEMM JIT
# paths are unavailable; vLLM falls back where it can. A GPU test must confirm
# the attention, sampler and MoE/FP8 backends in use. Adding gcc-c++ and
# CUDA_HOME would need a new scan.
#
# Upkeep per vLLM release:
# 1. Set the version in requirements.in, the lock header, the checks and labels
#    (image.version <vllm>-oss-r1; raise rN to publish a rebuild of the same
#    version, since a published version tag is never re-pointed).
# 2. Use the newest dated -minimal tag and index digest of
#    public.ecr.aws/amazonlinux/amazonlinux; update --releasever and the RPMs.
# 3. Re-check vLLM's setuptools bound (requirements/common.txt); drop the
#    override and its exception in the check once a fixed release is allowed.
# 4. Bump uv and the lock-stage packaging pin when convenient.
# 5. Move exclude-newer, regenerate the lock, build, scan, then test on a GPU.

FROM ghcr.io/astral-sh/uv:0.13.10@sha256:a3ea1357342c1a4bf9a0c53a3deb1b55379aefa037338d8113d5771efa01774f AS uv

# The dated tag only documents the digest; AL2023 repositories are locked to
# this image's release, so the pinned RPMs below resolve identically.
FROM public.ecr.aws/amazonlinux/amazonlinux:2023.12.20261120.0-minimal@sha256:75a2d4226d9b98c914d7eed878a03bef4f365ad548be5d28d464ccba504cec79 AS os
RUN <<'SH'
set -eu
dnf -y --releasever=2023.12.20261120 --setopt=install_weak_deps=0 --nodocs install \
    python3.12-3.12.16-2.amzn2023.0.1 \
    python3.12-devel-3.12.16-2.amzn2023.0.1 \
    gcc-11.5.0-5.amzn2023.0.5
rpm -q python3.12-3.12.16-2.amzn2023.0.1 python3.12-devel-3.12.16-2.amzn2023.0.1 gcc-11.5.0-5.amzn2023.0.5
dnf clean all
rm -rf /var/cache/dnf /var/cache/yum /var/log/dnf* /var/log/hawkey.log
SH

# Lock regeneration only (see header); never part of the default target.
FROM os AS lock
RUN --mount=from=uv,source=/uv,target=/run/uv <<'LOCK'
set -eu
export UV_PYTHON_DOWNLOADS=never UV_NO_CACHE=1
mkdir -p /lock /tmp/lock-input
cat > /tmp/lock-input/requirements.in <<'REQ'
vllm==0.34.0
REQ
cat > /tmp/lock-input/overrides.txt <<'REQ'
# vLLM 0.34.0 declares setuptools<81; the fixed releases are above that cap.
setuptools>=84.2.1
REQ
cat > /tmp/lock-input/tools.txt <<'REQ'
packaging==26.4 --hash=sha256:81383611a09c1bc0b08b76e0fd5829d7c6824c65b27a6aee339da133f4233ea2
REQ
/run/uv --no-config venv --python /usr/bin/python3.12 /tmp/lock-tools
/run/uv --no-config pip install --python /tmp/lock-tools/bin/python \
    --index-url https://pypi.org/simple --only-binary :all: --no-deps \
    --require-hashes -r /tmp/lock-input/tools.txt
/run/uv --no-config pip compile /tmp/lock-input/requirements.in \
    --overrides /tmp/lock-input/overrides.txt \
    --python /usr/bin/python3.12 --python-version 3.12 \
    --python-platform x86_64-manylinux_2_34 --only-binary :all: \
    --exclude-newer 2026-11-25T05:00:00Z --index-url https://pypi.org/simple \
    --generate-hashes --no-annotate --no-header --quiet \
    --output-file /tmp/lock-input/all-platforms.txt
# uv lists the hashes of every platform's files. Keep only the wheels that
# CPython 3.12 on glibc 2.34 x86_64 can install, using PyPI's file digests.
/tmp/lock-tools/bin/python -I - /tmp/lock-input/all-platforms.txt /lock/requirements.txt <<'PY'
import json, re, sys, urllib.request
from packaging.tags import compatible_tags, cpython_tags
from packaging.utils import parse_wheel_filename
from packaging.version import Version
source, target = sys.argv[1:3]
platforms = [f'manylinux_2_{minor}_x86_64' for minor in range(34, 4, -1)]
platforms += ['manylinux2014_x86_64', 'manylinux2010_x86_64', 'manylinux1_x86_64', 'linux_x86_64']
supported = set(cpython_tags((3, 12), ['cp312'], platforms)) | set(compatible_tags((3, 12), 'cp312', platforms))
rows = []
for line in open(source).read().replace('\\\n', ' ').splitlines():
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    match = re.fullmatch(r'([a-z0-9][a-z0-9._-]*)==(\S+)((?:\s+--hash=sha256:[0-9a-f]{64})+)', line)
    if not match:
        raise SystemExit('Unexpected compiled requirement: ' + line)
    name, version = match.group(1), match.group(2)
    listed = set(re.findall(r'sha256:([0-9a-f]{64})', match.group(3)))
    with urllib.request.urlopen(f'https://pypi.org/pypi/{name}/{version}/json', timeout=120) as response:
        release = json.load(response)
    assert Version(release['info']['version']) == Version(version), name
    keep = sorted({f['digests']['sha256'] for f in release['urls']
                   if f['packagetype'] == 'bdist_wheel' and not f.get('yanked')
                   and parse_wheel_filename(f['filename'])[3] & supported})
    if not keep or not set(keep) <= listed:
        raise SystemExit('No consistent linux x86_64 CPython 3.12 wheel for ' + name)
    rows.append(f'{name}=={version} ' + ' '.join('--hash=sha256:' + h for h in keep))
names = [row.split('==', 1)[0] for row in rows]
assert 'vllm==0.34.0' in {row.split(' ', 1)[0] for row in rows} and len(set(names)) == len(names)
with open(target, 'w') as output:
    output.write('# vLLM 0.34.0 for CPython 3.12 on linux x86_64 (glibc 2.34), PyPI wheels only.\n'
                 '# Generated by the lock stage of vllm/Dockerfile (uv 0.13.10,\n'
                 '# exclude-newer 2026-11-25T05:00:00Z, override setuptools>=84.2.1).\n')
    output.write('\n'.join(rows) + '\n')
print(f'{len(rows)} packages, {sum(row.count("--hash") for row in rows)} hashes')
PY
LOCK

FROM scratch AS lock-export
COPY --from=lock /lock/requirements.txt /requirements.txt

FROM scratch AS locked-requirements
COPY <<'VLLM_LOCK' /requirements.txt
# vLLM 0.34.0 for CPython 3.12 on linux x86_64 (glibc 2.34), PyPI wheels only.
# Generated by the lock stage of vllm/Dockerfile (uv 0.13.10,
# exclude-newer 2026-11-25T05:00:00Z, override setuptools>=84.2.1).
agent-detector==2.0.0 --hash=sha256:22c6a1c9c23894a12f55aea625f060b8d3330fba774de72d02d5442bb580417f
aiohappyeyeballs==2.7.1 --hash=sha256:9243213661e29250eb41368e5daa826fc017156c3b8a11440826b2e3ed376472
aiohttp==3.14.5 --hash=sha256:20f085697d7e911f1f73c43ed03fafbed1e7121797e2eb5428efa80398060584 --hash=sha256:efc21a454892828368b11c2c780de0ff8bc991f73f6b99c6b66e56205470929b
aiosignal==1.4.0 --hash=sha256:053243f8b92b990551949e63930a839ff0cf0b0ebbe0597b0f3fb19e1a0fe82e
annotated-doc==0.0.7 --hash=sha256:6bc31bbbec6dfaaedc1676dbc11dbda96fe22a2b5c400e9ebad113fec44a9dc6
annotated-types==0.8.0 --hash=sha256:f072f4d804ea359e4eaf198b1af7a8b0943881a87f31bb764f8bf219bb9419e0
anthropic==2.14.0 --hash=sha256:5cf986851f61c0858ac88c6f7c28490369a68ff4a89c309849605b764da0664d
anyio==4.16.0 --hash=sha256:c66ae634e0b8228396b801741beb3294326d4b6102f7bba4041c0dfb58c29026
apache-tvm-ffi==0.1.11 --hash=sha256:2843f084cdc94dedacd8b257a395a2b71b8a3dc7fc99711b148bf1d161983128 --hash=sha256:78aa1857b04a2ea718317041ab3f01288b3d496e6036eb1b99ebdc9da0fdaef5
astor==0.8.1 --hash=sha256:070a54e890cefb5b3739d19f30f5a5ec840ffc9c50ffa7d23cc9fc1a38ebbfc5
attrs==26.1.0 --hash=sha256:c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309
blake3==1.0.11 --hash=sha256:33424c686b291c7682b5816fe9320466dbc0a457ef7e15c273c804a2d70fea70
cachetools==8.0.2 --hash=sha256:502bf3c17c6e35d78ccdaa70da8c7001b28634541f5cde0dee33c93bb252277d
cbor2==6.3.0 --hash=sha256:4f160b662059cc30ced4436fca332f4c27d0259698a5bde8373c9c6f829aabdf
certifi==2026.11.20 --hash=sha256:7422df25243767b9877031a2248cb14d09ddac9beee846f4cef3d5c9191d488f
cffi==2.1.1 --hash=sha256:c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf
charset-normalizer==3.5.3 --hash=sha256:26c6ad87bb79628954b52f8f7b9e18ab5cd9667546712ded9689fb7677e630d6 --hash=sha256:96e268b0cbda016ac519513294fcd17032264085b600abaac58b93049477e132 --hash=sha256:e5e4785d8a0adeadfbdf75f4efc357911842674651cbafd7e97f69b11ec3cbc6
click==8.5.1 --hash=sha256:8bb5376d2006950386f8c6427613334a2acadc5f559cb80e638d00b4df957e37
cloudpickle==3.1.3 --hash=sha256:1654f4f18e416447210a63c5c25a135d65a292156aa5fa519dfa4baf7726dddb
compressed-tensors==0.17.0 --hash=sha256:4a1b89b508f7efb8ffb4eee8a6e69e0452d9b080cae130146025c64fbe9fa9aa
cryptography==50.0.2 --hash=sha256:1981f1db4630889b9ef7803fadef12b056f428cb6b85c27ba57b774793b6093c --hash=sha256:4061c0079120205fb760c58acab6443e217307dcf05e3702cf970e0689972856 --hash=sha256:630ebfea3bf689d075f82316324ff7433dc447fe6bc1bfc76524b74b4a9567d2 --hash=sha256:9dab55f57c74c3cad24c323bacbbd04be4705ba6eb0d92e920b1fc4837ed5079 --hash=sha256:ee247f5c245c9a2fe7c8e2214e295918838e44e00a45a6718451e4004219e767 --hash=sha256:f21e8a22c8605750c7af886bab299a363721264061b4ac0a30efb73cfd58efc5
cuda-bindings==13.5.0 --hash=sha256:a46a8cc84112d769d0f57bf3ae3fedc115cf09348f14da85a1a8200968b6f262
cuda-core==1.2.2 --hash=sha256:0b299eee52edece08b77428cfc22b33b29be1bc69c42878d2e6114031eac17e6
cuda-pathfinder==1.9.1 --hash=sha256:b743c132f90ad2d1e71d43fd28f31ebcde518f943e50fd44aca62b2a80d5230d
cuda-python==13.5.0 --hash=sha256:0fd6e6123cd648bd148bcd04675a98596508335951e1f8c1f3737d6ecd7a5025
cuda-tile==1.8.1 --hash=sha256:c4aaf00d3dd927645b15d743c87ad7e3540e4ca8c160a4085ab22255cb7f678d
cuda-toolkit==13.0.3.0 --hash=sha256:d693caaa261214ddd7dbb60d68e71cbed884e68c2be7509778f3051da0b91c3f
depyf==0.20.0 --hash=sha256:d31effad4261cebecb58955d832e448ace88f432328f95f82fd99c30fd9308d4
detect-installer==0.2.1 --hash=sha256:87e2ce7d05cb108b178f8e45bb80d3d88c0cb4b397983345c18ad6562e02e620
dill==0.4.1 --hash=sha256:1e1ce33e978ae97fcfcff5638477032b801c46c7c65cf717f95fbc2248f79a9d
dnspython==2.9.2 --hash=sha256:af15f7d385a6ae2fb35a796fde2138004c8c42c7389090e2addc83e3b3340fd8
docstring-parser==0.18.0 --hash=sha256:b3fcbed555c47d8479be0796ef7e19c2670d428d72e96da63f3a40122860374b
einops==0.8.2 --hash=sha256:54058201ac7087911181bfec4af6091bb59380360f069276601256a76af08193
email-validator==2.4.0 --hash=sha256:4454e41c4e1c6b6caee34a1dc71d5e736791562be8fd179b02e298f796522684
fastapi==0.136.3 --hash=sha256:3d2a69bdf04b7e9f3afa292c3bc7a98816bbfafa10bc9b45f3f3700d2f761620
fastapi-cli==0.0.34 --hash=sha256:4a1185b66308c7543e98957426a8ecd205d58853514cb9a68c78066f2e6e467b
fastapi-cloud-cli==0.28.0 --hash=sha256:e1409bc42017a86f8092fdf1dd64ead129698936cfeb151a6c3e023f611fd620
fastar==0.12.0 --hash=sha256:deb0b3882626832361dd0fcee1f4ef1c6e2a7aaa4165e51c86ae0bab95caccd6
fastsafetensors==0.5.0 --hash=sha256:cf8085203d83abbf2ea37edfb4b007cf1de521ab1cd29b46935f611d68c80d7d
filelock==4.3.1 --hash=sha256:79e43df8e9fe509cd83a3899a7c186c8077cbbe4d200a1ed3705c2f3bb6bc487
flashinfer-python==0.7.3 --hash=sha256:548a3ea1f9057025ace0a21b298824f8de049eb4b6c5c458f763309509e2ae40
frozenlist==1.8.0 --hash=sha256:0c18a16eab41e82c295618a77502e17b195883241c563b00f0aa5106fc4eaa0d --hash=sha256:494a5952b1c597ba44e0e78113a7266e656b9794eec897b19ead706bd7074383
fsspec==2026.9.0 --hash=sha256:8dd6e646e99ea382bd85f97a45e6b526a442d79423a7dc673f1e2756d05fcb5f
googleapis-common-protos==1.76.0 --hash=sha256:59e13344a9f3651aa201a03e2bee815a3bf43a4baf1f9ff8a9b62a840ce25fac
grpcio==1.85.4 --hash=sha256:f279c333de857630e12ce2751672cb0825d1df2f6f2ec209d0d40f86a26e4ac3
h11==0.16.0 --hash=sha256:63cf8bbe7522de3bf65932fda1d9c2772064ffb3dae62d55932da54b31cb6c86
hf-xet==1.8.0 --hash=sha256:29dab7c904cd1914a0439c6e1306c12c7497c8bd32290fbe563ebf51ca4b6d6d
httpcore==1.0.9 --hash=sha256:2d400746a40668fc9dec9810239072b40b4484b640a8c38fd654a024c7a1bf55
httpcore2==2.16.2 --hash=sha256:16051ae2a42f776007543f32de9349a317b23d2cbb4e1456b4bac0e88b87419a
httptools==0.9.0 --hash=sha256:3e3201fe4d46e0d15d7ff9fafc94a605da9eb82d2c5b9837f0368acb325481f1
httpx==0.28.1 --hash=sha256:d909fcccc110f8c7faf814ca82a9a4d816bc5a6dbfea25d6591d6985b8ba59ad
httpx2==2.16.2 --hash=sha256:f05c13aade4c45dbf1c9060647a1058f0acad62398fad96e741269edb33d46f5
huggingface-hub==2.4.0 --hash=sha256:42ecfd93ede47bdd333daebbf66a32d7bfe2e18752754fe4d2d4f98a0179d801
humming-kernels==0.1.19 --hash=sha256:16ad0c8e9c2d5a8db739bdb97bcc510cedc9dc4c4c111098cbb2d7ac9c1dd973
idna==3.20 --hash=sha256:ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c
ijson==3.6.0 --hash=sha256:c14d568d31a322e8ed7e9735f6e355608a23cc6ff4b5da843515089dae4cbf5f
instanttensor==0.2.3 --hash=sha256:bd5f12eb9b193a028c13ddd75b38c42b67846bcbc9b8822b08321fe1192a4654
interegular==0.3.3 --hash=sha256:b0c07007d48c89d6d19f7204972d369b2a77222722e126b6aa63aa721dc3b19c
jinja2==3.1.6 --hash=sha256:85ece4451f492d0c13c5dd7c13a64681a86afae63a5f347908daf103ce6d2f67
jiter==0.19.0 --hash=sha256:0956b5f58b804221dfb929c120e6d4032138fed20c1cc0ef683a2d1326255e46
jmespath==1.1.0 --hash=sha256:a5663118de4908c91729bea0acadca56526eb2698e83de10cd116ae0f4e97c64
jsonschema==4.26.0 --hash=sha256:d489f15263b8d200f8387e64b4c3a75f06629559fb73deb8fdfb525f2dab50ce
jsonschema-specifications==2025.9.1 --hash=sha256:98802fee3a11ee76ecaca44429fda8a41bff98b00a0f2838151b113f210cc6fe
lark==1.2.2 --hash=sha256:c2276486b02f0f1b90be155f2c8ba4a8e194d42775786db622faccd652d8e80c
llguidance==1.7.6 --hash=sha256:ceec951d29a74309984e3be0fe7f5f56c1362434cd937abd517b259a60908b1e
llvmlite==0.47.0 --hash=sha256:5853bf26160857c0c2573415ff4efe01c4c651e59e2c55c2a088740acfee51cd
lm-format-enforcer==0.11.3 --hash=sha256:cf586350875def1ae7a8fba84fcbbfc8371424b6c9d05c1fcba70aa233fbf06f
loguru==0.8.0 --hash=sha256:e0fba09d6f76ba2d2f4bd1757122942f5a670c702e988b5efaeab99dacba0069
markdown-it-py==4.3.0 --hash=sha256:7aa1511a46c39138de78d9eba92ce47e63124d8003fc98b3a351909e04239efa
markupsafe==3.0.4 --hash=sha256:8e124f974786f831d6043728e38296969d3579db8896fe004682f5758e613581
mcp==2.3.0 --hash=sha256:dd0c44c089d16453e8ae31a3877a0054d7a2314caaa81f5e0541b9b1734b2377
mcp-types==2.3.0 --hash=sha256:968efdbdaedfab06adae40d378a34395f1090c5921d4be3c9cde283aaf76d91d
mdurl==0.1.2 --hash=sha256:84008a41e51615a49fc9966191ff91509e3c40b939176e643fd50a5c2196b8f8
mistral-common==1.13.1 --hash=sha256:98b4d0755b8d90bf4691fa8f1b70cb3b4a8cd4dc1653c4ed08ef3d1c7d2c29af
ml-dtypes==0.7.0 --hash=sha256:3c4e47f553a04d33886160a9600e2313e5bee8c1c3da997baa23c8fecbfab189
model-hosting-container-standards==0.1.16 --hash=sha256:47f4f65713120bc3a69feb022981a38db9e557aedf88dbd72077f20588caa12b
mpmath==1.3.0 --hash=sha256:a0b2b9fe80bbcd81a6647ff13108738cfb482d481d826cc0e02f5b35e5c88d2c
msgspec==0.22.0 --hash=sha256:99c401861c5bb3a57f7d6423ea7ed4352cd57aa3f04f4fbe9f3e3e4564a10f08
multidict==7.2.1 --hash=sha256:08ea94663d9e7c25d14d78222f7aee906c472d4837766bec62477c38f6e419dc --hash=sha256:1fb8c1a3480c130c3a6422d5f16f3cad6552bf08c2089dd288ba7134649183b5
nccl-extensions==0.2.0 --hash=sha256:7db0d5980c734fa94823125d35e1024af86090c7b8f5ffe7de3ba2d242dc52e9
nccl4py==0.6.0 --hash=sha256:f4006cf8c12c26ed29811b80858a58f8f31e4b42ea85b6c1d23401981449ab9d
networkx==3.7 --hash=sha256:e3fd2c13a7814cee3746340d8d7f8598a67f16a58bf47fb7f8793fab6efca1b0
ninja==1.13.2 --hash=sha256:65a24341b5ac09fcadcc37082660be40a94174e51a937fabf6e2cae26225fa2c
numba==0.65.0 --hash=sha256:a52d92ffd297c10364bce60cd1fcb88f99284ab5df085f2c6bcd1cb33b529a6f
numpy==2.3.5 --hash=sha256:0d8163f43acde9a73c2a33605353a4f1bc4798745a8b1d73183b28e5b435ae28
nvidia-cublas==13.1.1.3 --hash=sha256:37936a16db8fe4ac1f065c2139360608a543a09275cb1a1af612e08cfa065436
nvidia-cuda-cccl==13.3.5.0.6 --hash=sha256:d5230098fa2df5021e1a00c0c4eee41797671a91119d31e892463e5ccf3ee326
nvidia-cuda-crt==13.5.37 --hash=sha256:e898b7f73d3035fa89915a3f7bf3b54a73e90249746111aed295822c4729bb29
nvidia-cuda-cupti==13.0.85 --hash=sha256:4eb01c08e859bf924d222250d2e8f8b8ff6d3db4721288cf35d14252a4d933c8
nvidia-cuda-nvcc==13.5.37 --hash=sha256:f5c4f7ead5d964fb4af42bbf1e6d3ec3c1e6e9d83b53749f691d387e7fcaa3a7
nvidia-cuda-nvrtc==13.0.88 --hash=sha256:ad9b6d2ead2435f11cbb6868809d2adeeee302e9bb94bcf0539c7a40d80e8575
nvidia-cuda-runtime==13.0.96 --hash=sha256:7f82250d7782aa23b6cfe765ecc7db554bd3c2870c43f3d1821f1d18aebf0548
nvidia-cudnn-cu13==9.24.0.43 --hash=sha256:71f181cd810e90f9b6023b01186fe82d13d65f0ec098581ee201d39fad769e4b
nvidia-cudnn-frontend==1.33.0 --hash=sha256:06bff4a67334cf2cc0d0528f2a847bf0bcd256b923c48bc7445afc962fecba32
nvidia-cufft==12.0.0.61 --hash=sha256:6c44f692dce8fd5ffd3e3df134b6cdb9c2f72d99cf40b62c32dde45eea9ddad3
nvidia-cufile==1.15.1.6 --hash=sha256:08a3ecefae5a01c7f5117351c64f17c7c62efa5fffdbe24fc7d298da19cd0b44
nvidia-curand==10.4.0.35 --hash=sha256:1aee33a5da6e1db083fe2b90082def8915f30f3248d5896bcec36a579d941bfc
nvidia-cusolver==12.0.4.66 --hash=sha256:0a759da5dea5c0ea10fd307de75cdeb59e7ea4fcb8add0924859b944babf1112
nvidia-cusparse==12.6.3.3 --hash=sha256:2b3c89c88d01ee0e477cb7f82ef60a11a4bcd57b6b87c33f789350b59759360b
nvidia-cusparselt-cu13==0.8.1 --hash=sha256:786ce87568c303fadb5afcc7102d454cd3040d75f6f8626f5db460d1871f4dd0
nvidia-cutlass-dsl==4.8.0 --hash=sha256:24f996e0e5fa88c8b417f4893e615af135bdfdfdbdbed7e239faf36a88df711b
nvidia-cutlass-dsl-libs-base==4.8.0 --hash=sha256:5bdc80989b0fbbac3d58960057e74e2ce8676fafa76b852d9422b9c4b9b74bdd
nvidia-cutlass-dsl-libs-core==4.8.0 --hash=sha256:b32716d2ed10c185cdbbb6b5c6fca26a3113a60e6e2fe4e2f0cb15966422b621
nvidia-cutlass-dsl-libs-cu12==4.8.0 --hash=sha256:2374cfdff635ceaf7e2c5bd17b4beb410830420a4fd65b12b7f24b5d5cbb9d4c
nvidia-cutlass-dsl-libs-cu13==4.8.0 --hash=sha256:463cd7f0c452ffeeecb530a15aeb1b10cbbd2c8da6c5aa2fecf65f836258a732
nvidia-ml-py==13.615.71 --hash=sha256:959bf4adf6fe1308e4bd739e722236b0d1ec8392e2cefad33ff70c311380b9b6
nvidia-nccl-cu13==2.30.7 --hash=sha256:cefa7fdb9710efd0f39c5f1be1d61ff6fc9a996c451265bd7fbdcf9455ed4b50
nvidia-nvjitlink==13.5.37 --hash=sha256:280d7cb9649704145f074b8dbde500de04ce02d0872e066e20a83c17bcaa93eb
nvidia-nvshmem-cu13==3.4.5 --hash=sha256:290f0a2ee94c9f3687a02502f3b9299a9f9fe826e6d0287ee18482e78d495b80
nvidia-nvtx==13.0.85 --hash=sha256:4936d1d6780fbe68db454f5e72a42ff64d1fd6397df9f363ae786930fd5c1cd4
nvidia-nvvm==13.5.37 --hash=sha256:c41bfa362e407405163f103c2229f0765f8cc2ed7d148b754dc77f228bf7e070
nvtx==0.2.15 --hash=sha256:3ca8030a6d197952318013dd1c12c22da1d4b9feb76ba72e0fcd449961183c2c
openai==3.59.0 --hash=sha256:e613537ac5f082c58f652a536ed4215b19a29d360c4348cca86f0e563f7a0b1f
opencv-python-headless==5.1.0.95 --hash=sha256:7d387d4a64abe0c737440d38b5a90822f9bbcc10c8ce06a35904d6ecf7a2fb30 --hash=sha256:93cc83677f07791a9d3284bb6b9bbf7c2ffcca05aabcee239e68ca4abaf50aa1
opentelemetry-api==1.45.2 --hash=sha256:2cbd737377e710ee740d261c94e93fa0f08e6d037c18f17513cc0a2d94479a34
opentelemetry-exporter-http-transport==0.66b2 --hash=sha256:fd5f5b490c099acda1cd7b909d5e8981436bf18cc8c6098d302d114c271720e9
opentelemetry-exporter-otlp==1.45.2 --hash=sha256:52c8b9f268289c92c08b3a97f48c63d6e5c037f25ca1f6f29ef162fb78974afc
opentelemetry-exporter-otlp-common==0.66b2 --hash=sha256:ace86efb75489f925f1ef809856ae5f0c7db534e4afdc624530222228b1236a5
opentelemetry-exporter-otlp-proto-common==1.45.2 --hash=sha256:af483b24217028892f017096731b794b196b785025d2e6808874720fd0b05a80
opentelemetry-exporter-otlp-proto-grpc==1.45.2 --hash=sha256:8a48d60835e90536846bd82de487bfbd81bccb5a1b3d0fb82edeea17db07395c
opentelemetry-exporter-otlp-proto-http==1.45.2 --hash=sha256:6e4d025138829d0ee57946930c2ccad6491ad4d92a958e9c7eea69278fe60cfc
opentelemetry-proto==1.45.2 --hash=sha256:03a7ca1b43f89fd5b965d5975902bb2515c0c86e2428b456836e9a6149c6235a
opentelemetry-sdk==1.45.2 --hash=sha256:ff974ea70ee4f1d51e2ec152db37c2b626c7bf82bb3f7d86114fd8704e7199c6
opentelemetry-semantic-conventions==0.66b2 --hash=sha256:4cbe61e5f9275d57ab31708446e7938ef4291ebbe6a7fca6f7a629c5acae87d8
opentelemetry-semantic-conventions-ai==0.5.1 --hash=sha256:25aeb22bd261543b4898a73824026d96770e5351209c7d07a0b1314762b1f6e4
orjson==3.13.0 --hash=sha256:bceadfd314bd238f584fc229a4bbaf0e573597e7a026dec5429fbf29fd66c641
oss-harmony==0.0.12 --hash=sha256:d49afad3d5deeaa0ce95a51e7c86f90d1630d36cea3ebd4a8542d214b97cecd7
outlines-core==0.2.14 --hash=sha256:3bb2060c240c4507f334965a8948dbeeb22007560d797f6debd92346c0b620cb
packaging==26.4 --hash=sha256:81383611a09c1bc0b08b76e0fd5829d7c6824c65b27a6aee339da133f4233ea2
partial-json-parser==0.2.1.1.post7 --hash=sha256:145119e5eabcf80cbb13844a6b50a85c68bf99d376f8ed771e2a3c3b03e653ae
pillow==13.0.0 --hash=sha256:42d63be3af4f9b951b199b0a9d23365d37ab14687e6d77b74940432c8515c4ca
prometheus-client==0.26.0 --hash=sha256:fa93d06737aa02bacd05794768508bb97d2fbee28cb3bca04eaae92f0ca953d6
prometheus-fastapi-instrumentator==8.1.0 --hash=sha256:b9f40b2cff3f7891ca0610b3ae4fc6ec723fd326b04bb659819aaeb821a0fc7d
propcache==0.5.4 --hash=sha256:2814ecd8e818f487bee4b0f921bc4d1c176cc5fc71ac0f072d0fa67eda4ac14b --hash=sha256:62c60aec739ed00124573cce1178138fd690c7676352d67a37328c1cf51d7468
protobuf==7.36.2 --hash=sha256:89f23aa53c24553a2416fd4fd1ec06f74fa42b14b546d8883128813f775bbfd2 --hash=sha256:bdb3a345d48db958e6ce1f18e508beb0cc981d64f24088427549c866cd039f1e
psutil==7.2.2 --hash=sha256:076a2d2f923fd4821644f5ba89f059523da90dc9014e85f8e45a5774ca5bc6f9
py-cpuinfo==9.0.0 --hash=sha256:859625bc251f64e21f077d099d4162689c762b5d6a4c3c97553d56241c9674d5
pybase64==1.5.2 --hash=sha256:037a811b9df84d568604b0b4739b6164801c06765ee010748e9b284dead6af2b
pycountry==26.2.16 --hash=sha256:115c4baf7cceaa30f59a4694d79483c9167dbce7a9de4d3d571c5f3ea77c305a
pycparser==3.12 --hash=sha256:a076f3f489b39b43ed13563a1dafe42447445bec2e294154ec5c57fcdda4c85e
pydantic==2.14.4 --hash=sha256:653a2ad9f6d8858529c77c72717d0ea991d6c6837fe683246b2f4b2bbfc3fadc
pydantic-core==2.50.5 --hash=sha256:470bbc2495367f60d3ca849a8039e4c164701d10637e7743f4427d92651bdb6d
pydantic-extra-types==2.11.1 --hash=sha256:1722ea2bddae5628ace25f2aa685b69978ef533123e5638cfbddb999e0100ec1
pydantic-settings==2.16.3 --hash=sha256:d1db16a2d34006323a1b42c0640898da58adfbad7ec30baaa9e2b18aafc08999
pygments==2.21.0 --hash=sha256:2363c69b61c4a97c838da3b130dcd6468f4848992b21a82f2a63ec34377137d9
pyjwt==2.15.1 --hash=sha256:42d59d631f7768a1028a64c7ff581a9bf7519804daf91fc5b6c56e30eec5e193
pynvvideocodec==2.0.4 --hash=sha256:b59cec7a1a3f78fad13fead78cad8b6d9686827f9ff4477080245457675a01d0
python-dotenv==1.2.4 --hash=sha256:42269a8a5b3fd54ffa6f3d84b18abed50064717576b4ecf03dc4a55d8aa04fdc
python-json-logger==4.2.0 --hash=sha256:158a52126fcd6869e09574d2b66272666f3dc8f468c62637ef9a1fa883719cb9
python-multipart==0.0.34 --hash=sha256:ebacd224bd686eee2f9aa1066a657affe07435a185834e05e5235e2e59173e91
pyyaml==6.0.4 --hash=sha256:93bfb2459195406a518e2f487a9bbf01df240175f31e06f5a252ac6734c7bbf0
pyzmq==27.3.0 --hash=sha256:858fe25231e0fd8612da142efde019faa5ef63fa150a821a27870e791b38c798
quack-kernels==0.6.5 --hash=sha256:df1ddd31366c82eb9692fe087c671209189dcbde53c909c81a865d4ee66b158d
referencing==0.37.0 --hash=sha256:381329a9f99628c9069361716891d34ad94af76e461dcb0335825aecc7692231
regex==2026.11.24 --hash=sha256:0778f76a63e677ef022087a6a49c9b82de9bb1916bd7402a25abfe9f66bdd97f
requests==2.34.2 --hash=sha256:2a0d60c172f83ac6ab31e4554906c0f3b3588d37b5cb939b1c061f4907e278e0
rich==15.0.0 --hash=sha256:33bd4ef74232fb73fe9279a257718407f169c09b78a87ad3d296f548e27de0bb
rich-toolkit==0.20.6 --hash=sha256:465453ba6f94f99401f59f79fb562827ba5f6b4d4759015d40019f5c67750262
rignore==0.8.1 --hash=sha256:2e68cfc4ee0a2909952af2aebd608d1cd22f7d1cdce332cb0b5ea3762939865d
rpds-py==2026.9.1 --hash=sha256:addeda51556dac7c1a2f14cda62db8b621cd12afba3091d03a96c72932387eab
safetensors==0.8.0 --hash=sha256:fd6f3f93c9a0a7cc2788ee63fb763353d4bd2e89b0751bc78fcf7dda00bea774
sentencepiece==0.2.3 --hash=sha256:cc3189b79c1ffda767f71b04238c27ac746f3b7abc263eab9a41c4cf46aee49e
sentry-sdk==3.0.0 --hash=sha256:22cfcdb11b494e8efa82a48edd655afdf99179df37f2ed37f18846b938455c36
setproctitle==1.3.8 --hash=sha256:4a765e0c80a2453480be27c4fc22ba1c0771867040c5f91e4221940d78a4abfb
setuptools==84.2.1 --hash=sha256:ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2
shellingham==1.5.4 --hash=sha256:7ecfff8f2fd72616f7481040475a65b2bf8af90a56c89140852d1120324e8686
six==1.17.0 --hash=sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274
sniffio==1.3.1 --hash=sha256:2f6da418d1f1e0fddd844478f41680e794e6051915791a034ff65e5f100525a2
sse-starlette==3.7.1 --hash=sha256:c1bb3af0508c6c24cd4ab6257047654bbec01456a424bed36b36e8020cd7a37f
starlette==1.10.0 --hash=sha256:478c0ab3b4ced6e82719849c118fa406f0278a3499c1a898cd15cd31bdc38ce4
supervisor==4.3.0 --hash=sha256:0bcb763fddafba410f35cbde226aa7f8514b9fb82eb05a0c85f6588d1c13f8db
sympy==1.14.0 --hash=sha256:e091cc3e99d2141a0ba2847328f5479b05d94a6635cb96148ccb3f34671bd8f5
tabulate==0.10.0 --hash=sha256:f0b0622e567335c8fabaaa659f1b33bcb6ddfe2e496071b743aa113f8774f2d3
tiktoken==0.14.0 --hash=sha256:7896eea257fe497a2b7134474d909156c6744ce8da35bce88011a960e008aa0d
tilelang==0.1.12 --hash=sha256:bbeb5573cbe2544a51a5c9a6cc737c5e3b5c2d95411caa3687fd9b08eb9d5f97
tokenizers==0.23.3 --hash=sha256:376851d22bcf9d650a5c3090bb83e6cf9e895fbf0595369fa4cd43c1f69b5f87
tokenspeed-mla==2.0.3 --hash=sha256:576ce91e861598347f09c429fe41269863d351bf3de8410a845dae39fa172e4a
tokenspeed-triton==3.9.10.post20261028 --hash=sha256:67f520af474d3e8afce38155c73b2b9a42864100ee220e2ee775f8706f1c5cc9
torch==2.14.0 --hash=sha256:fecffb58f51fd643d213acd68da21cc3fc19bea05a3bc64b4ee55128f47a4963
torch-c-dlpack-ext==0.1.5 --hash=sha256:e6f9da4bb9af70e27facc777458be62e10dbbbddda7672d16138db0553c5a524
torchaudio==2.11.0 --hash=sha256:6503c0bdb29daf2e6281bb70ea2dfe2c3553b782b619eb5d73bdadd8a3f7cecf
torchcodec==0.17.0 --hash=sha256:defd5f0901999c9e981f6465a0f4aac8b5a5147e38e539b77c0711c015cf5349
torchvision==0.29.0 --hash=sha256:0e631a2f8b24732672d35224d2574ff89a78d56bef5364ef6094a625fa5f1771
tqdm==4.70.1 --hash=sha256:c293e525e6fef9c20e8728fd4612df02a0aa31bb5fe91ecd93e123b1b7bffa73
transformers==5.22.2 --hash=sha256:829c2820aff91730b8ec45a4b8ff4be07f586a140b68a9073998b36fa35297dc
triton==3.8.0 --hash=sha256:e91ffa46d095b252248297292dd22bcbacd53a125a0c2eefbbbf74925a320bc3
truststore==0.10.5 --hash=sha256:9aaaedaefaf06d8b206278cf8b5012bc897f485a874503501e12d776df78951c
typer==0.29.2 --hash=sha256:f30731f8ca758368b836b3714872e58e395cef8fcaff918c853b1969ed5274e7
typing-extensions==4.16.0 --hash=sha256:481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8
typing-inspection==0.4.5 --hash=sha256:bc210535442b39e1bf2805e0c7a17dfd6a4ace760c84c7f7d16245d23a6b1c39
urllib3==2.8.0 --hash=sha256:0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3
uvicorn==0.54.0 --hash=sha256:505bdb0f318731d45f1f712071fc781a8981f6847a31c902c9f5e652d4f67faf
uvloop==0.23.0 --hash=sha256:090865d8ce7a03986755a3ce711b7dd0d4b44eb14ab74368b717f3fad1180208
vllm==0.34.0 --hash=sha256:79ca4b3cd74aec08c4bf476bdf0cb15735b605ae5368526a2faae1e30f044ca2
watchfiles==1.3.0 --hash=sha256:b5768b49e426fd5b550b012c866db347cdf15c398ef98dc557b6e6b72fa74cd1
websockets==17.4 --hash=sha256:9ae1429ee9e52b139167ed0169757806a27ed7307e942e8c62037a9184e9843b --hash=sha256:c6bd2c9781915592b209160d0f017d4c7c82ad53075e6b0c24d2a89299e7f9e9
xgrammar==0.2.8 --hash=sha256:4045b096735bb2523e0d874039a55994c1b390620d547c4a0d4f43b9a106177b
yarl==1.25.1 --hash=sha256:681c758b0490f9e96b78e5fa8e8dc6e648e9185bb6eaebe73183c33ea0c445f3 --hash=sha256:c6f117789d22dce188e5754e8bc65b7e6ebf8cb73963b9fa761f672a5883769d
z3-solver==4.15.4.0 --hash=sha256:7e103a6f203f505b8b8b8e5c931cc407c95b61556512d4921c1ddc0b3f41b08e
VLLM_LOCK

FROM os AS runtime
ARG TARGETARCH
# Non-root user as in upstream's vllm-openai-nonroot target: UID 2000, GID 0,
# group-writable HOME so arbitrary UIDs in group 0 can also write their caches.
RUN <<'SH'
set -eu
! grep -q -E '^vllm:|^[^:]*:[^:]*:2000:' /etc/passwd
printf 'vllm:x:2000:0:vLLM:/home/vllm:/bin/bash\n' >> /etc/passwd
printf 'vllm:!!:::::::\n' >> /etc/shadow
install -d -m 0770 -o 2000 -g 0 /home/vllm /home/vllm/.cache /home/vllm/.config
# The working directory must be enterable by any UID and GID: a process whose
# working directory it cannot read fails on the first relative path.
install -d -m 0755 -o 0 -g 0 /vllm-workspace
SH

# uv exists only during this RUN; the venv is created without pip. Every wheel
# is installed from the hash-locked set above with no dependency resolution.
RUN --mount=from=uv,source=/uv,target=/run/uv \
    --mount=from=locked-requirements,source=/requirements.txt,target=/run/vllm-requirements.txt <<'SH'
set -eu
test "$TARGETARCH" = amd64
export UV_PYTHON_DOWNLOADS=never UV_NO_CACHE=1
/run/uv --no-config venv --python /usr/bin/python3.12 /opt/vllm
/run/uv --no-config pip install --python /opt/vllm/bin/python \
    --index-url https://pypi.org/simple --only-binary :all: --no-deps \
    --require-hashes --compile-bytecode -r /run/vllm-requirements.txt
/opt/vllm/bin/python -I - /run/vllm-requirements.txt <<'PY'
import importlib.metadata as metadata
import importlib.util
import sys
from pathlib import Path
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version
locked = {}
for line in Path(sys.argv[1]).read_text().splitlines():
    if line and not line.startswith('#'):
        name, version = line.split(' ', 1)[0].split('==')
        locked[canonicalize_name(name)] = Version(version)
installed = {canonicalize_name(d.metadata['Name']): Version(d.version) for d in metadata.distributions()}
assert installed == locked, 'Installed distributions differ from the lock'
# --no-deps is safe only if the lock satisfies every declared dependency. The
# one intended exception is vLLM's setuptools<81 cap (see header).
violations = set()
for dist in metadata.distributions():
    for text in dist.requires or []:
        requirement = Requirement(text)
        if requirement.marker and not requirement.marker.evaluate({'extra': ''}):
            continue
        dependency = canonicalize_name(requirement.name)
        if dependency not in installed or not requirement.specifier.contains(installed[dependency], prereleases=True):
            violations.add((canonicalize_name(dist.metadata['Name']), dependency))
assert violations == {('vllm', 'setuptools')}, sorted(violations)
assert installed['vllm'] == Version('0.34.0') and installed['setuptools'] >= Version('84.2.1')
assert importlib.util.find_spec('pip') is None and not list(Path('/opt/vllm/bin').glob('pip*'))
print(f'Verified {len(installed)} locked distributions; only vllm -> setuptools is overridden')
PY
SH

LABEL org.opencontainers.image.source="https://github.com/ppippi-dev/docker-images-for-cve" \
      org.opencontainers.image.version="0.34.0-oss-r2" \
      org.opencontainers.image.base.name="public.ecr.aws/amazonlinux/amazonlinux:2023.12.20261120.0-minimal" \
      org.opencontainers.image.base.digest="sha256:75a2d4226d9b98c914d7eed878a03bef4f365ad548be5d28d464ccba504cec79" \
      org.opencontainers.image.description="vLLM 0.34.0 OpenAI-compatible server rebuilt on Amazon Linux 2023 minimal from hash-locked PyPI wheels for linux/amd64; requires a fresh vulnerability scan before use"
ENV PATH="/opt/vllm/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    VIRTUAL_ENV="/opt/vllm" \
    HOME="/home/vllm" \
    LD_LIBRARY_PATH="/usr/local/nvidia/lib64" \
    NVIDIA_VISIBLE_DEVICES="all" \
    NVIDIA_DRIVER_CAPABILITIES="compute,utility" \
    VLLM_NO_USAGE_STATS="1" \
    DO_NOT_TRACK="1"
WORKDIR /vllm-workspace
USER 2000:0
EXPOSE 8000/tcp
ENTRYPOINT ["vllm", "serve"]
