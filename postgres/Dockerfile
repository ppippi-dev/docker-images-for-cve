# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# LICENSE NOTES
# Package-level remediation of the official Docker Library image
# postgres:16.16-alpine3.24 (linux/amd64). PostgreSQL itself is not rebuilt:
# every file under /usr/local except the user-switch helper keeps its upstream
# bytes (checked below). PostgreSQL is under the PostgreSQL License; Alpine
# packages keep their own licenses (including GPL/LGPL, e.g. busybox, bash,
# readline, libstdc++; Alpine package sources: https://gitlab.alpinelinux.org/alpine/aports),
# su-exec is MIT and the Docker Library scripts are MIT. The upstream image
# ships no PostgreSQL license file; COPYRIGHT of the REL_16_16 tag (identical
# to the one in the release tarball) is added under /usr/share/licenses/postgresql.
# As in the upstream image, the license texts of the Alpine packages and of
# su-exec are not in the image.
# A successful CVE scan or functional test does not establish license clearance.
#
# PUBLIC REPOSITORY RULES
# - Track README.md, <open-source-name>/Dockerfile and reviewed build workflows only.
#   Never commit organization data, configuration,
#   hostnames, credentials, certificates, logs, scan reports, SBOMs or image TARs.
# - Use public upstream artifacts only; pin images by digest and Alpine
#   packages by exact version (the package-list check below enforces it).
#   Record each dependency change here for review.
# - Change open source at Dockerfile level only (base image, OS packages, helper
#   binaries); never patch upstream code files.
# - No local COPY/ADD, host-directory build mounts, private package indexes or
#   secret-valued ARG/ENV. Build from stdin with an empty context (command below).
# - Keep test files, reports and exported images outside this repository;
#   functional checks live in .github/workflows/build-images.yml. Never use
#   CVE ignores, severity filtering or --ignore-unfixed to claim a clean image.
# - Re-scan every candidate with a fresh vulnerability DB and retain all findings.
#   No runtime/compiler exceptions: every component must satisfy CVSS v3 = 0.
#   Any v3 score > 0, unknown/malformed assessment, or scanner error blocks.
# - Preserve upstream license notices; an image contains multiple licenses.
# - image.version is <upstream>-<variant>-rN (16.16-alpine3.24-r2). Main
#   publishes each image.version once as v<image.version>; a published version
#   tag is never re-pointed. Raise rN (-r1 -> -r2) to publish a rebuild of the
#   same upstream image; start again at -r1 for a new upstream tag.
#
# SCAN SCOPE
# Trivy inventories the Alpine packages only. The PostgreSQL server is built
# from source by the upstream image under /usr/local and has no package entry,
# so a PostgreSQL CVE is not reported by an image scan: follow the PostgreSQL
# security page (https://www.postgresql.org/support/security/) and move to the
# newest 16.x upstream tag when it lists a fix.
#
# CHANGES AGAINST THE UPSTREAM IMAGE, and nothing else
# - libcrypto3 3.5.9-r0 -> 3.5.9-r1, libssl3 3.5.9-r0 -> 3.5.9-r1,
#   libxml2 2.13.9-r2 -> 2.13.9-r5 (Alpine v3.24 main, signed index), with
#   "apk upgrade" so that /etc/apk/world gets no version pins.
# - gosu is removed. Alpine's su-exec 0.3-r0 is added, and /usr/local/bin/gosu
#   and /usr/local/bin/su-exec point to it, so the unchanged entrypoint can
#   still drop from root to postgres (exec gosu postgres "$BASH_SOURCE" "$@").
#   As a non-root user the entrypoint never calls gosu. su-exec takes the
#   same "user[:group] command" form; "gosu --version" is not provided.
# - /usr/share/licenses/postgresql/COPYRIGHT is added (see LICENSE NOTES).
# - ENV GOSU_VERSION is dropped. Other config (ENV, ENTRYPOINT, CMD, VOLUME,
#   STOPSIGNAL, EXPOSE, WORKDIR) equals upstream.
# - Layers are flattened, so the removed gosu and old libraries are physically
#   absent from every layer, not only hidden by a whiteout.
# The build fails unless exactly these packages change, gosu is a link to
# su-exec, every other file under /usr/local is unchanged and
# pg_config --configure equals upstream.
#
# Build (linux/amd64 only; no local build context is sent):
#   docker build --platform linux/amd64 -t postgres-cve:16.16-alpine3.24-r2 - < postgres/Dockerfile
# Supplementary public scan (run outside this repository):
#   trivy image --scanners vuln --ignorefile '' --ignore-unfixed=false \
#     --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL --exit-code 1 \
#     postgres-cve:16.16-alpine3.24-r2
# CI also starts the server as uid 70 with a read-only root and as root, restarts
# it on the same volume and connects from a second container with a password.
#
# Baseline: upstream 16.16-alpine3.24, platform manifest
#   sha256:9d9e487c1bd6413c52ccb3c02f46c8e37fa1e1d1a32a84519eb4e68d0ad1da30
#   (Trivy 0.76.2, DB 2026-11-27): 84 findings, all with a fixed version.
#   - 61 in /usr/local/bin/gosu 1.20: it is built with Go 1.24.6 and
#     golang.org/x/sys v0.1.0 on purpose (upstream does not rebuild gosu for
#     stdlib CVEs). The 16.16 bookworm/trixie/alpine3.23 variants carry the same
#     gosu, and Debian variants add hundreds of OS findings.
#   - 23 in Alpine 3.24 packages: libcrypto3/libssl3 3.5.9-r0 (10, fixed in
#     3.5.9-r1) and libxml2 2.13.9-r2 (13, fixed in 2.13.9-r3, -r4 and -r5).
#
# UPKEEP (a new upstream 16.x tag, a new Alpine package release, or a new finding)
# The Alpine index keeps only the newest release of a package, so the
# package-list check fails as soon as Alpine publishes a newer one. A pull
# request that changes the workflow builds every recipe, so it fails on this
# recipe too until the recipe is updated; then:
# 1. Upstream: find the newest 16.x-alpine3.y tag in the Tags lines of
#    https://github.com/docker-library/official-images/blob/master/library/postgres
#    and its index digest with docker buildx imagetools inspect
#    docker.io/library/postgres:<tag>. Scan it as is (command above, on the
#    upstream tag). If it scans 0, the recipe is not needed: retire it (see
#    README, Upkeep).
# 2. Otherwise set FROM to that tag and index digest, update the PG_VERSION test,
#    the ENV block (docker image inspect --format '{{json .Config.Env}}' <upstream>,
#    without GOSU_VERSION) and the base.name/base.digest/description labels.
#    Resolve the REL_16_<minor> tag of postgres/postgres to its commit (GitHub
#    git/ref/tags API) and update the COPYRIGHT URL and checksum. Update every
#    version in this header too, Baseline included.
# 3. Put every Alpine package the scan names into "apk upgrade" and keep the
#    gosu replacement while upstream gosu has findings.
# 4. Build. The package-list check prints the real change; confirm that each new
#    version is the fixed version the scan names, then copy it into the
#    expected list below and into CHANGES above.
# 5. Set image.version (new upstream: <pg>-alpine<3.y>-r1; same upstream: raise
#    rN), rebuild from an empty context, scan, and open a pull request: CI runs
#    the same build, checks and scan without publishing.

FROM docker.io/library/postgres:16.16-alpine3.24@sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d AS patched
ARG TARGETARCH
ADD --checksum=sha256:3d6af92ff8a4c2cdf69afb1cf44edea727922f5cd0cf8b5f72b11cdecac8fdfd \
    https://raw.githubusercontent.com/postgres/postgres/c0534eb02de050ac1035ad7b3ad7c3f02980f153/COPYRIGHT /tmp/postgresql-COPYRIGHT
RUN <<'SH'
set -eu
test "$TARGETARCH" = amd64
test "$PG_VERSION" = 16.16
apk info -v | sort > /tmp/apk-before
( cd /usr/local && find . -type f ! -path ./bin/gosu -exec sha256sum {} + | sort ) > /tmp/local-before
pg_config --configure > /tmp/configure-before
cp /etc/apk/world /tmp/apk-world-before

# "upgrade" keeps /etc/apk/world free of version pins; the exact versions are
# enforced by the package-list check below, which fails when the index moves.
apk upgrade --no-cache libcrypto3 libssl3 libxml2
apk add --no-cache su-exec
rm -f /usr/local/bin/gosu /usr/local/bin/su-exec
ln -s /sbin/su-exec /usr/local/bin/gosu
ln -s /sbin/su-exec /usr/local/bin/su-exec

# Only the intended packages changed.
apk info -v | sort > /tmp/apk-after
{ comm -23 /tmp/apk-before /tmp/apk-after | sed 's/^/- /'
  comm -13 /tmp/apk-before /tmp/apk-after | sed 's/^/+ /'; } > /tmp/apk-diff
cat > /tmp/apk-expected <<'EOF'
- libcrypto3-3.5.9-r0
- libssl3-3.5.9-r0
- libxml2-2.13.9-r2
+ libcrypto3-3.5.9-r1
+ libssl3-3.5.9-r1
+ libxml2-2.13.9-r5
+ su-exec-0.3-r0
EOF
diff /tmp/apk-expected /tmp/apk-diff
{ cat /tmp/apk-world-before; echo su-exec; } | sort | diff - /etc/apk/world
# gosu is only a link to su-exec.
test "$(readlink /usr/local/bin/gosu)" = /sbin/su-exec
test "$(readlink /usr/local/bin/su-exec)" = /sbin/su-exec
# PostgreSQL binaries, libraries and scripts keep their upstream bytes.
( cd /usr/local && find . -type f -exec sha256sum {} + | sort ) > /tmp/local-after
diff /tmp/local-before /tmp/local-after
pg_config --configure | diff /tmp/configure-before -
postgres --version
su-exec nobody true
gosu postgres true
mkdir -p /usr/share/licenses/postgresql
cp /tmp/postgresql-COPYRIGHT /usr/share/licenses/postgresql/COPYRIGHT
chmod 0755 /usr/share/licenses /usr/share/licenses/postgresql
chmod 0644 /usr/share/licenses/postgresql/COPYRIGHT
# "apk info" also stores the index in /var/cache/apk; the upstream image has none.
rm -rf /tmp/apk-* /tmp/local-* /tmp/configure-before /tmp/postgresql-COPYRIGHT /var/cache/apk/*
test -z "$(ls -A /var/cache/apk)"
SH

FROM scratch
COPY --from=patched / /
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    LANG="en_US.utf8" \
    PG_MAJOR="16" \
    PG_VERSION="16.16" \
    PG_SHA256="9d5cd8633043b75740d5d59749c6b7365e6aeb53c47098b1a5e80bb18f87881a" \
    DOCKER_PG_LLVM_DEPS="llvm21-dev 		clang21" \
    PGDATA="/var/lib/postgresql/data"
LABEL org.opencontainers.image.source="https://github.com/ppippi-dev/docker-images-for-cve" \
      org.opencontainers.image.version="16.16-alpine3.24-r2" \
      org.opencontainers.image.base.name="docker.io/library/postgres:16.16-alpine3.24" \
      org.opencontainers.image.base.digest="sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d" \
      org.opencontainers.image.description="Official PostgreSQL 16.16 Alpine image with patched Alpine packages and su-exec in place of gosu; requires a fresh vulnerability scan before use"
VOLUME /var/lib/postgresql/data
WORKDIR /
ENTRYPOINT ["docker-entrypoint.sh"]
STOPSIGNAL SIGINT
EXPOSE 5432
CMD ["postgres"]
