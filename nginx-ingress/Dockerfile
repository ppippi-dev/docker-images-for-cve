# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# LICENSE NOTES
# Package-level remediation of the official F5 NGINX Ingress Controller image
# public.ecr.aws/nginx/nginx-ingress:5.8.1-alpine (linux/amd64). Nothing is
# rebuilt: the controller binary, its templates, the njs scripts and the
# nginx.org packages keep their upstream bytes (checked below). The image
# contains components under several licenses:
# - The controller is Apache-2.0. F5 builds the image from a commit other than
#   the public v5.8.1 tag, so the LICENSE of that tag (commit 0f2c1bb) is added
#   under /usr/share/licenses/nginx-ingress.
# - nginx, njs and the geoip, image-filter and xslt modules are BSD-2-Clause.
#   The acme and otel modules are Apache-2.0: their COPYRIGHT files are Apache
#   License 2.0 texts, although the apk metadata of every nginx.org package says
#   "2-clause BSD-like license". The otel module includes opentelemetry-cpp
#   1.28.0 (Apache-2.0); the acme module is written in Rust and includes Rust
#   library code under its own licenses. The COPYRIGHT files are kept in
#   /usr/share/licenses/nginx*.
# - nginx-agent is Apache-2.0 and, as in the upstream image, has no license
#   file in the image.
# - /nginx-ingress (119 Go modules) and nginx-agent (305) are static Go
#   binaries that include third-party Go modules under their own licenses, e.g.
#   BSD-3-Clause (golang.org/x), Apache-2.0 (k8s.io), MIT and, in nginx-agent,
#   MPL-2.0 (hashicorp/go-version, hashicorp/golang-lru). As in the upstream
#   image, their license texts are not in the image.
# - Alpine packages keep their own licenses (including GPL/LGPL, e.g. busybox;
#   libexpat is MIT; Alpine package sources:
#   https://gitlab.alpinelinux.org/alpine/aports).
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
# - image.version is <upstream>-<variant>-rN (5.8.1-alpine-r1). Main
#   publishes each image.version once as v<image.version>; a published version
#   tag is never re-pointed. Raise rN (-r1 -> -r2) to publish a rebuild of the
#   same upstream image; start again at -r1 for a new upstream tag.
#
# SCAN SCOPE
# Trivy inventories the Alpine packages and the Go modules of /nginx-ingress.
# nginx, njs, the nginx modules and nginx-agent are nginx.org packages recorded
# in the apk database under Alpine-like names: Trivy matches them against
# Alpine advisories by name only, and it does not inventory the Go modules
# inside nginx-agent. Follow the nginx security advisories
# (https://nginx.org/en/security_advisories.html) and the kubernetes-ingress
# releases (https://github.com/nginx/kubernetes-ingress/releases), and move to
# the newest upstream tag when they list a fix.
#
# CHANGES AGAINST THE UPSTREAM IMAGE, and nothing else
# - libexpat 2.10.0-r0 -> 2.11.0-r0 (Alpine v3.24 main, signed index), with
#   "apk upgrade" so that /etc/apk/world gets no version pin. Only
#   /usr/lib/libfontconfig.so.1 links it (image-filter -> libgd -> fontconfig).
# - /usr/share/licenses/nginx-ingress/LICENSE is added (see LICENSE NOTES).
# - Layers are flattened, so the old libexpat is physically absent from every
#   layer, not only hidden by a whiteout. File capabilities and ownership are kept.
# - Config (ENV, ENTRYPOINT, USER, WORKDIR, EXPOSE, STOPSIGNAL) equals upstream;
#   the upstream labels are replaced by the labels below. That drops the
#   upstream licenses label (Apache-2.0), which names the controller's license
#   only; LICENSE NOTES list the licenses of the image.
# The build fails unless exactly this package changes, /etc/apk/world and the
# file capabilities of /nginx-ingress, nginx and nginx-debug are unchanged, and
# every other entry keeps its upstream type, mode, owner, symlink target and,
# for files, bytes.
#
# Build (linux/amd64 only; no local build context is sent):
#   docker build --platform linux/amd64 -t nginx-ingress-cve:5.8.1-alpine-r1 - < nginx-ingress/Dockerfile
# Supplementary public scan (run outside this repository):
#   trivy image --scanners vuln --ignorefile '' --ignore-unfixed=false \
#     --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL --exit-code 1 \
#     nginx-ingress-cve:5.8.1-alpine-r1
# CI also checks the controller version, runs nginx -t with every dynamic module
# and the njs scripts, and serves port 80 as uid 101 on a read-only root through
# the file capability of nginx.
# Not verified: the controller against a Kubernetes API (watching Ingress and
# VirtualServer resources, rendering configuration from the templates, reloads),
# leader election, nginx-agent, TLS, OpenTelemetry export, and linux/arm64.
#
# Baseline: upstream 5.8.1-alpine, platform manifest
#   sha256:26a6ed01de687f4a2a8b9991632d40d72dde114dc54bc00a185e2ee7ec1e2380
#   (Trivy 0.76.2, DB 2026-11-26): 3 findings, all in Alpine libexpat 2.10.0-r0
#   with the fixed version 2.11.0-r0. The 5.8.1-ubi variant has 1 finding in a Go
#   module and the Debian variant hundreds. 5.8.1 is the newest release.
#
# UPKEEP (a new upstream tag, a new Alpine package release, or a new finding)
# The Alpine index keeps only the newest release of a package, so the
# package-list check fails as soon as Alpine publishes a newer libexpat. A pull
# request that changes the workflow builds every recipe, so it fails on this
# recipe too until the recipe is updated; then:
# 1. Upstream: find the newest kubernetes-ingress release and the index digest
#    of its -alpine tag with docker buildx imagetools inspect
#    public.ecr.aws/nginx/nginx-ingress:<version>-alpine. Scan it as is (command
#    above, on the upstream tag). If it scans 0, the recipe is not needed: retire
#    it (see README, Upkeep).
# 2. Otherwise set FROM to that tag and index digest, update the Alpine release,
#    controller version and nginx version tests (here and in the CI step), the
#    ENV block (docker image inspect --format '{{json .Config.Env}}' <upstream>)
#    and the base.name/base.digest/description labels. Resolve the v<version> tag
#    of nginx/kubernetes-ingress to its commit (GitHub git/ref/tags API) and
#    update the LICENSE URL and checksum. Update every version in this header
#    too, Baseline included.
# 3. Put every Alpine package the scan names into "apk upgrade".
# 4. Build. The package-list check prints the real change; confirm that each new
#    version is the fixed version the scan names, then copy it into the
#    expected list below and into CHANGES above.
# 5. Set image.version (new upstream: <version>-alpine-r1; same upstream: raise
#    rN), rebuild from an empty context, scan, and open a pull request: CI runs
#    the same build, checks and scan without publishing.

FROM public.ecr.aws/nginx/nginx-ingress:5.8.1-alpine@sha256:3396b325971fd36202dfb2e0dca73950d23d27f570ab5ed232d3540799ad6ff7 AS patched
ARG TARGETARCH
USER 0
ADD --checksum=sha256:444e7731cbe71bc2f52bbbffb809f41ca562524e4e2945da78cf3b41305b3de0 \
    https://raw.githubusercontent.com/nginx/kubernetes-ingress/0f2c1bb499dd434c335885a6f568e2d7d3d07158/LICENSE /tmp/nginx-ingress-LICENSE
RUN <<'SH'
set -eu
test "$TARGETARCH" = amd64
test "$(cat /etc/alpine-release)" = 3.24.4
/nginx-ingress -version | grep -q '^NGINX Ingress Controller Version=5.8.1 '
apk info -v | sort > /tmp/apk-before
cp /etc/apk/world /tmp/apk-world-before
getcap /nginx-ingress /usr/sbin/nginx /usr/sbin/nginx-debug > /tmp/caps-before
# Every other entry (controller binary, templates, njs, nginx.org packages,
# configuration) keeps its upstream type, mode, owner, symlink target and, for
# files, bytes.
entries() {
  find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /tmp -o -path /lib/apk -o -path /var/cache/apk -o -path /etc/apk \) -prune -o "$@" -print0
}
snapshot() {
  { entries | xargs -0 stat -c '%n|%F|%f|%u:%g|%N'
    entries -type f | xargs -0 sha256sum | sed 's/^\([0-9a-f]*\)  \(.*\)$/\2|sha256:\1/'
  } | grep -v -e '^/usr/lib/libexpat\.so' -e '^/var/log/apk\.log|' | sort
}
snapshot > /tmp/files-before
grep -qx '/nginx-ingress|regular file|81fd|101:0|/nginx-ingress' /tmp/files-before
grep -q '^/nginx\.tmpl|sha256:' /tmp/files-before

# "upgrade" keeps /etc/apk/world free of version pins; the exact versions are
# enforced by the package-list check below, which fails when the index moves.
apk upgrade --no-cache libexpat

# Only the intended package changed.
apk info -v | sort > /tmp/apk-after
{ comm -23 /tmp/apk-before /tmp/apk-after | sed 's/^/- /'
  comm -13 /tmp/apk-before /tmp/apk-after | sed 's/^/+ /'; } > /tmp/apk-diff
cat > /tmp/apk-expected <<'EOF'
- libexpat-2.10.0-r0
+ libexpat-2.11.0-r0
EOF
diff /tmp/apk-expected /tmp/apk-diff
diff /tmp/apk-world-before /etc/apk/world
getcap /nginx-ingress /usr/sbin/nginx /usr/sbin/nginx-debug | diff /tmp/caps-before -
snapshot | diff /tmp/files-before -
mkdir -p /usr/share/licenses/nginx-ingress
cp /tmp/nginx-ingress-LICENSE /usr/share/licenses/nginx-ingress/LICENSE
chmod 0755 /usr/share/licenses/nginx-ingress
chmod 0644 /usr/share/licenses/nginx-ingress/LICENSE
# "apk info" also stores the index in /var/cache/apk; the upstream image has none.
rm -rf /tmp/apk-* /tmp/caps-before /tmp/files-before /tmp/nginx-ingress-LICENSE /var/cache/apk/*
test -z "$(ls -A /var/cache/apk)"
test -z "$(ls -A /tmp)"
SH

FROM scratch
COPY --from=patched / /
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    BUILD_OS="alpine"
LABEL org.opencontainers.image.source="https://github.com/ppippi-dev/docker-images-for-cve" \
      org.opencontainers.image.version="5.8.1-alpine-r1" \
      org.opencontainers.image.base.name="public.ecr.aws/nginx/nginx-ingress:5.8.1-alpine" \
      org.opencontainers.image.base.digest="sha256:3396b325971fd36202dfb2e0dca73950d23d27f570ab5ed232d3540799ad6ff7" \
      org.opencontainers.image.description="F5 NGINX Ingress Controller 5.8.1 Alpine image with a patched Alpine libexpat; requires a fresh vulnerability scan before use"
WORKDIR /
EXPOSE 80 443
STOPSIGNAL SIGTERM
USER 101
ENTRYPOINT ["/nginx-ingress"]
