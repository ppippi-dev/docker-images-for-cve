# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# LICENSE NOTES
# Apache APISIX 3.21.0 (Apache-2.0) on Amazon Linux 2023 minimal for
# linux/amd64. This recipe installs the official signed APISIX 3.21.0 RPM
# unchanged (the package the official -redhat image installs) on a different
# base; no APISIX file is patched. As in the official image, only the bundled
# etcdctl is removed.
# The RPM ships no APISIX LICENSE or NOTICE file, so APISIX's LICENSE and NOTICE
# from the release tag are added under /usr/share/licenses/apisix.
# The image also contains components under other licenses:
# - The RPM bundles apisix-runtime under /usr/local/openresty: OpenResty and
#   nginx (BSD-2-Clause), LuaJIT (MIT), OpenSSL 3.5.9 (Apache-2.0), PCRE 8.45
#   (BSD-3-Clause), zlib 1.3.2 (zlib license) and the Wasmtime C API
#   (Apache-2.0 WITH LLVM-exception); Lua rocks under /usr/local/apisix/deps
#   (MIT, Apache-2.0, BSD or public domain; each rockspec or doc/LICENSE names
#   it); and the built dashboard UI under /usr/local/apisix/ui, whose
#   JavaScript bundles include third-party libraries under their own licenses.
# - Amazon Linux RPMs under their own licenses, including GPL/LGPL (e.g. glibc,
#   bash). Corresponding sources of the pinned release, one source package per
#   call (its name is rpm -q --qf '%{SOURCERPM}' <package> in the image):
#     docker run --rm -v "$PWD:/out" -w /out <base image below> \
#       dnf download --source --releasever=2023.12.20261120 <source-name>-<version>
# - docker-entrypoint.sh from apache/apisix-docker (Apache-2.0), unchanged.
# Every license file shipped by the packages is kept; see each component's
# license text for its terms. As in the official images, the bundled runtime
# under /usr/local/openresty carries no license text for its OpenSSL, PCRE,
# LuaJIT or zlib; the license files in /usr/share/licenses belong to the Amazon
# Linux packages of those projects. A successful CVE scan or functional test
# does not establish license clearance.
#
# PUBLIC REPOSITORY RULES
# - Track README.md, <open-source-name>/Dockerfile and reviewed build workflows only.
#   Never commit organization data, configuration,
#   hostnames, credentials, certificates, logs, scan reports, SBOMs or image TARs.
# - Use public upstream artifacts only; pin images by digest, downloads by
#   SHA-256 and RPMs by exact version (AL2023 repositories are locked to the
#   base release). Record each dependency change here for review.
# - Change open source at Dockerfile level only (base image, OS packages, helper
#   binaries, unmodified upstream packages); never patch upstream code files.
# - No local COPY/ADD, host-directory build mounts, private package indexes or
#   secret-valued ARG/ENV. Build from stdin with an empty context (command below).
# - Keep test files, reports and exported images outside this repository;
#   functional checks live in .github/workflows/build-images.yml. Never use
#   CVE ignores, severity filtering or --ignore-unfixed to claim a clean image.
# - Re-scan every candidate with a fresh vulnerability DB and retain all findings.
#   No runtime/compiler exceptions: every component the scan inventories must
#   satisfy CVSS v3 = 0. Any v3 score > 0, unknown/malformed assessment, or
#   scanner error blocks. SCAN SCOPE states what the scan cannot see.
# - Preserve upstream license notices; an image contains multiple licenses.
# - image.version is <upstream>-<variant>-rN (3.21.0-al2023-r1). Main publishes
#   each image.version once as v<image.version>; a published version tag is
#   never re-pointed. Raise rN (-r1 -> -r2) to publish a rebuild of the same
#   APISIX version; start again at -r1 for a new APISIX version. Main keeps
#   only the newest version of the package and deletes every other one, so
#   never go back to an earlier label.
#
# SCAN SCOPE
# Trivy inventories the Amazon Linux RPMs and the apisix RPM entry; no Amazon
# Linux advisory covers apisix, so the scan reports nothing for that entry.
# Trivy does not inventory what the apisix RPM bundles: OpenResty/nginx
# (openresty -V: openresty/1.31.9.1), OpenSSL 3.5.9, PCRE 8.45, zlib 1.3.2,
# LuaJIT and the Wasmtime C API under /usr/local/openresty, the Lua rocks under
# /usr/local/apisix/deps, and the third-party JavaScript bundled in the
# dashboard UI under /usr/local/apisix/ui. A CVE in any of them is not reported
# by an image scan, so a zero scan says nothing about them: follow the OpenSSL
# (https://openssl-library.org/news/vulnerabilities/), nginx
# (https://nginx.org/en/security_advisories.html) and APISIX
# (https://apisix.apache.org/docs/general/security/) security pages.
# Known limit: the bundled OpenSSL is the unmodified OpenSSL 3.5.9 release
# that the upstream apisix 3.21.0 RPM ships, and every official APISIX 3.21.0
# image (-ubuntu, -debian, -redhat) bundles the same OpenSSL 3.5.9. 3.5.9 is
# the newest upstream OpenSSL 3.5 release. As listed on 2026-11-25, the OpenSSL
# vulnerabilities page names twelve CVEs affecting it (from 3.5.0 before
# 3.5.10): CVE-2026-35190, CVE-2026-84785, CVE-2026-84786, CVE-2026-88822,
# CVE-2026-88823, CVE-2026-95691, CVE-2026-95692, CVE-2026-107493,
# CVE-2026-107494, CVE-2026-107496, CVE-2026-121482 and CVE-2026-124709.
# OpenSSL rates all twelve Low. Red Hat scores eleven of them CVSS v3 3.7 to
# 7.5 (7.5 for CVE-2026-107494 and CVE-2026-124709) and has not yet scored
# CVE-2026-84785. Per the advisories they concern QUIC, AES-GCM-SIV,
# CMS_encrypt(), X.509 CRL and PEM handling, DANE clients and TLS 1.3 key-share
# processing; whether APISIX reaches these code paths depends on its
# configuration and is not assessed here. If the scan inventoried the bundled
# OpenSSL, these scores would block publication under the rules above; the
# image is published because the scan of what it inventories is clean, and
# this limit is stated here instead. OpenSSL has fixed all twelve in git for
# 3.5.10, which is not released; Alpine's openssl 3.5.9-r1 backports five of
# them (CVE-2026-88822, -88823, -95691, -95692 and -107496). This recipe does
# not rebuild the runtime, so the bundled OpenSSL changes only with a new
# upstream APISIX runtime release. The list grows as OpenSSL publishes
# advisories; UPKEEP step 4 keeps it current.
#
# CHANGES AGAINST THE OFFICIAL -redhat IMAGE
# - Base: AL2023 minimal instead of UBI 9; its glibc (2.34) matches the EL9
#   build of the RPM. AL2023 repositories are locked to the base release, so
#   the pinned RPMs below resolve identically.
# - The RPM's declared dependencies (libxml2, libxslt, libyaml-devel,
#   openldap-devel, pcre, which) are installed from the AL2023 repository, as
#   upstream declares them; rpm -i checks them (no --nodeps). libxcrypt is
#   added because nginx links libcrypt.so.2 and the RPM does not declare it
#   (UBI 9 ships it in the base, AL2023 minimal does not).
# - Fewer tools than the standard UBI 9 image the official one starts from:
#   tar (which kubectl cp needs), vi, the openssl command, ip (iproute) and
#   Python 3 are not installed; the package manager is microdnf (also run as
#   dnf). Neither image has ps (procps-ng) or less.
# - No brotli library: the official image compiles it with install-brotli.sh;
#   this recipe does not, so the brotli plugin cannot load. Every other bundled
#   plugin is unchanged.
# - wget is not installed (curl is) and /etc/login.defs is not edited
#   (PASS_MAX_DAYS); the apisix user has home /usr/local/apisix and shell
#   /sbin/nologin, and no /etc/shadow entry.
# - The bundled etcdctl is removed, as in the official image.
# - The apisix user and group (636) are written to /etc/passwd and /etc/group
#   directly instead of groupadd/useradd; ownership, log links, PATH, WORKDIR,
#   EXPOSE, ENTRYPOINT, CMD and STOPSIGNAL follow the official image. USER is
#   numeric (636:636) so that a non-root check needs no /etc/passwd lookup.
#
# Build (linux/amd64 only; no local build context is sent):
#   docker build --platform linux/amd64 -t apisix-cve:3.21.0-al2023-r1 - < apisix/Dockerfile
# Supplementary public scan (run outside this repository):
#   trivy image --scanners vuln --ignorefile '' --ignore-unfixed=false \
#     --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL --exit-code 1 \
#     apisix-cve:3.21.0-al2023-r1
# CI also checks that no ELF file under /usr/local/openresty and
# /usr/local/apisix has an unresolved library, and starts APISIX in standalone
# mode as a non-root user to proxy one request to a local upstream.
#
# Baseline (Trivy 0.76.1, DB 2026-11-25, linux/amd64), OS packages only:
#   apache/apisix:3.21.0-redhat (UBI 9.9), platform manifest
#     sha256:b20541ac3d53ee75f60e77ea67ad80aa94174f60d747adb58ba9c28c555ab740:
#     537 findings, 32 with a fixed version.
#   apache/apisix:3.21.0-ubuntu (Ubuntu 24.04), platform manifest
#     sha256:fa17ec0a723963069de29323f92009d3062bdb7072b50422f9449046063ff939:
#     30 findings, 1 with a fixed version.
#   apache/apisix:3.21.0-debian (Debian 12.15), platform manifest
#     sha256:c5c84e1457f48a1fab9d1e01d9e8c268553efe30b5c54a6a4d2835ee86300367:
#     302 findings, none with a fixed version.
#   The OpenSSL findings among them are of the distribution's own OpenSSL
#   packages; none of these scans reports the bundled OpenSSL (see SCAN SCOPE).
#
# UPKEEP (a new APISIX release, a new AL2023 date release, a new finding, or a
# new advisory on a security page named in SCAN SCOPE)
# The AL2023 release repositories and the APISIX repository keep older
# packages, so the pinned build does not break when upstream moves on; a fresh
# scan fails once an advisory names a pinned RPM. No scan fails for an advisory
# against a bundled component; step 4 covers those. Then:
# 1. Upstream: scan apache/apisix:<v>-redhat, -ubuntu and -debian as published
#    (command above, on the upstream tag) and update Baseline. If one scans 0
#    and its bundled OpenSSL is not older than this recipe's, the recipe is not
#    needed: retire it (see README, Upkeep).
# 2. Base: find the newest 2023.x.<date>.N-minimal tag in the public ECR gallery
#    (gallery.ecr.aws/amazonlinux/amazonlinux, image tags) and its index digest
#    with docker buildx imagetools inspect public.ecr.aws/amazonlinux/amazonlinux:<tag>;
#    the release value is the tag without .N-minimal (cat /etc/amazon-linux-release
#    in it). Replace the FROM tag and digest, the --releasever values and the
#    base.name/base.digest labels. Look up the new RPM versions with
#    docker run --rm <base> dnf --releasever=<release> install --assumeno <names>
#    and update the pinned names below.
# 3. APISIX: find the new apisix-<v>-<release>.x86_64.rpm in
#    https://repos.apiseven.com/packages/redhat/9/x86_64/ (repodata/repomd.xml
#    names the primary.xml.zst that lists every file with its sha256), download
#    it and take its sha256sum; rpm -K below checks its signature. Set
#    APISIX_VERSION, the RPM file name and the --checksum of the RPM ADD line.
#    The KEYS checksum only changes when the APISIX signing key changes (rpm -K
#    below fails then). Resolve the new tag of apache/apisix to its commit
#    (GitHub git/ref/tags API) and update the LICENSE and NOTICE URLs and
#    checksums.
# 4. Bundled components: on every upkeep pass, re-read
#    https://openssl-library.org/news/vulnerabilities/ for the entries that
#    affect the bundled OpenSSL version and update the Known limit in SCAN
#    SCOPE: its date, the CVE list, the Red Hat CVSS v3 scores
#    (https://access.redhat.com/security/cve/<id>) and the distribution
#    backports. When upstream publishes an APISIX release whose runtime bundles
#    a newer OpenSSL, bump to that release (step 3). The runtime version is
#    APISIX_RUNTIME in .requirements of apache/apisix at the release tag; its
#    OpenSSL is OPENSSL_VERSION in build-apisix-runtime.sh of
#    api7/apisix-build-tools at tag apisix-runtime/<version>, and openresty -V
#    prints it during the build, which fails until the "built with OpenSSL"
#    check below names it. Update that check, the OpenSSL and OpenResty
#    versions in this header and the Known limit.
# 5. Official image: diff redhat/Dockerfile and redhat/docker-entrypoint.sh of
#    apache/apisix-docker between the last reviewed commit (d3803aa, in the
#    entrypoint URL) and the newest commit on master that sets the new
#    APISIX_VERSION. Carry over each new package or step, or list it in CHANGES;
#    update the entrypoint commit and sha256.
# 6. Update every version in this header, Baseline included, then set
#    image.version (new APISIX: <v>-al2023-r1; same APISIX: raise rN), rebuild
#    from an empty context, scan, and open a pull request: CI runs the same
#    build, library check, smoke test and scan without publishing.

FROM public.ecr.aws/amazonlinux/amazonlinux:2023.12.20261120.0-minimal@sha256:75a2d4226d9b98c914d7eed878a03bef4f365ad548be5d28d464ccba504cec79

ARG APISIX_VERSION=3.21.0
LABEL org.opencontainers.image.source="https://github.com/ppippi-dev/docker-images-for-cve" \
      org.opencontainers.image.version="${APISIX_VERSION}-al2023-r1" \
      org.opencontainers.image.base.name="public.ecr.aws/amazonlinux/amazonlinux:2023.12.20261120.0-minimal" \
      org.opencontainers.image.base.digest="sha256:75a2d4226d9b98c914d7eed878a03bef4f365ad548be5d28d464ccba504cec79" \
      org.opencontainers.image.description="Apache APISIX ${APISIX_VERSION} from the official signed RPM on Amazon Linux 2023 minimal for linux/amd64; the bundled OpenSSL 3.5.9 is outside the scan and has known CVEs without a released fix (see the recipe header); requires a fresh vulnerability scan before use" \
      apisix_version="${APISIX_VERSION}"

# Official APISIX package signing key and EL9 package (repos.apiseven.com is
# the repository the official -redhat image installs from). The checksum pins
# the RPM of this APISIX_VERSION; a different version fails here.
ADD --checksum=sha256:12314090cb9b72a2eb18decc620b3e03ab0b814dc2186a6242e1dcc6af69cc7a \
    https://repos.apiseven.com/KEYS /tmp/apisix/KEYS
ADD --checksum=sha256:668374da43b921eb01833325ae115250544592705934e1f3f2a942e082377b74 \
    https://repos.apiseven.com/packages/redhat/9/x86_64/apisix-${APISIX_VERSION}-0.ubi9.6.x86_64.rpm /tmp/apisix/apisix.rpm
# Upstream start-up script (identical in the ubuntu, debian and redhat images).
ADD --chmod=0755 --checksum=sha256:ed99ac2755efa9c98ff04b4699e076e0ac5b8b4e6b832f36ef954324ee6ce5fe \
    https://raw.githubusercontent.com/apache/apisix-docker/d3803aada949c8a97bbd1f61f009b6738e818f65/redhat/docker-entrypoint.sh /docker-entrypoint.sh
# The RPM ships no APISIX LICENSE or NOTICE; add APISIX's own from the release
# tag commit (apache/apisix 3.21.0).
ADD --checksum=sha256:f314c26b97520df58cc9f29f30dc1f65f3e0235365b6dce0e3b6adc388958aeb \
    https://raw.githubusercontent.com/apache/apisix/07446140f87b475330ab86f280b94eaf2aeda020/LICENSE /tmp/apisix/LICENSE
ADD --checksum=sha256:25235d29b8c0c24d06a0166b45297b173cf251786cb24a57e91218f23ecdf63c \
    https://raw.githubusercontent.com/apache/apisix/07446140f87b475330ab86f280b94eaf2aeda020/NOTICE /tmp/apisix/NOTICE

RUN <<'SH'
set -eux
packages='libxcrypt-4.4.33-7.amzn2023 libxml2-2.10.4-1.amzn2023.0.22 libxslt-1.1.43-1.amzn2023.0.3 libyaml-devel-0.2.5-5.amzn2023.0.2 openldap-devel-2.4.57-6.amzn2023.0.7 pcre-8.44-3.amzn2023.1.0.3 which-2.21-26.amzn2023.0.2'
dnf -y --releasever=2023.12.20261120 --setopt=install_weak_deps=0 install $packages
rpm -q $packages
dnf clean all
rm -rf /var/cache/dnf /var/cache/yum /var/log/dnf* /var/log/hawkey.log /var/lib/dnf/history*
rpm --import /tmp/apisix/KEYS
rpm -K /tmp/apisix/apisix.rpm | grep -q 'digests signatures OK'
rpm -i /tmp/apisix/apisix.rpm
rpm -q "apisix-$APISIX_VERSION"
install -d -m 0755 /usr/share/licenses/apisix
install -m 0644 /tmp/apisix/LICENSE /tmp/apisix/NOTICE /usr/share/licenses/apisix/
rm -rf /tmp/apisix /usr/local/openresty/bin/etcdctl
echo 'apisix:x:636:' >> /etc/group
echo 'apisix:x:636:636:apisix:/usr/local/apisix:/sbin/nologin' >> /etc/passwd
chown -R 636:0 /usr/local/apisix
chmod -R g=u /usr/local/apisix
ln -sf /dev/stdout /usr/local/apisix/logs/access.log
ln -sf /dev/stderr /usr/local/apisix/logs/error.log
/usr/local/openresty/bin/openresty -V 2>&1 | tee /tmp/openresty-V
# SCAN SCOPE names this OpenSSL; a runtime with another one fails here.
grep -q '^built with OpenSSL 3\.5\.9 ' /tmp/openresty-V
rm /tmp/openresty-V
test "$(/usr/bin/apisix version | tail -1)" = "$APISIX_VERSION"
SH

WORKDIR /usr/local/apisix
ENV PATH=$PATH:/usr/local/openresty/luajit/bin:/usr/local/openresty/nginx/sbin:/usr/local/openresty/bin
USER 636:636
EXPOSE 9080 9443
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["docker-start"]
STOPSIGNAL SIGQUIT
