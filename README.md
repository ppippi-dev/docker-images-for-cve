# docker-images-for-cve

Recipes that rebuild public open-source container images so that a
vulnerability scan of the result reports no finding with a CVSS v3 base score
above zero. Each recipe is one `<name>/Dockerfile`. The workflow
`.github/workflows/build-images.yml` builds it from an empty context, runs the
recipe's checks, scans it with Trivy and publishes it to
`ghcr.io/ppippi-dev/<name>`. Only the newest version of each image is kept.

## Rules

- Inputs are public upstream artifacts only, each pinned: images by digest,
  downloads by SHA-256, OS packages and Python wheels by exact version.
- Open source is changed at Dockerfile level only. Allowed: swap the base
  image, upgrade vulnerable OS packages, replace or remove a vulnerable helper
  binary, reinstall unmodified upstream packages on a clean base, rebuild
  unmodified upstream source with a fixed toolchain. Not allowed: patching
  upstream code files.
- Nothing of any private project or organization in files, commit messages or
  branch names: no host, registry, account, cluster, namespace, environment,
  team, internal system or process names, no configuration values of a
  deployment, no credentials, local paths, logs or scan reports. Write in
  English, in the plain style of the existing files, about the recipes and
  their upstream projects only.
- The README and recipe headers state the present state only; history belongs
  in commit messages.
- Track this README, the recipes (`<name>/Dockerfile`) and the reviewed
  workflows only. Keep test files, reports and exported images outside the
  repository; functional checks live in `build-images.yml`.
- No ignore files, severity filters or `--ignore-unfixed`. Every finding of a
  fresh scan is kept; any CVSS v3 score above zero, or a missing or invalid v3
  assessment, blocks publication.
- Upstream license notices are kept. Each recipe header lists the licenses of
  what the image contains.
- Each package keeps one version, the newest published `v<version>`. Every
  main run of `build-images.yml` for a recipe (push or manual) deletes all
  other versions of its package once `v<version>` pulls anonymously (see step
  9).
- Merging to main publishes immediately and publicly. Judge the license
  conditions of the image contents before merging.
- Before every push, read the full diff, the commit message and the branch
  name against the rules above.

## Recipes

| Name | Upstream | What the recipe changes |
|---|---|---|
| `vllm` | vLLM 0.34.0 | Unmodified PyPI wheels, hash-locked, on Amazon Linux 2023 minimal; setuptools raised above vLLM's cap. |
| `postgres` | `postgres:16.16-alpine3.24` | Upgrades three Alpine packages and replaces gosu with Alpine's su-exec; PostgreSQL files unchanged. |
| `nginx-ingress` | `public.ecr.aws/nginx/nginx-ingress:5.8.1-alpine` | Upgrades Alpine libexpat and libxml2; controller, nginx and modules unchanged. |

A recipe whose fresh scan fails is not republished and nothing is deleted; its
published version stays as it was until the recipe is updated (see Upkeep).

## Add or update a recipe

1. Use a folder named after the open-source project in lowercase kebab-case
   (`<name>/Dockerfile`). The folder name becomes the package name.
2. Start the Dockerfile with a header like the existing recipes: LICENSE NOTES,
   PUBLIC REPOSITORY RULES, SCAN SCOPE (what the scanner cannot see), CHANGES
   against the upstream image, build and scan commands, baseline findings and
   UPKEEP steps.
3. Set `org.opencontainers.image.version` to `<upstream>-<variant>-rN`, for
   example `16.16-alpine3.24-r2`. Start at `r1` for a new upstream version and
   raise `rN` to publish a rebuild of the same one. Never go back to an earlier
   label: its version was deleted, so it would be published again with other
   contents.
4. Build from an empty context, as CI does:

   ```
   docker build --platform linux/amd64 -t <name>-cve:<version> - < <name>/Dockerfile
   ```

5. Scan with every severity and no ignores:

   ```
   trivy image --scanners vuln --pkg-types os,library --ignorefile '' \
     --ignore-unfixed=false --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
     --exit-code 1 <name>-cve:<version>
   ```

6. Add the recipe's functional checks to `build-images.yml` as one step
   conditioned on `matrix.oss == '<name>'`, defined with an anchor in the
   `verify-pr` job (`- &<name>_runtime`) and referenced in the main job before
   `*scanner` (`- *<name>_runtime`). Use only values generated during the run.
7. Open a pull request. CI builds, checks and scans the changed recipes (all
   recipes when the workflow changes) and publishes nothing. Change the
   workflow through a pull request too: a push to main that changes only the
   workflow runs no recipe job.
8. Merging to main publishes: the push builds, checks and scans the recipes
   whose Dockerfile changed, then pushes `sha-<commit>` and `v<version>`. A
   new package may be public as soon as it is pushed, so merging is
   publication: judge the license conditions of everything the image contains
   before merging. A published `v<version>` is never re-pointed; if it exists,
   nothing is pushed.
9. Once `v<version>` is published (pushed by this run, or already present)
   and pulls anonymously, the job deletes every other version of that package:
   older `v<version>` and `sha-<commit>` tags and untagged manifests. If
   `v<version>` is an image index, the package listing does not show exactly
   one version with its digest, or another version was created after it, it
   deletes nothing and fails. A version GitHub refuses to delete (a public
   version with more than 5,000 downloads) is listed in the step summary and
   the job fails.

A push run that was replaced by a newer one, or that refused to publish because
main had advanced, leaves its recipe unpublished: run the workflow manually on
main with that recipe name (or `all`). A manual run on main also builds, checks
and scans the recipe, publishes `v<version>` if it is absent and deletes every
other version of the package.

## Use an image

Only the newest version of each image is kept. Every main run of
`build-images.yml` for a recipe deletes all older versions of its package;
their tags and digests then no longer pull. Pin the digest, not only the tag,
and move to the new digest when a new version appears; to keep an older one,
copy it into your own registry.

```
docker pull ghcr.io/ppippi-dev/<name>:v<version>
docker buildx imagetools inspect ghcr.io/ppippi-dev/<name>:v<version>
# then reference ghcr.io/ppippi-dev/<name>@sha256:<digest>
```

To recheck the published tag without rebuilding, run the manual workflow
`Verify published image with Podman` (`verify-published.yml`) with the package
name, tag and expected digest. `verify-published.yml` only reads; it deletes
nothing.

A zero result is a statement about one scanner and one database on one day.
Scan the exact digest with your own scanner and policy before use, and read the
recipe header for what the scan does not cover.

## Upkeep

Update a recipe, following its UPKEEP steps, when:

- upstream publishes a new release,
- the base image publishes a new date release, or
- a fresh scan reports a new finding.

To retire a recipe, remove its folder and README row in a pull request. No
workflow touches its package afterwards; delete the package in its settings.

Nothing rescans published images on a schedule. To rescan every recipe with a
fresh database, run the workflow manually on a branch other than main with
`all`: it builds, checks and scans without publishing.
