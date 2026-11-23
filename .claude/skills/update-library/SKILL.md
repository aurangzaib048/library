---
name: update-library
description: Audit every app in the sbomify SBOM library, bump each one to the latest upstream version that actually publishes an SBOM, and open a PR. Use for "update the library", "bump versions", "check for new releases", or a scheduled autopilot maintenance run.
---

# Keep the SBOM library current

The library tracks one version per app in `apps/<app>/config.yaml`. Each version only needs to be processed once.
After an SBOM is uploaded to sbomify it stays there, so keeping the library current just means bumping `version` to
the newest upstream release that has an SBOM, then running the pipeline for the apps you bumped.

## 1. Prerequisites

- `bash` 4+, `git`, `jq`, `yq` (mikefarah v4), `crane`, `gh` (authenticated), `shellcheck`
- `cosign` only if you run the `nginx` (Chainguard) pipeline
- `export GH_TOKEN=$(gh auth token)` so GitHub lookups aren't rate limited

**Docker Hub rate limit:** anonymous manifest pulls are capped at 100 per hour per IP. A full check needs about 2
pulls per docker app (there are around 50), so it can run out of quota partway through. When that happens the
affected apps show up as `(error)`, never as "up to date". To avoid it, either:

- log in to Docker Hub first (`crane auth login index.docker.io -u <user> -p <token>`), or
- set `DOCKER_HUB_MIRROR=mirror.gcr.io`. The mirror is read-only and content-addressed, but its tag list can be a few
  days behind. If you use it, run the check again directly against Docker Hub once the quota resets, and take any
  newer patch versions it finds.

## 2. Audit

```bash
./scripts/check-updates.sh --verify            # human-readable table
./scripts/check-updates.sh --verify --json     # machine-readable
```

Statuses:

| Status | Meaning | Action |
|---|---|---|
| `update available` | Newer version found and its SBOM is confirmed to exist | Apply it |
| `unverified` | Newer version found but no SBOM (missing attestation, release asset or lockfile) | Don't bump. Note it in the PR. If it stays unverified across runs, check whether upstream changed how it publishes |
| `error` | Lookup failed (rate limit, network, unknown tag shape) | Re-run that app (`--app <name>`). Never treat an error as up to date |
| `skipped` | `nginx` (Chainguard rolling `latest`) | Nothing to do. The `tea-sync` workflow picks up new digests |

Exit codes: `0` all current, `1` updates or unverified, `2` errors.

## 3. Apply

```bash
./scripts/check-updates.sh --verify --update
```

This rewrites only the `version:` line of each config and leaves formatting and comments alone. It never applies
`unverified` or `error` results.

## 4. Review the bumps before committing

`git diff apps/` and look closely at:

- **Major version jumps** (e.g. postgres 18→19, debian 12→13, mongo 8→9, dependency-track 4→5). These are expected.
  The library follows upstream `latest`. Check that `format` and the `source` settings still apply: the release asset
  name, the lockfile path, and the `tag_prefix`.
- **Shape changes on suffixed tags**, e.g. `eclipse-temurin` going from `…-jdk-noble` to `…-jdk-resolute` or
  `sonarqube` `…-community`. These are accepted when the new tag exists. Make sure the suffix still means the same
  edition.
- **Non-LTS lines:** the checker follows what upstream tags as `latest`. Ubuntu `latest` is the LTS release and
  Temurin `latest` is the LTS JDK, so interim releases aren't picked unless upstream moves `latest` to them.
- **Lockfile sources with `post_clone_commands`** (keycloak). A major bump can break the build. Run the fetch
  (step 5) for them.
- Any comment in a config that names a version or codename. Update it so it matches.

## 5. Validate end to end (spot checks)

`fetch-sbom.sh` downloads the real SBOM without uploading it:

```bash
mkdir -p /tmp/sbom-check && cd /tmp/sbom-check
/path/to/library/scripts/fetch-sbom.sh <app>   # writes sbom.json
jq '.bomFormat // .spdxVersion' sbom.json
```

At minimum, run it for every `github_release` and `lockfile` app you bumped, plus one or two docker apps. Docker
fetches go straight to Docker Hub and count against the rate limit.

## 6. Lint

```bash
shellcheck -x -S warning scripts/*.sh scripts/*/*.sh
yamllint .
```

## 7. Deliver

- Branch from `master`. Commit with SSH signing. Name the branch after the change, e.g. `chore/bump-versions-YYYY-MM-DD`.
- Use one PR per run. The PR body lists each `app: old → new`, calls out major bumps, and lists every
  `unverified` or `error` app with the reason.
- The repo is public, so don't put internal tracker IDs, customer data or other confidential details in commits or
  the PR.
- After the PR merges, run `./scripts/run.sh --app <comma-separated bumped apps>` (needs `SBOMIFY_TOKEN`) to upload.
  The per-app workflows are dispatch-only.

## Maintaining this skill

If you change `scripts/check-updates.sh` (new flags, statuses, source types) or add a new source type, update this
file in the same PR. The autopilot follows it as written.
