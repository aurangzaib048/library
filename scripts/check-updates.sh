#!/usr/bin/env bash
# check-updates.sh - Check for upstream version updates across all apps
#
# Usage:
#   ./scripts/check-updates.sh                    # Check all apps
#   ./scripts/check-updates.sh --type docker      # Only docker apps
#   ./scripts/check-updates.sh --app redis,trivy  # Specific apps
#   ./scripts/check-updates.sh --update           # Auto-update config.yaml files
#   ./scripts/check-updates.sh --json             # JSON output for CI
#   ./scripts/check-updates.sh --dry-run --update # Preview updates
#   ./scripts/check-updates.sh --verify --update  # Only apply updates whose SBOM exists
#
# Exit codes: 0=all current, 1=updates available, 2=errors
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# =============================================================================
# Constants
# =============================================================================

MAX_PARALLEL=5

# Read-through mirror for Docker Hub lookups (default: mirror.gcr.io).
# Anonymous Docker Hub manifest pulls are rate limited (100/hour per IP), which
# a full check exhausts; the mirror is faster and not throttled. Digests are
# content-addressed, so whatever it returns is identical to Docker Hub, though
# its tag list can lag upstream by a few days.
# Set DOCKER_HUB_MIRROR="" to query Docker Hub directly.
DOCKER_HUB_MIRROR="${DOCKER_HUB_MIRROR-mirror.gcr.io}"

# =============================================================================
# Argument Parsing
# =============================================================================

FILTER_TYPE=""
FILTER_APPS=""
AUTO_UPDATE=false
JSON_OUTPUT=false
VERIFY=false

print_check_usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") [options]

Check for upstream version updates across all tracked apps.

Options:
  --type TYPE      Only check apps of this source type (docker, github_release, lockfile)
  --app APP[,APP]  Only check specific apps (comma-separated)
  --update         Auto-update config.yaml files with new versions
  --verify         Confirm the new version actually publishes an SBOM
                   (attestation / release asset / lockfile); failures are
                   reported as "unverified" and never applied by --update
  --json           Output results as JSON
  -n, --dry-run    Preview updates without writing changes
  -v, --verbose    Enable debug output
  -h, --help       Show this help message

Examples:
  $(basename "$0")                          # Check all apps
  $(basename "$0") --type docker            # Only docker apps
  $(basename "$0") --app redis,trivy        # Specific apps
  $(basename "$0") --update --dry-run       # Preview auto-updates
  $(basename "$0") --json | jq .summary     # JSON output for CI
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                print_check_usage
                exit 0
                ;;
            -n|--dry-run)
                export DRY_RUN="true"
                shift
                ;;
            -v|--verbose)
                export LOG_LEVEL="DEBUG"
                shift
                ;;
            --type)
                [[ $# -lt 2 ]] && die "--type requires an argument"
                FILTER_TYPE="$2"
                shift 2
                ;;
            --app)
                [[ $# -lt 2 ]] && die "--app requires an argument"
                FILTER_APPS="$2"
                shift 2
                ;;
            --update)
                AUTO_UPDATE=true
                shift
                ;;
            --json)
                JSON_OUTPUT=true
                shift
                ;;
            --verify)
                VERIFY=true
                shift
                ;;
            *)
                die "Unknown option: $1. Use --help for usage."
                ;;
        esac
    done
}

# =============================================================================
# Version Detection Functions
# =============================================================================

# Map a docker.io repository to the configured mirror (if any).
lookup_repo() {
    local registry="$1" image="$2"
    if [[ -n "$DOCKER_HUB_MIRROR" && "$registry" == "docker.io" ]]; then
        echo "${DOCKER_HUB_MIRROR}/${image}"
    else
        echo "${registry}/${image}"
    fi
}

# Clean a Docker annotation version to match the config's tag pattern.
# The annotation often has a distro suffix (e.g., "3.14.3-trixie") that the
# config doesn't track (e.g., "3.14.3"). This function derives the "shape"
# of the current version and extracts the matching portion.
clean_docker_version() {
    local annotation="$1"
    local current="$2"

    # If annotation matches current exactly, return as-is
    if [[ "$annotation" == "$current" ]]; then
        echo "$annotation"
        return
    fi

    # If current version contains a dash, it has an intentional suffix
    # (e.g., "25.0.2_10-jdk-noble", "26.2.0.119303-community")
    # Return the full annotation since we expect suffixed versions
    if [[ "$current" == *-* ]]; then
        echo "$annotation"
        return
    fi

    # Current has no dash — strip any dash-suffix from annotation
    # e.g., annotation "3.14.3-trixie" → "3.14.3"
    local stripped="${annotation%%-*}"

    # If the current version is a simple number like "2", match segment count
    local current_dots="${current//[^.]}"
    local stripped_dots="${stripped//[^.]}"

    if [[ ${#current_dots} -lt ${#stripped_dots} ]]; then
        # Current has fewer segments — extract matching number of segments
        local num_segments=$(( ${#current_dots} + 1 ))
        local result=""
        local i=0
        IFS='.' read -ra parts <<< "$stripped"
        for part in "${parts[@]}"; do
            if [[ $i -ge $num_segments ]]; then
                break
            fi
            if [[ -n "$result" ]]; then
                result="${result}.${part}"
            else
                result="$part"
            fi
            i=$(( i + 1 ))
        done
        echo "$result"
    else
        echo "$stripped"
    fi
}

# Get latest version from Docker Hub by reading the org.opencontainers.image.version
# annotation from the amd64 manifest entry in the image index.
get_latest_docker_version() {
    local app="$1"
    local registry image current platform
    registry=$(get_config "$app" ".source.registry" "docker.io")
    image=$(get_config "$app" ".source.image")
    platform="linux/amd64"
    current=$(yq -r '.version' "${APPS_DIR}/${app}/config.yaml")

    local repo
    repo=$(lookup_repo "$registry" "$image")
    local image_ref="${repo}:latest"
    log_debug "Checking Docker: $image_ref"

    # Get the manifest index for the latest tag
    local index
    index=$(crane manifest "$image_ref" 2>&1) || {
        # Some images (e.g. oraclelinux) publish no :latest tag; fall back to
        # tag listing. Any other failure (rate limit, network) is an error.
        if [[ "$index" == *MANIFEST_UNKNOWN* ]]; then
            log_debug "No :latest tag for ${repo}, falling back to tag listing"
            resolve_docker_tag "$repo" "$current" ""
        else
            log_warn "Failed to fetch manifest for $image_ref: $index"
            echo "ERROR"
        fi
        return
    }
    # Cache the index so --verify can reuse it instead of spending another
    # (rate-limited) Docker Hub pull when the new version is the :latest tag.
    if [[ -n "${INDEX_CACHE_DIR:-}" ]]; then
        printf '%s' "$index" > "${INDEX_CACHE_DIR}/${app}.json"
    fi

    # Check if this is a manifest index (multi-arch) or a single manifest
    local media_type
    media_type=$(echo "$index" | jq -r '.mediaType // .schemaVersion' 2>/dev/null)

    local annotation=""
    IFS='/' read -r plat_os plat_arch <<< "$platform"

    case "$media_type" in
        *index*|*list*)
            # Multi-arch manifest — find the annotation on the amd64 entry
            annotation=$(echo "$index" | jq -r --arg os "$plat_os" --arg arch "$plat_arch" '
                .manifests[] |
                select(.platform.os == $os and .platform.architecture == $arch) |
                select(.annotations["vnd.docker.reference.type"] == null) |
                .annotations["org.opencontainers.image.version"] // empty
            ' 2>/dev/null | head -1)
            ;;
        *)
            # Single manifest — check config for annotation
            annotation=$(echo "$index" | jq -r '
                .annotations["org.opencontainers.image.version"] // empty
            ' 2>/dev/null)
            ;;
    esac

    if [[ -z "$annotation" ]]; then
        # Fallback: try to get annotation from image config
        local config_json
        config_json=$(crane config "${image_ref}" 2>/dev/null) || true
        if [[ -n "$config_json" ]]; then
            annotation=$(echo "$config_json" | jq -r '
                .config.Labels["org.opencontainers.image.version"] // empty
            ' 2>/dev/null)
        fi
    fi

    local candidate=""
    if [[ -n "$annotation" ]]; then
        log_debug "Annotation for $app: $annotation (current: $current)"
        candidate=$(clean_docker_version "$annotation" "$current")
    fi

    resolve_docker_tag "$repo" "$current" "$candidate"
}

# Build an anchored regex describing the "shape" of a version tag: every run of
# digits becomes [0-9]+ and everything else is matched literally.
# e.g. "25.0.2_10-jdk-noble" -> ^[0-9]+\.[0-9]+\.[0-9]+_[0-9]+-jdk-noble$
version_shape_regex() {
    local version="$1"
    local escaped
    escaped=$(printf '%s' "$version" | sed -E 's/[][\\.^$*+?(){}|/]/\\&/g')
    printf '^%s$' "$(printf '%s' "$escaped" | sed -E 's/[0-9]+/[0-9]+/g')"
}

# Turn the annotation-derived candidate into a real, fully-qualified tag that
# has the same shape as the tracked version.
#
# The :latest annotation is often less specific than what we track
# ("26" for node, "1-trixie" for rust, "trixie" for debian), and some images
# have no :latest tag at all (oraclelinux). In those cases list the tags and
# pick the highest one with the same shape — constrained to the annotation's
# release line when the annotation is numeric.
resolve_docker_tag() {
    local repo="$1"
    local current="$2"
    local candidate="$3"

    local shape
    shape=$(version_shape_regex "$current")

    if [[ -n "$candidate" ]] && [[ "$candidate" =~ $shape ]]; then
        echo "$candidate"
        return
    fi

    # Suffixed versions (e.g. "25.0.2_10-jdk-noble") may legitimately change
    # shape upstream ("25.0.5.1_2-jdk-resolute"). Trust the annotation as long
    # as it is a real tag.
    if [[ -n "$candidate" && "$current" == *-* && "$candidate" == *-* ]] \
        && crane digest "${repo}:${candidate}" >/dev/null 2>&1; then
        echo "$candidate"
        return
    fi

    local tags
    tags=$(crane ls "$repo" 2>/dev/null) || {
        log_warn "Failed to list tags for $repo"
        echo "ERROR"
        return
    }

    local matching
    matching=$(grep -E "$shape" <<< "$tags" || true)

    # Constrain to the release line the annotation points at (e.g. "26" -> "26.x.y")
    if [[ -n "$candidate" && "$candidate" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
        local line_prefix="${candidate}."
        local in_line
        in_line=$(awk -v p="$line_prefix" 'index($0, p) == 1' <<< "$matching")
        [[ -n "$in_line" ]] && matching="$in_line"
    fi

    local best
    best=$(sort -V <<< "$matching" | tail -1)

    if [[ -z "$best" ]]; then
        log_warn "No tag matching shape of '$current' found for $repo (annotation: '${candidate:-none}')"
        echo "ERROR"
        return
    fi

    log_debug "Resolved $repo: annotation '${candidate:-none}' -> tag '$best'"
    echo "$best"
}

# Get latest version from GitHub releases.
# Used for both github_release and lockfile source types.
get_latest_github_version() {
    local app="$1"
    local repo tag_prefix
    repo=$(get_config "$app" ".source.repo")
    tag_prefix=$(get_config "$app" ".source.tag_prefix" "")

    log_debug "Checking GitHub: $repo"

    local tag_name=""

    if command -v gh &>/dev/null; then
        tag_name=$(gh release view --repo "$repo" --json tagName -q '.tagName' 2>&1) || {
            log_warn "gh release view failed for $repo: $tag_name"
            tag_name=""
        }
    fi

    # Fallback to curl if gh failed or isn't installed
    if [[ -z "$tag_name" ]]; then
        local api_url="https://api.github.com/repos/${repo}/releases/latest"
        local response
        response=$(curl -fsSL -H "Accept: application/vnd.github+json" \
            ${GH_TOKEN:+-H "Authorization: Bearer ${GH_TOKEN}"} \
            "$api_url" 2>&1) || {
            log_warn "Failed to fetch latest release for $repo: $response"
            echo "ERROR"
            return
        }
        tag_name=$(echo "$response" | jq -r '.tag_name // empty')
    fi

    if [[ -z "$tag_name" ]]; then
        log_warn "No release found for $repo"
        echo "ERROR"
        return
    fi

    # Strip tag prefix (e.g., "v1.2.3" → "1.2.3")
    if [[ -n "$tag_prefix" && "$tag_name" == "${tag_prefix}"* ]]; then
        tag_name="${tag_name#"$tag_prefix"}"
    fi

    # Strip tag suffix
    local tag_suffix
    tag_suffix=$(get_config "$app" ".source.tag_suffix" "")
    if [[ -n "$tag_suffix" && "$tag_name" == *"${tag_suffix}" ]]; then
        tag_name="${tag_name%"$tag_suffix"}"
    fi

    echo "$tag_name"
}

# =============================================================================
# SBOM Availability Verification
# =============================================================================

# Check that a docker tag carries an attestation manifest for linux/amd64.
# Docker Official Images attach SBOM + provenance attestations together; the
# full SBOM layer is extracted (and validated) later by fetch-sbom.sh.
# Returns 0 = SBOM available, 1 = not available, 2 = could not check.
verify_docker_sbom() {
    local app="$1" version="$2"
    local registry image
    registry=$(get_config "$app" ".source.registry" "docker.io")
    image=$(get_config "$app" ".source.image")
    local base_ref
    base_ref=$(lookup_repo "$registry" "$image")

    local index="" cached="${INDEX_CACHE_DIR:-}/${app}.json"
    if [[ -n "${INDEX_CACHE_DIR:-}" && -s "$cached" ]]; then
        # HEAD requests do not count towards the Docker Hub pull rate limit
        local tag_digest cached_digest
        tag_digest=$(crane digest "${base_ref}:${version}" 2>/dev/null || true)
        cached_digest="sha256:$(sha256sum < "$cached" | cut -d' ' -f1)"
        [[ "$tag_digest" == "$cached_digest" ]] && index=$(<"$cached")
    fi
    if [[ -z "$index" ]]; then
        index=$(crane manifest "${base_ref}:${version}" 2>&1) || {
            [[ "$index" == *MANIFEST_UNKNOWN* ]] && return 1
            log_warn "Could not verify $app $version: $index"
            return 2
        }
    fi

    local image_digest
    image_digest=$(jq -r '
        .manifests[]? |
        select(.platform.os == "linux" and .platform.architecture == "amd64") |
        select(.annotations["vnd.docker.reference.type"] == null) |
        .digest
    ' <<< "$index" | head -1)
    [[ -n "$image_digest" ]] || return 1

    local att_digest
    att_digest=$(jq -r --arg ref "$image_digest" '
        .manifests[]? |
        select(
            .annotations["vnd.docker.reference.type"] == "attestation-manifest" and
            .annotations["vnd.docker.reference.digest"] == $ref
        ) | .digest
    ' <<< "$index" | head -1)
    [[ -n "$att_digest" ]]
}

# Check that the GitHub release for this version has the configured SBOM asset.
verify_github_release_sbom() {
    local app="$1" version="$2"
    local repo asset tag
    repo=$(get_config "$app" ".source.repo")
    asset=$(get_config "$app" ".source.asset")
    tag="$(get_config "$app" ".source.tag_prefix" "")${version}$(get_config "$app" ".source.tag_suffix" "")"
    asset="${asset//\$\{version\}/$version}"

    gh release view "$tag" --repo "$repo" --json assets -q '.assets[].name' 2>/dev/null \
        | grep -Fxq "$asset"
}

# Check that the configured lockfile exists at the release tag.
verify_lockfile_sbom() {
    local app="$1" version="$2"
    local repo lockfile tag
    repo=$(get_config "$app" ".source.repo")
    lockfile=$(get_config "$app" ".source.lockfile")
    tag="$(get_config "$app" ".source.tag_prefix" "")${version}$(get_config "$app" ".source.tag_suffix" "")"

    gh api "repos/${repo}/contents/${lockfile}?ref=${tag}" --silent 2>/dev/null
}

verify_sbom_available() {
    local app="$1" source_type="$2" version="$3"
    case "$source_type" in
        docker)         verify_docker_sbom "$app" "$version" ;;
        github_release) verify_github_release_sbom "$app" "$version" ;;
        lockfile)       verify_lockfile_sbom "$app" "$version" ;;
        *)              return 1 ;;
    esac
}

# =============================================================================
# Version Comparison
# =============================================================================

# Compare two versions. Returns 0 if latest is newer than current.
version_is_newer() {
    local current="$1"
    local latest="$2"

    if [[ "$current" == "$latest" ]]; then
        return 1
    fi

    # Use sort -V (version sort) to determine order
    local sorted_first
    sorted_first=$(printf '%s\n%s\n' "$current" "$latest" | sort -V | head -1)

    # If current sorts first, then latest is newer
    [[ "$sorted_first" == "$current" ]]
}

# =============================================================================
# Per-App Check
# =============================================================================

check_single_app() {
    local app="$1"
    local result_dir="$2"

    local source_type current latest status
    source_type=$(get_source_type "$app")
    current=$(yq -r '.version' "${APPS_DIR}/${app}/config.yaml")

    case "$source_type" in
        docker)
            latest=$(get_latest_docker_version "$app")
            ;;
        github_release|lockfile)
            latest=$(get_latest_github_version "$app")
            ;;
        chainguard)
            # Rolling latest tag — nothing to compare
            echo "skipped|${app}|${current}||${source_type}" > "${result_dir}/${app}"
            return
            ;;
        *)
            log_warn "Unknown source type for $app: $source_type"
            echo "error|${app}|${current}||${source_type}" > "${result_dir}/${app}"
            return
            ;;
    esac

    if [[ "$latest" == "ERROR" ]]; then
        echo "error|${app}|${current}||${source_type}" > "${result_dir}/${app}"
        return
    fi

    if version_is_newer "$current" "$latest"; then
        status="update"
        if [[ "$VERIFY" == true ]]; then
            local rc=0
            verify_sbom_available "$app" "$source_type" "$latest" || rc=$?
            if [[ $rc -eq 1 ]]; then
                log_warn "$app $latest: no SBOM found at the configured source"
                status="unverified"
            elif [[ $rc -ne 0 ]]; then
                status="error"
            fi
        fi
    else
        status="current"
    fi

    echo "${status}|${app}|${current}|${latest}|${source_type}" > "${result_dir}/${app}"
}

# =============================================================================
# Output Functions
# =============================================================================

print_table() {
    local result_dir="$1"

    local up_to_date=0 updates=0 unverified=0 skipped=0 errors=0

    for result_file in "${result_dir}"/*; do
        [[ -f "$result_file" ]] || continue
        local line
        line=$(<"$result_file")

        IFS='|' read -r status app current latest source_type <<< "$line"

        case "$status" in
            unverified)
                printf "  %-30s %-24s -> %-16s (unverified: no SBOM found)\n" "$app" "$current" "$latest"
                unverified=$(( unverified + 1 ))
                ;;
            current)
                printf "  %-30s %-24s (up to date)\n" "$app" "$current"
                up_to_date=$(( up_to_date + 1 ))
                ;;
            update)
                printf "  %-30s %-24s -> %-16s (update available)\n" "$app" "$current" "$latest"
                updates=$(( updates + 1 ))
                ;;
            skipped)
                printf "  %-30s %-24s              (skipped: %s)\n" "$app" "$current" "$source_type"
                skipped=$(( skipped + 1 ))
                ;;
            error)
                printf "  %-30s %-24s              (error)\n" "$app" "$current"
                errors=$(( errors + 1 ))
                ;;
        esac
    done

    echo ""
    echo "Summary: ${up_to_date} up to date, ${updates} updates available, ${unverified} unverified," \
        "${skipped} skipped, ${errors} errors"
}

print_json() {
    local result_dir="$1"

    local results=()
    local up_to_date=0 updates=0 unverified=0 skipped=0 errors=0

    for result_file in "${result_dir}"/*; do
        [[ -f "$result_file" ]] || continue
        local line
        line=$(<"$result_file")

        IFS='|' read -r status app current latest source_type <<< "$line"

        results+=("$(jq -n \
            --arg status "$status" \
            --arg app "$app" \
            --arg current "$current" \
            --arg latest "$latest" \
            --arg source_type "$source_type" \
            '{status: $status, app: $app, current_version: $current, latest_version: $latest, source_type: $source_type}'
        )")

        case "$status" in
            current) up_to_date=$(( up_to_date + 1 )) ;;
            update)  updates=$(( updates + 1 )) ;;
            unverified) unverified=$(( unverified + 1 )) ;;
            skipped) skipped=$(( skipped + 1 )) ;;
            error)   errors=$(( errors + 1 )) ;;
        esac
    done

    # Build JSON array from results
    local json_array="["
    local first=true
    for item in "${results[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            json_array+=","
        fi
        json_array+="$item"
    done
    json_array+="]"

    jq -n \
        --argjson apps "$json_array" \
        --argjson up_to_date "$up_to_date" \
        --argjson updates "$updates" \
        --argjson unverified "$unverified" \
        --argjson skipped "$skipped" \
        --argjson errors "$errors" \
        '{
            apps: $apps,
            summary: {
                up_to_date: $up_to_date,
                updates_available: $updates,
                unverified: $unverified,
                skipped: $skipped,
                errors: $errors
            }
        }'
}

# =============================================================================
# Auto-Update
# =============================================================================

apply_updates() {
    local result_dir="$1"
    local applied=0

    for result_file in "${result_dir}"/*; do
        [[ -f "$result_file" ]] || continue
        local line
        line=$(<"$result_file")

        IFS='|' read -r status app _ latest _ <<< "$line"

        if [[ "$status" != "update" ]]; then
            continue
        fi

        local config_file="${APPS_DIR}/${app}/config.yaml"

        if is_dry_run; then
            log_info "[DRY RUN] Would update $app to $latest in $config_file"
        else
            log_info "Updating $app to $latest"
            # Edit only the version line; yq -i would reformat the file and
            # drop its blank lines and comments' spacing.
            sed -i -E "s|^version:.*$|version: \"${latest}\"|" "$config_file"
        fi
        applied=$(( applied + 1 ))
    done

    if [[ $applied -eq 0 ]]; then
        log_info "No updates to apply."
    else
        local verb="Applied"
        is_dry_run && verb="Would apply"
        log_info "${verb} ${applied} update(s)."
    fi
}

# =============================================================================
# Main
# =============================================================================

main() {
    parse_args "$@"

    require_cmd "yq" "Install with: brew install yq"
    require_cmd "jq" "Install with: brew install jq"

    # Check for source-type-specific tools
    if [[ -z "$FILTER_TYPE" || "$FILTER_TYPE" == "docker" ]]; then
        require_cmd "crane" "Install with: go install github.com/google/go-containerregistry/cmd/crane@latest"
    fi

    # Build app list
    local apps=()

    if [[ -n "$FILTER_APPS" ]]; then
        IFS=',' read -ra apps <<< "$FILTER_APPS"
        # Validate each app exists
        for app in "${apps[@]}"; do
            validate_app_dir "$app"
        done
    else
        for config in "${APPS_DIR}"/*/config.yaml; do
            local app_dir
            app_dir="$(dirname "$config")"
            local app
            app="$(basename "$app_dir")"

            # Skip template
            [[ "$app" == ".template" ]] && continue

            # Apply type filter
            if [[ -n "$FILTER_TYPE" ]]; then
                local src_type
                src_type=$(yq -r '.source.type' "$config")
                [[ "$src_type" != "$FILTER_TYPE" ]] && continue
            fi

            apps+=("$app")
        done
    fi

    if [[ ${#apps[@]} -eq 0 ]]; then
        die "No apps found matching filters."
    fi

    local result_dir
    result_dir=$(create_temp_dir "check-updates")
    INDEX_CACHE_DIR=$(create_temp_dir "check-updates-index")
    export INDEX_CACHE_DIR

    if [[ "$JSON_OUTPUT" != true ]]; then
        echo "Checking ${#apps[@]} apps for updates..." >&2
        echo "" >&2
    fi

    # Run checks in parallel, capped at MAX_PARALLEL
    local running=0
    local pids=()

    for app in "${apps[@]}"; do
        (
            # Clear inherited EXIT trap so child doesn't remove parent's temp dir
            trap - EXIT
            _SBOM_TEMP_DIRS=()
            check_single_app "$app" "$result_dir"
        ) &
        pids+=($!)
        running=$(( running + 1 ))

        if [[ $running -ge $MAX_PARALLEL ]]; then
            # Wait for any one job to finish
            wait -n 2>/dev/null || true
            running=$(( running - 1 ))
        fi
    done

    # Wait for all remaining jobs
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    # Output results
    if [[ "$JSON_OUTPUT" == true ]]; then
        print_json "$result_dir"
    else
        print_table "$result_dir" >&2
    fi

    # Apply updates if requested
    if [[ "$AUTO_UPDATE" == true ]]; then
        apply_updates "$result_dir"
    fi

    # Set exit code based on results
    local has_updates=false has_errors=false
    for result_file in "${result_dir}"/*; do
        [[ -f "$result_file" ]] || continue
        local status
        status=$(cut -d'|' -f1 < "$result_file")
        [[ "$status" == "update" || "$status" == "unverified" ]] && has_updates=true
        [[ "$status" == "error" ]] && has_errors=true
    done

    if [[ "$has_errors" == true ]]; then
        exit 2
    elif [[ "$has_updates" == true ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
