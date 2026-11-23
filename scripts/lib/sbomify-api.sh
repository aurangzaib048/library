#!/usr/bin/env bash
# sbomify-api.sh - Shared utilities for sbomify API calls
#
# Usage: source this file in other scripts (after common.sh)
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/sbomify-api.sh"
#
# Authentication is OIDC trusted publishing only: on GitHub Actions (with
# `permissions: id-token: write`) a GitHub-issued JWT is exchanged for a
# short-lived sbomify token scoped to one component. There is no long-lived
# API token. The component must have an OIDC binding for this repository in
# sbomify (Component → Settings → Trusted Publishing).
#
# Requires: curl, jq

set -euo pipefail

SBOMIFY_API="${SBOMIFY_API_URL:-https://app.sbomify.com}"
SBOMIFY_OIDC_AUDIENCE="${SBOMIFY_OIDC_AUDIENCE:-sbomify.com}"

# True when the GitHub Actions OIDC token endpoint is available
sbomify_oidc_available() {
    [[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" && -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]]
}

# Mint a short-lived sbomify token for a component via OIDC.
# Usage: token=$(sbomify_token <component_id>)
sbomify_token() {
    local component_id="$1"

    sbomify_oidc_available || die "No OIDC token available. sbomify API calls only run on GitHub Actions" \
        "with 'permissions: id-token: write' (the component needs an OIDC binding for this repository)."

    local jwt
    jwt=$(curl -fsSL -G \
        -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
        --data-urlencode "audience=${SBOMIFY_OIDC_AUDIENCE}" \
        "${ACTIONS_ID_TOKEN_REQUEST_URL}" | jq -r '.value // empty')
    [[ -n "$jwt" ]] || die "GitHub did not return an OIDC token"

    local response http_code body
    response=$(curl -sS -X POST \
        -H "Authorization: Bearer ${jwt}" \
        -H "Content-Type: application/json" \
        -d "$(jq -n --arg c "$component_id" '{component_id: $c}')" \
        -w '\n%{http_code}' \
        "${SBOMIFY_API}/api/v1/auth/oidc/github/exchange")
    http_code="${response##*$'\n'}"
    body="${response%$'\n'*}"

    case "$http_code" in
        200) ;;
        403) die "sbomify has no OIDC binding for component ${component_id} and this repository" \
                 "(Component → Settings → Trusted Publishing)" ;;
        *)   die "sbomify OIDC exchange failed for component ${component_id} (HTTP ${http_code})" ;;
    esac

    local token
    token=$(jq -r '.access_token // empty' <<< "$body")
    [[ -n "$token" ]] || die "sbomify OIDC exchange returned no access_token"
    echo "$token"
}

# Check if a component already has an SBOM with this digest as version
# Usage: sbomify_digest_exists <component_id> <digest>
# Returns: 0 if exists, 1 if not, 2 if sbomify could not be queried
# (auth or network failure must not be mistaken for "new digest").
sbomify_digest_exists() {
    local component_id="$1" digest="$2"

    local token sboms
    token=$(sbomify_token "$component_id") || return 2
    sboms=$(curl -fsSL -H "Authorization: Bearer ${token}" \
        "${SBOMIFY_API}/api/v1/components/${component_id}/sboms") || {
        log_error "Could not list SBOMs for component ${component_id}"
        return 2
    }
    jq -e --arg d "$digest" 'any(.items[]?; .sbom.version == $d)' <<< "$sboms" > /dev/null 2>&1
}

# Remove old SBOMs for a component (keep only current digest)
# Usage: sbomify_cleanup_old_sboms <component_id> <current_digest>
sbomify_cleanup_old_sboms() {
    local component_id="$1" current_digest="$2"

    local token sboms old_ids
    token=$(sbomify_token "$component_id") || return 1
    sboms=$(curl -fsSL -H "Authorization: Bearer ${token}" \
        "${SBOMIFY_API}/api/v1/components/${component_id}/sboms")
    old_ids=$(echo "$sboms" | jq -r --arg d "$current_digest" \
        '.items[] | select(.sbom.version != $d) | .sbom.id')

    for sbom_id in $old_ids; do
        log_info "Removing old SBOM ${sbom_id} from component ${component_id}"
        curl -fsSL -X DELETE -H "Authorization: Bearer ${token}" \
            "${SBOMIFY_API}/api/v1/sboms/sbom/${sbom_id}" || true
    done
}

# Remove versioned releases from a product (keep only "latest").
# The OIDC token is minted for the component, so this only succeeds if
# sbomify lets that component's token manage the product's releases; a
# refusal is logged rather than failing the run.
# Usage: sbomify_cleanup_versioned_releases <product_id> <component_id>
sbomify_cleanup_versioned_releases() {
    local product_id="$1" component_id="$2"

    local token releases release_ids
    token=$(sbomify_token "$component_id") || return 1
    releases=$(curl -fsSL -H "Authorization: Bearer ${token}" \
        "${SBOMIFY_API}/api/v1/releases?product_id=${product_id}") || {
        log_warn "Could not list releases for product ${product_id} with component ${component_id}'s token; skipping"
        return 0
    }
    release_ids=$(echo "$releases" | jq -r \
        '.items[] | select(.is_latest != true) | .id')

    for release_id in $release_ids; do
        log_info "Removing versioned release ${release_id} from product ${product_id}"
        curl -fsSL -X DELETE -H "Authorization: Bearer ${token}" \
            "${SBOMIFY_API}/api/v1/releases/${release_id}" || true
    done
}
