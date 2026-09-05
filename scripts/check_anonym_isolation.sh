#!/usr/bin/env bash
# Check whether the separate-user deployment actually isolates the agent.
#
# The documentation claims that running anonym-mcp as its own user is the only
# real boundary: the agent's user cannot read the sensitive files, the server's
# user can. That claim was never verified end to end, because creating an
# account needs a sudo password. This script verifies it on a machine where the
# account exists, so the claim stops being an assumption.
#
# Usage:
#   scripts/check_anonym_isolation.sh <server-user> <sensitive-file>
#
# Run it as the agent's user, not as root: the whole point is to observe what
# the agent can reach.
set -uo pipefail

SERVER_USER="${1:-}"
TARGET="${2:-}"

if [[ -z "$SERVER_USER" || -z "$TARGET" ]]; then
    echo "usage: $0 <server-user> <sensitive-file>" >&2
    exit 64
fi

if [[ "$(id -u)" == "0" ]]; then
    echo "error: run this as the agent's user, not root; root reads everything" >&2
    exit 64
fi

failures=0
skipped=0

note() { printf '%s\n' "$*"; }
pass() { printf 'ok    %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failures=$((failures + 1)); }

note "agent user: $(id -un)"
note "server user: $SERVER_USER"
note "target: $TARGET"
note ""

# 1. The agent must NOT be able to read the file. This is the property that
#    makes the deployment a boundary rather than a convention.
if cat "$TARGET" >/dev/null 2>&1; then
    fail "the agent's user can read $TARGET, so masking can be bypassed with cat"
else
    pass "the agent's user cannot read the file directly"
fi

# 2. The server's user MUST be able to read it, or the setup is merely broken
#    rather than secure. Distinguish "it cannot read" from "we could not ask":
#    a sudo password prompt is not evidence of anything, and reporting it as a
#    failure would tell a correctly configured operator their setup is broken.
sudo_probe="$(sudo -n -u "$SERVER_USER" cat "$TARGET" 2>&1 >/dev/null)"
sudo_status=$?
if [[ $sudo_status -eq 0 ]]; then
    pass "the server's user can read the file"
elif [[ "$sudo_probe" == *"password is required"* || "$sudo_probe" == *"askpass"* ]]; then
    note "skip  cannot test the server's user without a sudo password."
    note "      Re-run with sudo credentials cached (\`sudo -v\` first), or check by hand:"
    note "        sudo -u $SERVER_USER cat $TARGET"
    skipped=$((skipped + 1))
else
    fail "the server's user cannot read $TARGET either; the setup is broken, not secure"
fi

# 3. The mapping table must not be readable by the agent: it holds exactly the
#    values the whole exercise keeps away from the model.
mappings="${ANONYM_MAPPINGS:-$(eval echo ~"$SERVER_USER")/.anonym-mcp/mappings.json}"
if [[ -e "$mappings" ]]; then
    if cat "$mappings" >/dev/null 2>&1; then
        fail "the agent's user can read the mapping table at $mappings"
    else
        pass "the mapping table is not readable by the agent"
    fi
else
    note "note  no mapping table at $mappings yet; run the server once, then re-check"
fi

note ""
if [[ $failures -eq 0 && $skipped -eq 0 ]]; then
    note "Isolation holds: the agent reaches this data only through anonym-mcp."
elif [[ $failures -eq 0 ]]; then
    note "No failures, but $skipped check(s) could not run, so isolation is unproven."
    note "Resolve the skipped check before relying on this as a boundary."
else
    note "$failures check(s) failed. Until they pass, anonym-mcp is a convenience,"
    note "not a boundary: an agent that runs 'cat' still sees the real values."
fi
# A skipped check is not a pass: exit non-zero so a CI job or a cautious
# operator does not read silence as confirmation.
if [[ $failures -gt 0 ]]; then
    exit 1
elif [[ $skipped -gt 0 ]]; then
    exit 2
fi
exit 0
