#!/usr/bin/env bash
# Build and install the anonymizing MCP server.
#
# Two macOS-specific traps this script exists to avoid:
#   * Writing over a binary *while a copy of it is running* corrupts the running
#     image's code signature, and the next execution dies with SIGKILL
#     ("Killed: 9"). An MCP server is usually running, launched by the agent, so
#     this is the normal case rather than an edge case. Reproduced: overwriting
#     an idle binary is fine; overwriting a running one gives exit 137. Hence
#     rm-then-copy, plus a re-sign.
#   * The server reads JSON-RPC from stdin, so a failed install looks like a
#     hang rather than an error. We verify with --version, which never blocks.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="${ANONYM_MCP_PREFIX:-$HOME/.local/bin}"
TARGET="$INSTALL_DIR/anonym-mcp"

echo "Building anonym-mcp..."
cargo build --manifest-path "$REPO_ROOT/Cargo.toml" --release

mkdir -p "$INSTALL_DIR"
# Remove first, never write in place: unlinking leaves any running process with
# its own intact inode, while overwriting corrupts the image it is executing.
rm -f "$TARGET"
cp "$REPO_ROOT/target/release/anonym-mcp" "$TARGET"
chmod +x "$TARGET"

if [[ "$(uname -s)" == "Darwin" ]] && command -v codesign >/dev/null 2>&1; then
    codesign --force --sign - "$TARGET" >/dev/null 2>&1 || true
fi

# Prove the installed artifact actually runs, rather than assuming the copy
# worked. --version returns immediately even though the server's normal mode
# blocks on stdin.
if ! installed_version="$("$TARGET" --version 2>&1)"; then
    echo "error: installed binary does not run: $installed_version" >&2
    exit 1
fi
echo "Installed $installed_version at $TARGET"

case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) echo "note: $INSTALL_DIR is not on your PATH" >&2 ;;
esac

cat <<EOF

Next: point your agent at it. In a project, .jcode/mcp.json:

  {
    "mcpServers": {
      "anonym": {
        "command": "$TARGET",
        "env": {
          "ANONYM_ROOTS": "/path/to/sensitive/data",
          "ANONYM_WORDS": "Musteri Adi"
        }
      }
    }
  }

Docs: README.md
EOF
