# Shared shell helpers for hosted-mode signal-cli tests.
# Source from other tests/hosted/*.sh scripts; do not run directly.
#
# Adapted from ~/workdir/xous-signal-client/tools/test-helpers.sh.
# Trimmed to what xas's MVP tests actually exercise.

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "test_helpers.sh is a library; source it from another script." >&2
    exit 64
fi

# Repo root (the xous-app-signal/ directory).
xas_repo_root() {
    local here
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$here/../.." && pwd
}

# Load tests/hosted/test_env if present.
xas_load_env() {
    local root env
    root="$(xas_repo_root)"
    env="$root/tests/hosted/test_env"
    if [[ -f "$env" ]]; then
        # shellcheck source=/dev/null
        source "$env"
        return 0
    fi
    return 1
}

xas_require_env() {
    local missing=()
    local v
    for v in "$@"; do
        if [[ -z "${!v:-}" ]]; then
            missing+=("$v")
        fi
    done
    if (( ${#missing[@]} > 0 )); then
        echo "Missing required env vars: ${missing[*]}" >&2
        echo "Configure them in tests/hosted/test_env" >&2
        echo "(template: tests/hosted/test_env.example)" >&2
        return 2
    fi
    return 0
}

xas_require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" &>/dev/null; then
        echo "Required command not found: $cmd" >&2
        return 2
    fi
    return 0
}

# Verify signal-cli is linked to a given account with at least one
# expected linked secondary. Refuse to run the scan if the expected
# secondary is absent. (Same hard-rule the previous project used.)
xas_verify_linked_device() {
    local account="$1"; shift
    if (( $# == 0 )); then
        echo "xas_verify_linked_device: caller must list at least one expected device" >&2
        return 64
    fi
    local devices rc
    devices="$(signal-cli -a "$account" listDevices 2>&1)"
    rc=$?
    if (( rc != 0 )); then
        echo "signal-cli listDevices failed for $account (rc=$rc):" >&2
        echo "$devices" | head -5 >&2
        return 2
    fi
    local expected
    for expected in "$@"; do
        if grep -qE "Name:.*$expected" <<<"$devices"; then
            return 0
        fi
    done
    echo "Expected linked device(s) not found on $account:" >&2
    printf "  - %s\n" "$@" >&2
    echo "Actual listDevices:" >&2
    echo "$devices" | sed 's/^/  /' >&2
    return 2
}

# Clear signal-cli's stored sessions for a target UUID, looked up by
# phone number. Forces signal-cli's next outbound to that target to
# issue a PreKey-bundle (envelope type 3) — needed when xas's PDDB
# state has been rolled back relative to signal-cli's session table.
# Best-effort: returns 0 even when the account/recipient/db is missing.
#
# Args: signal_cli_account_e164, target_phone_e164
xas_clear_signal_cli_sessions() {
    local sender="$1"
    local target="$2"
    local signal_cli_root="${SIGNAL_CLI_ROOT:-$HOME/.local/share/signal-cli}"
    local accounts_json="$signal_cli_root/data/accounts.json"

    if [[ ! -f "$accounts_json" ]]; then
        echo "  (accounts.json missing — skipping session-clear)"
        return 0
    fi
    if ! command -v python3 &>/dev/null; then
        echo "  (python3 missing — skipping session-clear)"
        return 0
    fi

    python3 - "$accounts_json" "$sender" "$target" <<'PYEOF'
import sqlite3, json, os, sys

accounts_json, sender, target = sys.argv[1], sys.argv[2], sys.argv[3]

with open(accounts_json) as f:
    data = json.load(f)
sender_path = None
for acc in data.get("accounts", []):
    if acc.get("number") == sender:
        sender_path = acc.get("path")
        break
if not sender_path:
    print(f"  signal-cli has no account for {sender}; nothing to clear")
    sys.exit(0)

if not os.path.isabs(sender_path):
    sender_path = os.path.join(os.path.dirname(accounts_json), sender_path)
db_dir = sender_path if sender_path.endswith(".d") else sender_path + ".d"
db_path = os.path.join(db_dir, "account.db")
if not os.path.exists(db_path):
    print(f"  signal-cli db not at {db_path}; nothing to clear")
    sys.exit(0)

con = sqlite3.connect(db_path)
row = con.execute("SELECT aci FROM recipient WHERE number = ?", (target,)).fetchone()
if not row or not row[0]:
    print(f"  signal-cli has no recipient row for {target}; nothing to clear")
    con.close()
    sys.exit(0)
uuid = row[0]
cur = con.execute("DELETE FROM session WHERE address = ?", (uuid,))
con.commit()
print(f"  cleared {cur.rowcount} session row(s) for {target} (uuid={uuid})")
con.close()
PYEOF
    return 0
}
