#!/usr/bin/env bash
#
# claude-resume.sh - Start or resume Claude Code sessions with full memory integration
# Always uses --dangerously-skip-permissions
#
# Memory layers managed:
#   1. Claude Code Memory  — ~/.claude/projects/.../memory/ (auto-loaded by Claude)
#   2. Ruflo AgentDB       — .claude/memory.db (vector embeddings, patterns, learning)
#   3. Ruflo Session State  — .claude-flow/sessions/ (hooks: session-restore/session-end)
#
# Usage:
#   ./scripts/claude-resume.sh              # Interactive resume picker
#   ./scripts/claude-resume.sh <session-id> # Resume specific session
#   ./scripts/claude-resume.sh --new        # New named session
#   ./scripts/claude-resume.sh --new "name" # New session with specific name
#   ./scripts/claude-resume.sh --continue   # Continue most recent session
#   ./scripts/claude-resume.sh --list       # List recent sessions
#   ./scripts/claude-resume.sh --fork <id>  # Fork a session (new branch from existing)
#   ./scripts/claude-resume.sh --memory     # Show memory status across all layers
#   ./scripts/claude-resume.sh --cleanup    # Cleanup stale memory + compress DB
#

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

WORKSPACE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BASE_FLAGS="--dangerously-skip-permissions"

# Derive Claude Code project memory path
# Claude Code uses the absolute path with '/' replaced by '-', leading slash becomes single '-'
CLAUDE_PROJECT_ID="$(echo "$WORKSPACE_DIR" | sed 's|^/|-|' | tr '/' '-')"
CLAUDE_MEMORY_DIR="$HOME/.claude/projects/${CLAUDE_PROJECT_ID}/memory"

# Ruflo paths
RUFLO_MEMORY_DB="$WORKSPACE_DIR/.claude/memory.db"
RUFLO_SESSION_DIR="$WORKSPACE_DIR/.claude-flow/sessions"

print_banner() {
    local ws_name
    ws_name="$(basename "$WORKSPACE_DIR")"
    local ruflo_ver
    ruflo_ver="$(ruflo --version 2>/dev/null | grep -o '[0-9.]*' || echo '?')"
    echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}Claude Code Session Manager${NC}                 ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${DIM}${ws_name} | ruflo ${ruflo_ver} | 3-layer memory${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
    echo ""
}

check_claude() {
    if ! command -v claude &>/dev/null; then
        echo -e "${RED}Error: claude CLI not found${NC}"
        echo "Install: npm install -g @anthropic-ai/claude-code"
        exit 1
    fi
}

check_ruflo() {
    if command -v ruflo &>/dev/null; then
        return 0
    elif npx ruflo@latest --version &>/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Ensure ruflo memory DB is initialized
ensure_memory_db() {
    if [ ! -f "$RUFLO_MEMORY_DB" ]; then
        echo -e "  ${DIM}├─${NC} Initializing ruflo memory database..."
        (cd "$WORKSPACE_DIR" && ruflo memory init 2>/dev/null) || \
        (cd "$WORKSPACE_DIR" && npx ruflo@latest memory init 2>/dev/null) || true
    fi
}

# Restore ruflo session state before launching Claude
pre_session_restore() {
    local session_id="${1:-}"
    echo -e "${GREEN}[memory]${NC} Preparing memory layers..."

    # Layer 1: Claude Code Memory (auto-loaded, just verify)
    if [ -d "$CLAUDE_MEMORY_DIR" ]; then
        local mem_count
        mem_count=$(find "$CLAUDE_MEMORY_DIR" -name "*.md" ! -name "MEMORY.md" 2>/dev/null | wc -l | tr -d ' ')
        echo -e "  ${DIM}├─${NC} Claude Memory: ${GREEN}${mem_count} entries${NC} in ${DIM}${CLAUDE_MEMORY_DIR}${NC}"
    else
        echo -e "  ${DIM}├─${NC} Claude Memory: ${YELLOW}no entries yet${NC} (created on first save)"
    fi

    # Layer 2: Ruflo AgentDB
    if [ -f "$RUFLO_MEMORY_DB" ]; then
        local db_size
        db_size=$(du -h "$RUFLO_MEMORY_DB" 2>/dev/null | cut -f1 | tr -d ' ')
        echo -e "  ${DIM}├─${NC} Ruflo AgentDB: ${GREEN}${db_size}${NC} ${DIM}${RUFLO_MEMORY_DB}${NC}"
    else
        ensure_memory_db
        echo -e "  ${DIM}├─${NC} Ruflo AgentDB: ${GREEN}initialized${NC}"
    fi

    # Layer 3: Ruflo Session Restore (if resuming a specific session)
    if [ -n "$session_id" ]; then
        echo -e "  ${DIM}├─${NC} Session restore: ${BOLD}${session_id}${NC}"
        (cd "$WORKSPACE_DIR" && ruflo hooks session-restore --session-id "$session_id" 2>/dev/null) || \
        (cd "$WORKSPACE_DIR" && npx ruflo@latest hooks session-restore --session-id "$session_id" 2>/dev/null) || true
    else
        # Try restoring the latest session
        (cd "$WORKSPACE_DIR" && ruflo hooks session-restore 2>/dev/null) || \
        (cd "$WORKSPACE_DIR" && npx ruflo@latest hooks session-restore 2>/dev/null) || true
        echo -e "  ${DIM}├─${NC} Session state: ${GREEN}restored (latest)${NC}"
    fi

    echo -e "  ${DIM}└─${NC} ${GREEN}All memory layers ready${NC}"
    echo ""
}

# Register a trap to persist session state on script exit (if Claude exits normally)
register_session_end_trap() {
    trap 'post_session_end' EXIT
}

post_session_end() {
    # Only run if ruflo is available - don't block exit on failure
    (cd "$WORKSPACE_DIR" && ruflo hooks session-end --generate-summary true --persist-state true --export-metrics true 2>/dev/null) || \
    (cd "$WORKSPACE_DIR" && npx ruflo@latest hooks session-end --generate-summary true --persist-state true --export-metrics true 2>/dev/null) || true
}

show_help() {
    echo -e "${BOLD}Usage:${NC} $(basename "$0") [OPTIONS] [SESSION_ID]"
    echo ""
    echo -e "${BOLD}Session Options:${NC}"
    echo -e "  ${GREEN}(no args)${NC}         Interactive session picker (--resume)"
    echo -e "  ${GREEN}<session-id>${NC}      Resume specific session by ID"
    echo -e "  ${GREEN}--new [name]${NC}      Start new session, optionally named"
    echo -e "  ${GREEN}--continue${NC}        Continue most recent session in this directory"
    echo -e "  ${GREEN}--fork <id>${NC}       Fork existing session (new ID, same context)"
    echo -e "  ${GREEN}--list${NC}            List recent sessions (via interactive picker)"
    echo -e "  ${GREEN}--pr [num|url]${NC}    Resume session linked to a PR"
    echo ""
    echo -e "${BOLD}Memory Options:${NC}"
    echo -e "  ${GREEN}--memory${NC}          Show memory status across all 3 layers"
    echo -e "  ${GREEN}--cleanup${NC}         Cleanup stale entries and compress AgentDB"
    echo -e "  ${GREEN}--export${NC}          Export ruflo memory to JSON backup"
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo -e "  ${GREEN}--help${NC}            Show this help"
    echo ""
    echo -e "${DIM}All sessions run with --dangerously-skip-permissions${NC}"
    echo -e "${DIM}Memory: Claude Memory + Ruflo AgentDB + Ruflo Session State${NC}"
}

cmd_resume_interactive() {
    pre_session_restore ""
    echo -e "${GREEN}>>>${NC} Opening session picker..."
    cd "$WORKSPACE_DIR"
    register_session_end_trap
    claude $BASE_FLAGS --resume
    exit $?
}

cmd_resume_id() {
    local session_id="$1"
    pre_session_restore "$session_id"
    echo -e "${GREEN}>>>${NC} Resuming session: ${BOLD}${session_id}${NC}"
    cd "$WORKSPACE_DIR"
    register_session_end_trap
    claude $BASE_FLAGS --resume "$session_id"
    exit $?
}

cmd_new() {
    local name="${1:-}"
    pre_session_restore ""
    if [ -n "$name" ]; then
        echo -e "${GREEN}>>>${NC} Starting new session: ${BOLD}${name}${NC}"
        cd "$WORKSPACE_DIR"
        register_session_end_trap
        claude $BASE_FLAGS --name "$name"
        exit $?
    else
        echo -e "${GREEN}>>>${NC} Starting new session..."
        cd "$WORKSPACE_DIR"
        register_session_end_trap
        claude $BASE_FLAGS
        exit $?
    fi
}

cmd_continue() {
    pre_session_restore ""
    echo -e "${GREEN}>>>${NC} Continuing most recent session..."
    cd "$WORKSPACE_DIR"
    register_session_end_trap
    claude $BASE_FLAGS --continue
    exit $?
}

cmd_fork() {
    local session_id="$1"
    pre_session_restore "$session_id"
    echo -e "${GREEN}>>>${NC} Forking session: ${BOLD}${session_id}${NC}"
    cd "$WORKSPACE_DIR"
    register_session_end_trap
    claude $BASE_FLAGS --resume "$session_id" --fork-session
    exit $?
}

cmd_from_pr() {
    local pr="${1:-}"
    pre_session_restore ""
    echo -e "${GREEN}>>>${NC} Resuming PR session..."
    cd "$WORKSPACE_DIR"
    register_session_end_trap
    if [ -n "$pr" ]; then
        claude $BASE_FLAGS --from-pr "$pr"
    else
        claude $BASE_FLAGS --from-pr
    fi
    exit $?
}

cmd_list() {
    echo -e "${GREEN}>>>${NC} Listing sessions (interactive picker)..."
    cd "$WORKSPACE_DIR"
    exec claude $BASE_FLAGS --resume ""
}

cmd_memory_status() {
    echo -e "${BOLD}Memory Status (3 Layers)${NC}"
    echo ""

    # Layer 1: Claude Code Memory
    echo -e "${CYAN}Layer 1: Claude Code Memory${NC}"
    if [ -d "$CLAUDE_MEMORY_DIR" ]; then
        local mem_count
        mem_count=$(find "$CLAUDE_MEMORY_DIR" -name "*.md" ! -name "MEMORY.md" 2>/dev/null | wc -l | tr -d ' ')
        echo -e "  Path:    ${DIM}${CLAUDE_MEMORY_DIR}${NC}"
        echo -e "  Entries: ${GREEN}${mem_count}${NC}"
        if [ -f "$CLAUDE_MEMORY_DIR/MEMORY.md" ]; then
            echo -e "  Index:   ${GREEN}MEMORY.md present${NC}"
        fi
        find "$CLAUDE_MEMORY_DIR" -name "*.md" ! -name "MEMORY.md" -exec basename {} .md \; 2>/dev/null | while read -r entry; do
            echo -e "    ${DIM}├─${NC} $entry"
        done
    else
        echo -e "  ${YELLOW}Not yet created${NC}"
    fi
    echo ""

    # Layer 2: Ruflo AgentDB
    echo -e "${CYAN}Layer 2: Ruflo AgentDB${NC}"
    if [ -f "$RUFLO_MEMORY_DB" ]; then
        local db_size
        db_size=$(du -h "$RUFLO_MEMORY_DB" 2>/dev/null | cut -f1 | tr -d ' ')
        echo -e "  Path: ${DIM}${RUFLO_MEMORY_DB}${NC}"
        echo -e "  Size: ${GREEN}${db_size}${NC}"
        (cd "$WORKSPACE_DIR" && ruflo memory stats 2>/dev/null) || \
        (cd "$WORKSPACE_DIR" && npx ruflo@latest memory stats 2>/dev/null) || \
        echo -e "  ${YELLOW}Stats unavailable${NC}"
    else
        echo -e "  ${YELLOW}Not initialized${NC} (run: ruflo memory init)"
    fi
    echo ""

    # Layer 3: Ruflo Session State
    echo -e "${CYAN}Layer 3: Ruflo Session State${NC}"
    if [ -d "$RUFLO_SESSION_DIR" ]; then
        local session_count
        session_count=$(ls "$RUFLO_SESSION_DIR" 2>/dev/null | wc -l | tr -d ' ')
        echo -e "  Path:     ${DIM}${RUFLO_SESSION_DIR}${NC}"
        echo -e "  Sessions: ${GREEN}${session_count}${NC}"
    else
        echo -e "  ${YELLOW}No sessions stored${NC}"
    fi
}

cmd_cleanup() {
    echo -e "${BOLD}Memory Cleanup${NC}"
    echo ""

    # Ruflo memory cleanup + compress
    echo -e "${GREEN}>>>${NC} Cleaning stale ruflo memory entries..."
    (cd "$WORKSPACE_DIR" && ruflo memory cleanup 2>&1) || \
    (cd "$WORKSPACE_DIR" && npx ruflo@latest memory cleanup 2>&1) || \
    echo -e "  ${YELLOW}Cleanup unavailable${NC}"

    echo ""
    echo -e "${GREEN}>>>${NC} Compressing ruflo memory database..."
    (cd "$WORKSPACE_DIR" && ruflo memory compress 2>&1) || \
    (cd "$WORKSPACE_DIR" && npx ruflo@latest memory compress 2>&1) || \
    echo -e "  ${YELLOW}Compress unavailable${NC}"

    echo ""
    echo -e "${GREEN}Done.${NC}"
}

cmd_export() {
    local export_file="$WORKSPACE_DIR/.claude-flow/memory-backup-$(date +%Y%m%d-%H%M%S).json"
    echo -e "${GREEN}>>>${NC} Exporting ruflo memory to ${DIM}${export_file}${NC}..."
    (cd "$WORKSPACE_DIR" && ruflo memory export "$export_file" 2>&1) || \
    (cd "$WORKSPACE_DIR" && npx ruflo@latest memory export "$export_file" 2>&1) || \
    echo -e "  ${YELLOW}Export unavailable${NC}"
}

# Main
main() {
    check_claude
    print_banner

    if [ $# -eq 0 ]; then
        cmd_resume_interactive
        exit 0
    fi

    case "$1" in
        --help|-h)
            show_help
            ;;
        --new|-n)
            cmd_new "${2:-}"
            ;;
        --continue|-c)
            cmd_continue
            ;;
        --fork|-f)
            if [ -z "${2:-}" ]; then
                echo -e "${RED}Error: --fork requires a session ID${NC}"
                exit 1
            fi
            cmd_fork "$2"
            ;;
        --pr|--from-pr)
            cmd_from_pr "${2:-}"
            ;;
        --list|-l)
            cmd_list
            ;;
        --memory|-m)
            cmd_memory_status
            ;;
        --cleanup)
            cmd_cleanup
            ;;
        --export)
            cmd_export
            ;;
        -*)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
        *)
            # Assume it's a session ID
            cmd_resume_id "$1"
            ;;
    esac
}

main "$@"
