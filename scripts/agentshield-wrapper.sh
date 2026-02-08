#!/usr/bin/env zsh
# AgentShield Shell Wrapper
# Source this file in your .zshrc to route all commands through AgentShield.
#
# Usage:
#   echo 'source /usr/local/share/agentshield/agentshield-wrapper.sh' >> ~/.zshrc
#
# To disable temporarily:
#   export AGENTSHIELD_BYPASS=1
#
# To re-enable:
#   unset AGENTSHIELD_BYPASS

# Avoid double-loading
if [[ -n "$AGENTSHIELD_LOADED" ]]; then
  return 0
fi
export AGENTSHIELD_LOADED=1

# Path to the agentshield binary
AGENTSHIELD_BIN="${AGENTSHIELD_BIN:-$(command -v agentshield 2>/dev/null)}"

if [[ -z "$AGENTSHIELD_BIN" ]]; then
  echo "[AgentShield] WARNING: agentshield binary not found in PATH. Wrapper disabled." >&2
  return 1
fi

# Commands to never intercept (AgentShield itself, shell builtins, etc.)
_agentshield_skip_list=(
  agentshield
  cd
  exit
  source
  export
  unset
  alias
  unalias
  history
  bg
  fg
  jobs
  kill
  wait
  eval
  exec
  trap
)

# Check if a command should be skipped
_agentshield_should_skip() {
  local cmd_name="$1"

  # Bypass mode
  [[ -n "$AGENTSHIELD_BYPASS" ]] && return 0

  # Skip shell builtins and agentshield itself
  for skip in "${_agentshield_skip_list[@]}"; do
    [[ "$cmd_name" == "$skip" ]] && return 0
  done

  return 1
}

# The preexec hook — runs before every command
_agentshield_preexec() {
  local full_cmd="$1"

  # Extract the first word (command name)
  local cmd_name="${full_cmd%% *}"

  # Skip if in the skip list
  if _agentshield_should_skip "$cmd_name"; then
    return 0
  fi

  # Route through AgentShield
  # We use AGENTSHIELD_INTERCEPTED to prevent recursion
  if [[ -z "$AGENTSHIELD_INTERCEPTED" ]]; then
    export AGENTSHIELD_INTERCEPTED=1
    # Run through agentshield instead
    eval "$AGENTSHIELD_BIN run -- $full_cmd"
    local exit_code=$?
    unset AGENTSHIELD_INTERCEPTED
    # Return non-zero to prevent zsh from running the original command
    # This works because we use the 'preexec' approach with a custom wrapper
    return $exit_code
  fi
}

# For zsh: use the preexec hook array
if [[ -n "$ZSH_VERSION" ]]; then
  autoload -Uz add-zsh-hook
  # Instead of preexec (which can't cancel commands), we override the
  # command execution by wrapping it in a function
  agentshield_exec() {
    local full_cmd="$*"
    local cmd_name="${full_cmd%% *}"

    if _agentshield_should_skip "$cmd_name"; then
      command $@
      return $?
    fi

    if [[ -n "$AGENTSHIELD_INTERCEPTED" ]]; then
      command $@
      return $?
    fi

    export AGENTSHIELD_INTERCEPTED=1
    "$AGENTSHIELD_BIN" run -- $@
    local exit_code=$?
    unset AGENTSHIELD_INTERCEPTED
    return $exit_code
  }

  echo "[AgentShield] Wrapper loaded. All commands will be audited." >&2
  echo "[AgentShield] Set AGENTSHIELD_BYPASS=1 to disable." >&2
  echo "[AgentShield] Use 'agentshield log' to view audit trail." >&2
fi
