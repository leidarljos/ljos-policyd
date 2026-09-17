# Shared Cap'n vocabulary for this library (Sandstorm util.capnp analog).
# Source of truth: schema/util.capnp in this repository.
#
# Import from policy.capnp:
#   using Util = import "util.capnp";
#
# No I/O. No platform APIs. Only types every speaker must agree on.

@0xe570dd5cbce72246;

# ------------------------------------------------------------------------------
# Time
# ------------------------------------------------------------------------------

using UnixSecs = UInt64;
# Whole seconds since Unix epoch (UTC). Prefer this over RFC3339 on the wire.
# Zero means "unset" unless a field comment says otherwise.

using UnixNanos = UInt64;
# Nanoseconds since Unix epoch when sub-second precision is required.

# ------------------------------------------------------------------------------
# Generic pairs
# ------------------------------------------------------------------------------

struct KeyValue {
  # Open key/value bag for attributes that are not closed product enums.
  # Do not encode closed sets (RunState, SeatMode) here — use those enums.

  key @0 :Text;
  # Non-empty when meaningful. Empty key is ignored by well-behaved readers.

  value @1 :Text;
  # Free-form; not localized. Keep short on hot paths (events).
}

# ------------------------------------------------------------------------------
# Seat run state (herdr-class). Closed product law.
# ------------------------------------------------------------------------------

enum RunState {
  # Unknown / not yet classified. Prefer over inventing new Text tokens.
  unknown @0;
  # Process or agent is not actively working (registered idle).
  idle @1;
  # Actively running model/tool work (legacy; prefer running).
  working @2;
  # Waiting on human, policy, or external gate; not terminal.
  blocked @3;
  # Finished successfully (legacy; prefer succeeded).
  done @4;
  # Explicit cancel (user/parent/kill). Distinct from blocked/failed.
  cancelled @5;
  # sessiond admitted the agent; process not yet started.
  admitted @6;
  # Supervised process starting (spawn/jail/scope attach).
  starting @7;
  # Model/tool work in progress (canonical "running").
  running @8;
  # Waiting on peer message, tool, or external event (not blocked by policy).
  waiting @9;
  # Terminal success (product). Terminal != success alone.
  succeeded @10;
  # Terminal failure (non-cancel).
  failed @11;
}

# RunState server law: writers MUST emit canonical tokens
# (running|succeeded|admitted|starting|waiting|…). Readers MUST accept legacy
# working|done until a future schema-v1 pin.

# ------------------------------------------------------------------------------
# Agent product surface (what the seat UI presents). Orthogonal to RunState.
# ------------------------------------------------------------------------------

enum AgentSurface {
  # Default / not classified. Peers must not invent Text surface tokens.
  unset @0;
  # Generic board row; no special plan/question pane surface.
  board @1;
  # Plan mode finished; plan body lives in ReportAgent.resultTail.
  planAwaitingApproval @2;
  # User question / comments gate; questions JSON in resultTail.
  userQuestion @3;
}

# ------------------------------------------------------------------------------
# Seat product mode. Closed allowlist (shell-init / sessiond mode).
# ------------------------------------------------------------------------------

enum SeatMode {
  # Default engineering mode.
  develop @0;
  # Focus / do-not-disturb oriented mode.
  focus @1;
}

# ------------------------------------------------------------------------------
# Backend health snapshot (observe plane).
# ------------------------------------------------------------------------------

struct BackendState {
  # Whether this backend is usable for product paths.

  available @0 :Bool;
  # True when the feature is present and not hard-disabled.

  detail @1 :Text;
  # Human diagnostic only. Peers must not parse for control flow.
}

# ------------------------------------------------------------------------------
# Agent identity — fixed-width hash, never free-form Text on the wire
# ------------------------------------------------------------------------------

struct AgentId {
  # Canonical 128-bit agent identity (xxHash3-128 of admit material, or
  # sessiond-minted). Peers MUST treat this as opaque bits — do not parse Text.
  #
  # Zero (hi == 0 && lo == 0) means unset / root / "sessiond allocates".
  #
  # Minting (sessiond, reproducible when inputs fixed):
  #   xxh3_128( parentId || rootId || role || cwd || promptHash || seq || salt )
  # Client-proposed non-zero ids are accepted only if unique; collision → error.
  #
  # CLI display (off-wire only): 32 lowercase hex chars, hi then lo, big-endian
  # per half. Never put that hex string in a Cap'n Text field for identity.

  hi @0 :UInt64;
  lo @1 :UInt64;
}

struct TraceId {
  # Farm correlation id. Same layout as AgentId; separate type so APIs cannot
  # mix agent identity with trace by accident. Zero = unset / sessiond mints.

  hi @0 :UInt64;
  lo @1 :UInt64;
}
