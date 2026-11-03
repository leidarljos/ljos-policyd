#!/bin/sh
# Run the suite with a fresh state directory and home, then fail if either
# gained a deny log. The files are checked after cargo exits, so the
# assertion sits outside the test process.
set -eu
orig_home=$HOME
xdg=$(mktemp -d)
home=$(mktemp -d)
# rustup and cargo live under the real home when their own variables are
# unset. Point them there before HOME moves, or the toolchain disappears
# with it. The tests still see the fresh HOME and XDG_STATE_HOME.
if [ -z "${RUSTUP_HOME:-}" ]; then
  RUSTUP_HOME="$orig_home/.rustup"
  export RUSTUP_HOME
fi
if [ -z "${CARGO_HOME:-}" ]; then
  CARGO_HOME="$orig_home/.cargo"
  export CARGO_HOME
fi
export XDG_STATE_HOME="$xdg"
export HOME="$home"
set +e
cargo test --locked --workspace "$@"
status=$?
set -e
if [ -e "$xdg/ljos-policyd/deny.log" ] || [ -e "$home/.local/state/ljos-policyd/deny.log" ]; then
  echo "the test suite wrote the developer deny log" >&2
  if [ -e "$xdg/ljos-policyd/deny.log" ]; then
    echo "XDG_STATE_HOME $xdg/ljos-policyd/deny.log" >&2
  fi
  if [ -e "$home/.local/state/ljos-policyd/deny.log" ]; then
    echo "HOME $home/.local/state/ljos-policyd/deny.log" >&2
  fi
  status=1
fi
rm -rf "$xdg" "$home"
exit "$status"
