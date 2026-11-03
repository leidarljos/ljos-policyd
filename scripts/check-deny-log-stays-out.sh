#!/bin/sh
# Run the suite with a fresh XDG_STATE_HOME and fail if that directory
# or the home state directory gained a deny log. HOME stays the real
# home. The test moved HOME while XDG_CONFIG_HOME stayed set, so
# process_xdg watched a different config dir. The failing row is
# ~/.config/ljos, not $ENV{HOME}/.secrets, and the plain test job
# failed too, not only the phronesis build. Any fresh HOME must also
# set or unset XDG_CONFIG_HOME and XDG_DATA_HOME. The files are
# checked after cargo exits, so the assertion sits outside the
# test process.
set -eu
xdg=$(mktemp -d)
home_log="${HOME}/.local/state/ljos-policyd/deny.log"
before=
if [ -f "$home_log" ]; then
  before=$(cksum "$home_log")
fi
export XDG_STATE_HOME="$xdg"
set +e
cargo test --locked --workspace "$@"
status=$?
set -e
if [ -e "$xdg/ljos-policyd/deny.log" ]; then
  echo "the test suite wrote $xdg/ljos-policyd/deny.log" >&2
  status=1
fi
if [ -f "$home_log" ]; then
  after=$(cksum "$home_log")
  if [ "$before" != "$after" ]; then
    echo "the test suite wrote $home_log" >&2
    status=1
  fi
fi
rm -rf "$xdg"
exit "$status"
