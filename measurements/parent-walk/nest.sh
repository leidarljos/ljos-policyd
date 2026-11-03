#!/bin/sh
# nest.sh N CMD... runs CMD under N + 1 shells.
# `exit $?` keeps sh from exec'ing the next level in its own place.
n=$1; shift
if [ "$n" -gt 0 ]; then "$0" $((n-1)) "$@"; exit $?; fi
"$@"; exit $?
