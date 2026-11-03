#!/bin/sh
# Prints how many parents this script has, then their names, nearest first.
p=$PPID n=0 line=
while [ -n "$p" ] && [ "$p" != 0 ]; do
  n=$((n+1)); line="$line $(cat /proc/$p/comm)"
  p=$(awk '/^PPid:/{print $2}' /proc/$p/status)
done
echo "$n:$line"
