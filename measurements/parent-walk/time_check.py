"""time_check.py BIN N [ARG...]: run `BIN ARG...` N times, one after
another, and print the nearest-rank p50 wall time in ms. With no ARG it
runs `BIN check -- rm -rf /srv/x`."""

import math
import os
import subprocess
import sys
import time


def main() -> None:
    bin_path, n = sys.argv[1], int(sys.argv[2])
    env = {k: v for k, v in os.environ.items() if k != "LJOS_POLICYD_DAEMON"}
    argv = [bin_path] + (sys.argv[3:] or ["check", "--", "rm", "-rf", "/srv/x"])
    times = []
    for _ in range(n):
        start = time.perf_counter()
        subprocess.run(argv, env=env, stdout=subprocess.DEVNULL, check=True)
        times.append((time.perf_counter() - start) * 1000)
    times.sort()
    print(f"{times[math.ceil(n / 2) - 1]:.3f}")


if __name__ == "__main__":
    main()
