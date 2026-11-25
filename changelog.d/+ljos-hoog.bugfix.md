A read of a curl config file now warns as `reads-credential`, and inline program text that names one asks with `credential-mention`.
The names are `.curlrc` and `_curlrc` anywhere, and `curlrc` with no dot under `.config` or `$XDG_CONFIG_HOME`, which cover every file curl 7.x to 8.23.0 reads by default, including `~/.config/curlrc` from curl 7.82.0 and `$XDG_CONFIG_HOME/curlrc` from 8.10.0.
`_curlrc` was the only name on Windows, and on MS-DOS from 7.10.6, before 7.66.0, and is the Windows-only second choice after `.curlrc` from 7.66.0.
A bare `curlrc` elsewhere, such as `tests/fixtures/curlrc` or a search word, stays allowed.
