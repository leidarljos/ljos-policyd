A brace group no longer hides directory changes. A line such as
`{ cd project && make clean-all; }` now tracks `cd` before the runner is
read.
