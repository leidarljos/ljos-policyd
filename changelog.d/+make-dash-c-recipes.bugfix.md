`make -C build` read the makefile in `build`, then judged a recipe
such as `$(MAKE) -f CMakeFiles/Makefile2` from the directory make was
started in. That file lives under `build`. The recipe is judged
there, and a dangerous line in it is still refused.
