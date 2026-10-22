`ENV=/dev/null; (unset ENV) && unset ENV; sh` was refused as an
unshown startup file. One side of the `&&` still holds `/dev/null`
and the other has unset it, which sources nothing. A shown value
stays that value. Two different values are still not one file, and a
branch that may leave a real file in place is still judged.
