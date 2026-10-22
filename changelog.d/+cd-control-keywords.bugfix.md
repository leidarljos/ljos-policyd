A control keyword in front of `cd` now keeps directory tracking aligned
with shell behavior. Lines such as
`if cd project; then make clean-all; fi` and
`while cd project; do make clean-all; done` now read the runner in the
directories those forms can reach.
