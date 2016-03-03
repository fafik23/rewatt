# rewatt
A simple overlay allows override attribute values.
In our case, it we replicate users date from three different servers and we
wanted to override attributes such as homeDirectory, shell.

a sample config:

overlay rewatt
ra_attribute homeDirectory
ra_regex "home/(users|staff|guest)"
ra_sub "icm/hydra/home/local"
