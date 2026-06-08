#!/bin/sh
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1
eval $(alr -n --no-tty printenv --unix)
make
