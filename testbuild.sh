#!/bin/sh

logfile="../../testbuild.log"

err_out() {
  tail $logfile
  exit 1
}

./bootstrap.sh
./configure >> $logfile || err_out
make -j$(( `nproc` * 2 + 1 )) >> $logfile || err_out
make check >> $logfile || err_out
