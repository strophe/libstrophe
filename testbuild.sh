#!/bin/sh

logfile="../../testbuild.log"
errfile="../../testerr.log"

err_out() {
  tail $logfile
  exit 1
}

./bootstrap.sh
./configure >> $logfile 2>> $errfile || err_out
make -j$(( `nproc` * 2 + 1 )) >> $logfile 2>> $errfile || err_out
make check >> $logfile 2>> $errfile || err_out
