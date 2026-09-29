#!/bin/bash
# Phase 5: สคริปต์ demo — รันทีละ test case พร้อม log เก็บไว้ในโฟลเดอร์ logs/
set -e
make -s
mkdir -p logs
cd tests

run() {  # run <ชื่อ> <flag ของ tracer> <program>
    echo; echo "================ $1 ================"
    ../tracer $2 -o ../logs/$1.log ./$3 && true
    tail -n +1 ../logs/$1.log | sed -n '/Syscall Summary/,$p'
}

run 1_file_io      "-c"    test_io
run 2_fork         "-f"    test_fork
run 3_cpu_bound    "-c"    test_cpu
run 4_suspicious   "-c"    test_suspicious

echo; echo "log เต็มอยู่ใน logs/*.log"
echo "เทียบกับ strace จริง (ถ้ามี):  strace -c ./tests/test_io"
