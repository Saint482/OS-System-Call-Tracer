# System Call Tracer (Linux x86_64)
    make                       # build tracer + test programs
    ./tracer ./tests/test_io   # log ทีละ syscall (stderr) + summary
    ./tracer -c  <prog>        # summary อย่างเดียว
    ./tracer -f  <prog>        # ตาม fork/clone
    ./tracer -o out.log <prog> # เขียน log ลงไฟล์
    ./demo.sh                  # รัน test case ทั้งหมด
ต้องรันบน Linux (WSL2 ใช้ได้) ที่อนุญาต ptrace
