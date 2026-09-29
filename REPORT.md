# รายงาน Mini Project: System Call Tracer
วิชา Operating Systems 

| ชื่อ-รหัสนักศึกษา: อนัตตา โยคาพจร 673380429-4 | Section: 3

| ชื่อ-รหัสนักศึกษา: จีรภัทร แก้วดี 673380577-9 | Section: 3

สภาพแวดล้อมที่ทดสอบ: Linux บน WSL2, kernel 6.18.33.2-microsoft-standard-WSL2

---

## 1. บทนำและวัตถุประสงค์

**System call** คือช่องทางที่โปรแกรมในโหมดผู้ใช้ (user mode) ใช้ขอบริการจาก kernel เช่น เปิด/อ่าน/เขียนไฟล์ สร้าง process ขอ memory หรือเชื่อมต่อ network โปรแกรมทั่วไปไม่มีสิทธิ์เข้าถึง hardware และทรัพยากรของเครื่องโดยตรง ต้องส่งคำขอผ่าน kernel ทุกครั้งเพื่อให้ OS ควบคุมความปลอดภัยและแบ่งปันทรัพยากรได้ ดังนั้นการดูว่าโปรแกรมเรียก system call อะไรบ้างจึงเท่ากับการดูว่าโปรแกรมนั้น "คุยกับ OS" ว่าอะไร

**วัตถุประสงค์ของโปรเจกต์**
1. สร้างเครื่องมือที่ดักและบันทึก system call ของ process เป้าหมาย (แนวทางเดียวกับ `strace`) บน Linux x86_64
2. แสดงชื่อ syscall, argument ที่อ่านเข้าใจได้ (path, flag, buffer) และค่าที่คืนพร้อมชื่อ errno
3. วิเคราะห์พฤติกรรมของโปรแกรมจาก log ได้แก่ สถิติรายตัว แยกตามประเภท จำแนก workload และแจ้งเตือนพฤติกรรมน่าสงสัย

---

## 2. ทฤษฎีที่เกี่ยวข้อง

**User mode / Kernel mode และ system call**
CPU แยกโหมดการทำงานเป็นโหมดผู้ใช้ (สิทธิ์จำกัด) และโหมด kernel (สิทธิ์เต็ม) เมื่อโปรแกรมเรียก syscall CPU จะ trap เข้า kernel ด้วยคำสั่งพิเศษ (บน x86_64 คือ `syscall`) kernel ทำงานที่ขอ แล้วคืนค่ากลับสู่โหมดผู้ใช้ syscall แต่ละตัวมีหมายเลขประจำตัวใน syscall table

**Calling convention บน x86_64 Linux**

| ข้อมูล | Register |
|---|---|
| หมายเลข syscall | `orig_rax` |
| argument 1–6 | `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` |
| ค่าที่คืน | `rax` (ค่าลบระหว่าง -4095 ถึง -1 คือ errno) |

**`ptrace()`**
system call ที่ให้ process หนึ่ง (tracer) ควบคุมและตรวจสอบอีก process หนึ่ง (tracee) ได้ กลไกเดียวกับที่ debugger ใช้ คำสั่งที่ใช้ในโปรเจกต์นี้:

| คำสั่ง | หน้าที่ |
|---|---|
| `PTRACE_TRACEME` | tracee ประกาศให้ process แม่ trace ตนได้ |
| `PTRACE_SETOPTIONS` | ตั้งค่า เช่น `TRACESYSGOOD`, `EXITKILL`, `TRACEFORK/VFORK/CLONE` |
| `PTRACE_SYSCALL` | สั่งให้ tracee รันต่อจนกว่าจะถึง syscall ครั้งถัดไป (ทั้งตอนเข้าและออก) |
| `PTRACE_GETREGS` | อ่านค่า register ของ tracee |
| `PTRACE_PEEKDATA` | อ่าน memory ของ tracee ทีละ word (ใช้ดึง string/buffer ที่ argument ชี้ไป) |
| `PTRACE_GETEVENTMSG` | รับ pid ของ process ลูกที่เพิ่งถูกสร้างตอน trace `fork/clone` |

**`waitpid()` และการหยุด 2 ครั้งต่อ 1 syscall**
เมื่อ tracee ถูก trace ด้วย `PTRACE_SYSCALL` kernel จะหยุด tracee ที่ *syscall-enter-stop* (ก่อน kernel ทำงาน) และ *syscall-exit-stop* (หลังทำงานเสร็จ มีค่าที่คืนแล้ว) สองจังหวะนี้สลับกันเสมอ tracer รับรู้ผ่าน `waitpid()` ใช้ `PTRACE_O_TRACESYSGOOD` เพื่อให้แยก stop ของ syscall (`SIGTRAP | 0x80`) ออกจาก signal ปกติได้

---

## 3. การออกแบบ

### 3.1 ลำดับการทำงานระหว่าง tracer ↔ tracee

```
tracer (แม่)                                   tracee (ลูก)
    | fork() --------------------------------> |
    |                                           | PTRACE_TRACEME
    |                                           | raise(SIGSTOP)  <- หยุดรอแม่ตั้ง option
    | waitpid()  <------------- หยุด ---------- |
    | PTRACE_SETOPTIONS                         |
    | PTRACE_SYSCALL -------------------------> | execvp(โปรแกรมเป้าหมาย)
    |                                           | ... เรียก syscall ...
    | waitpid(-1, __WALL) <---- หยุดที่ enter - |
    | on_entry(): GETREGS + decode argument     |
    | PTRACE_SYSCALL -------------------------> | (kernel ทำงานตาม syscall)
    | waitpid() <-------------- หยุดที่ exit -- |
    | on_exit_stop(): GETREGS + ค่าที่คืน + log |
    | PTRACE_SYSCALL --> วนซ้ำจนโปรแกรมจบ       |
    v
print_summary()  (สถิติ, จำแนก workload, alerts)
```

### 3.2 โครงสร้างข้อมูล

| โครงสร้าง | ใช้ทำอะไร |
|---|---|
| `table[512]` (`struct sc_info`) | map เลข syscall → ชื่อ, spec ของ argument, หมวด (file I/O / memory / process / network / other) |
| `struct proc` (`procs[1024]`) | state ของแต่ละ process ที่ trace อยู่ เช่น กำลังอยู่ที่ enter หรือ exit, register ตอน enter, เวลาเริ่ม syscall, ข้อความ argument |
| `stats[512]` (`struct stat_ent`) | นับจำนวนครั้ง จำนวน error และเวลารวมของ syscall แต่ละตัว |
| `alerts[64][300]` | เก็บข้อความแจ้งเตือนพฤติกรรมน่าสงสัย |

**Spec ของ argument** ใช้ตัวอักษรกำกับชนิด เช่น `d`=int, `x`=hex, `f`=flag ของ `open`, `s`=string (path), `w`=buffer ที่ความยาวอยู่ใน argument ถัดไป, `r`=buffer ที่ความยาวคือค่าที่คืน (เช่น `read`) ทำให้เพิ่ม syscall ใหม่ได้ด้วยการเพิ่มหนึ่งบรรทัดในตาราง

### 3.3 การอ่าน memory ของ tracee
argument ที่เป็น pointer (เช่น path ของ `openat`) ต้องดึงข้อมูลจริงจาก memory ของ tracee ด้วย `PTRACE_PEEKDATA` โดยอ่านทีละ word แบบ align เพื่อไม่ให้อ่านข้ามหน้า memory ที่ไม่ได้ map จำกัดความยาว string ที่แสดงที่ 64 ตัวอักษร และ buffer ที่ 32 byte

### 3.4 การตาม process ลูก (`-f`)
เมื่อเปิด `-f` จะตั้ง `PTRACE_O_TRACEFORK | TRACEVFORK | TRACECLONE` ให้ kernel แนบ process ลูกเข้ามา trace อัตโนมัติ และรับ pid ลูกผ่าน `PTRACE_GETEVENTMSG`

---

## 4. การ implement (แบ่งตาม Phase)

| Phase | สิ่งที่ทำ | ฟังก์ชันหลักใน tracer.c |
|---|---|---|
| 2 Core | fork/exec/ptrace loop | `main`, `on_entry`, `on_exit_stop` |
| 3 Decode | ชื่อ syscall, args, errno, อ่าน memory | `table[]`, `format_args`, `read_mem`, `read_str`, `format_ret`, `errname` |
| 4 Analysis | สถิติ, จำแนก workload, alert | `account`, `print_summary`, `check_alerts` |

**ตัวเลือกของโปรแกรม:** `-c` แสดงเฉพาะสรุป, `-f` ตาม process ลูก, `-o file` เขียน log ลงไฟล์ (การใช้งาน: `./tracer [-c] [-f] [-o file] <program> [args...]`)

**Phase 2 – Core:** tracee เรียก `PTRACE_TRACEME` แล้ว `raise(SIGSTOP)` เพื่อรอให้ tracer ตั้ง option ก่อน แล้วจึง `execvp` ฝั่ง tracer วน `waitpid(-1, __WALL)` และใช้ค่า `in_syscall` ของแต่ละ process สลับระหว่าง `on_entry` กับ `on_exit_stop` ส่วน signal ที่ tracee ได้รับ (เช่น SIGCHLD) จะถูกบันทึกเป็นบรรทัด `--- ชื่อ signal ---` แล้วส่งต่อให้ tracee ตามเดิม

**Phase 3 – Decode:** ที่ syscall-enter จะอ่าน register และ format argument ทันที เพราะสำหรับ `execve` memory เดิมจะหายไปหลัง exec ส่วน `read`/`recv` ที่ buffer เพิ่งถูกเติมตอนออกจาก syscall จะ format ใหม่ที่ exit-stop ค่าที่คืนถูกแปลงเป็นชื่อ errno เช่น `-1 ENOENT (No such file or directory)` syscall ที่ไม่มีในตารางแสดงเป็น `syscall_N`

**Phase 4 – Analysis:**
- `account()` จับเวลาตั้งแต่ enter ถึง exit ของแต่ละ syscall แล้วสะสมลง `stats[]`
- `print_summary()` แสดงตารางเรียงตามเวลา (รูปแบบเดียวกับ `strace -c`), สรุปแยกตามประเภท และจำแนก workload
- `check_alerts()` แจ้งเตือนเมื่อพบ: เข้าถึงไฟล์อ่อนไหว (`/etc/shadow`, `/etc/passwd`, `/.ssh/`, `/proc/*/mem`), Permission denied ซ้ำตั้งแต่ 3 ครั้ง, `exec` โปรแกรมอื่นระหว่างรัน, `connect` ไป network, และการเรียก `ptrace` เอง

**หลักการจำแนก workload (heuristic)**

| เงื่อนไข | ผล |
|---|---|
| เวลาใน syscall < 20% ของ wall **และ** เรียก syscall < 2000 ครั้ง/วินาที | CPU-bound |
| ไม่เข้าเงื่อนไขข้างบน และเวลาของ file+network syscall > 50% ของเวลาใน syscall | I/O-bound |
| นอกเหนือจากนั้น | Mixed / waiting-bound |

### ปัญหาที่พบและวิธีแก้
1. **format argument ของ `execve` ตอน entry** เพราะหลัง exec memory เดิมของ tracee หายไป
2. **state ของ process ลูกตอนใช้ `-f`** โค้ดเวอร์ชันแรกสมมติว่า stop แรกของลูกคือ syscall-exit ของ `clone` (ตั้ง `in_syscall = 1` และบังคับค่าที่คืนเป็น 0) แต่ผลรัน `./tracer -f ./test_fork` แสดงว่าสมมติฐานนี้ผิด: ทุก syscall ของลูกถูกบันทึกเป็น `-1 ENOSYS (Function not implemented)`, มีบรรทัด `clone(...) = 0` ของลูกที่ไม่ได้เกิดขึ้นจริง, และ `exit_group` ของลูกหายไป (error รวมขึ้นเป็น 8 ทั้งที่ควรมีแค่ 1) สาเหตุคือ stop แรกของลูกเป็น syscall-**enter** ของ syscall แรกที่ลูกเรียกเอง ทำให้การสลับ enter/exit ผิดไปหนึ่งจังหวะตลอด และที่ enter-stop ค่า `rax` เป็น `-ENOSYS` เสมอ จึงถูกอ่านเป็นค่าที่คืน แก้โดยเริ่มลูกที่ `in_syscall = 0` และเลิกบังคับค่าที่คืน (ผลหลังแก้ดู 5.3 ก)
3. **อ่าน memory แบบ align ทีละ word** เพื่อไม่ให้อ่านข้ามหน้าที่ไม่ได้ map
4. **ผลจำแนก workload ไม่นิ่ง** ตอนทดสอบพบว่าผลของ `test_io` เปลี่ยนไปมาระหว่างรอบ มี 2 สาเหตุ
   - `execve` ตัวแรกคือ kernel โหลดโปรแกรมเป้าหมาย ไม่ใช่พฤติกรรมของโปรแกรม แต่กินเวลาถึง 46–52% ของเวลา syscall รวมในตารางดิบ (ดูหัวข้อ 5.1) จึงหักเวลาส่วนนี้ออกก่อนแยกประเภทและตัดสินผล (ตาราง syscall หลักยังนับครบเพื่อให้เทียบกับ `strace -c` ได้)
   - การใช้สัดส่วนเวลาใน syscall ต่อ wall time อย่างเดียวไม่พอ เพราะ overhead ของ ptrace ตอนหยุดทุก syscall อยู่นอกช่วงที่จับเวลา ทำให้โปรแกรมที่เรียก syscall ถี่ๆ ดูเหมือนใช้ CPU จึงเพิ่มเงื่อนไขอัตราการเรียก syscall ต่อวินาที

---

## 5. การทดสอบและผลลัพธ์

**สภาพแวดล้อม:** Linux บน WSL2 (Windows), gcc, x86_64, kernel 6.18.33.2-microsoft-standard-WSL2 โฟลเดอร์งานอยู่ใน `/mnt/c/...` (ระบบไฟล์ของ Windows)
**วิธีรัน:** `./tracer ./test_xxx` (ไม่ใช้ `-c` เพื่อให้เห็น log ทีละ syscall ตามด้วยตารางสรุป)

### 5.1 ผลของแต่ละ test case

| Test case | ไฟล์ | สิ่งที่คาดหวัง | ผลจริง | ตรงตามคาด |
|---|---|---|---|---|
| File I/O | tests/test_io.c | เห็น open/write/read/close/unlink, จัดเป็น I/O-bound | เห็น `openat` 4, `write` 51, `read` 12, `close` 4, `unlink` 1 ครั้ง จัดเป็น **I/O-bound** (file I/O = 96.8% ของเวลา syscall) | ✓ |
| Fork | tests/test_fork.c | เห็น clone ทั้งพ่อ/ลูก, wait4, SIGCHLD | ฝั่งพ่อเห็น `clone(...) = 2929`, `wait4(2929, ...) = 2929` และ `--- Child exited ---` (SIGCHLD) ส่วนฝั่งลูกต้องรันด้วย `-f` (ดู 5.3 ก) | ✓ (ฝั่งพ่อ) / รอผล `-f` หลังแก้ |
| CPU-bound | tests/test_cpu.c | syscall น้อยมาก, จัดเป็น CPU-bound | syscall รวมเพียง 35 ครั้ง (51 ครั้ง/วินาที) เวลาใน syscall 0.2% ของ wall จัดเป็น **CPU-bound** | ✓ |
| Suspicious | tests/test_suspicious.c | alert: /etc/shadow, connect, exec, permission denied | ได้ alert ครบทั้ง 4 รายการ | ✓ |

**ภาพรวมตัวเลข**

| Test | syscall รวม | errors | wall (s) | เวลาใน syscall* (s) | % ของ wall | syscall/s | ผลจำแนก |
|---|---|---|---|---|---|---|---|
| test_cpu | 35 | 1 | 0.6677 | 0.001464 | 0.2% | 51 | CPU-bound |
| test_io | 101 | 1 | 0.0465 | 0.037323 | 80.2% | 2149 | I/O-bound |
| test_fork (ไม่ใช้ `-f`) | 37 | 1 | 0.0065 | 0.001754 | 26.8% | 5503 | Mixed / waiting-bound |
| test_suspicious | 148 | 21 | 0.0201 | 0.008269 | 41.2% | 7320 | I/O-bound |

\* ไม่นับ `execve` ตัวแรกที่โหลดโปรแกรม

**สัดส่วนแยกตามประเภท (% ของเวลา syscall ไม่นับ execve ตัวแรก)**

| Test | file I/O | memory | process | network | other |
|---|---|---|---|---|---|
| test_cpu | 34.5% | 48.9% | 0.0% | – | 16.6% |
| test_io | 96.8% | 2.4% | 0.0% | – | 0.7% |
| test_fork (ไม่ใช้ `-f`) | 29.9% | 40.4% | 16.8% | – | 12.9% |
| test_suspicious | 49.5% | 26.2% | 13.7% | 4.4% | 6.3% |

### 5.2 วิเคราะห์ผล

**test_io – I/O-bound ชัดเจน**
`write` 51 ครั้งกินเวลารวม 0.0217 s (55.8% ของเวลา syscall ทั้งหมด) และ `openat` 4 ครั้งกิน 26.7% เวลาเฉลี่ยต่อครั้งสูงมาก (`write` ≈ 425 µs, `openat` ≈ 2.6 ms) เทียบกับ syscall ทั่วไปที่ ≈ 40 µs ขณะที่ `strace -c` รายงาน `write` เพียง ≈ 6 µs ต่อครั้ง (ดู 5.3 ข) ซึ่งต่างกันเพราะ `strace -c` วัดเวลา CPU ในโหมด kernel เป็นค่าเริ่มต้น ส่วน tracer วัดเวลาจริงตั้งแต่เข้าถึงออก (wall-clock) ที่รวมเวลารอด้วย จึงสันนิษฐานว่าเวลาส่วนใหญ่เป็นเวลารอการเขียนไฟล์ ซึ่งสอดคล้องกับการที่โฟลเดอร์งานอยู่บนระบบไฟล์ของ Windows ที่ mount ผ่าน `/mnt/c` แต่ข้อมูลที่มียังไม่พอจะยืนยัน [ทางเลือก: รัน `strace -c -w ./test_io` และรันซ้ำในโฟลเดอร์บน `~` แล้วแปะผลเปรียบเทียบตรงนี้]

**test_cpu – CPU-bound**
โปรแกรมวนคำนวณ 4×10⁸ รอบ ใช้เวลา 0.67 s แต่เรียก syscall เพียง 35 ครั้ง ซึ่งแทบทั้งหมดเป็น syscall ตอนเริ่มโปรแกรม (dynamic loader: `brk`, `mmap`, `openat` ของ `ld.so.cache` และ `libc.so.6`, `mprotect` ฯลฯ) ส่วนที่เป็นของโปรแกรมจริงมีเพียง `write` ผลลัพธ์กับ `exit_group` เวลาที่อยู่ใน syscall เพียง 0.2% ของ wall time

**test_fork – Mixed / waiting-bound**
เห็นลำดับ `clone` → `wait4` → SIGCHLD (`--- Child exited ---`) ฝั่งพ่อ พ่อต้องรอลูกใน `wait4` จึงไม่ใช่ทั้ง CPU-bound และ I/O-bound ผลจำแนกเป็น Mixed / waiting-bound ตามที่คาด ค่า `clone(0x1200011, ...)` แสดง flag เป็นเลขฐานสิบหก ยังไม่ decode เป็นชื่อ flag

**test_suspicious – จับพฤติกรรมน่าสงสัยได้ครบ**
- `openat("/etc/shadow") = -1 EACCES` 4 ครั้ง → alert "เข้าถึงไฟล์อ่อนไหว" และ "Permission denied ซ้ำ ≥ 3 ครั้ง"
- `connect(...) = -1 ECONNREFUSED` → alert พยายามเชื่อมต่อ network
- `execve("/bin/echo", ...)` เป็น exec ครั้งที่ 2 → alert exec โปรแกรมอื่น
- error รวม 21 ครั้ง แยกได้เป็น `openat` 18 (EACCES 4, ไม่พบ `/nonexistent/file` 1, และ ENOENT อีก 13 ครั้งจาก `echo` ค้นหาไฟล์ locale), `access` 2 (`/etc/ld.so.preload` ของทั้งสอง process) และ `connect` 1 ระบบ alert นับเฉพาะ EACCES/EPERM ไม่นับ ENOENT จึงไม่แจ้งเตือนเกินจริงจาก error ที่เกิดปกติ

**ข้อสังเกตเรื่อง overhead ของ ptrace**
syscall ง่ายๆ เช่น `fstat`, `brk`, `set_tid_address` วัดได้ประมาณ 36–50 µs ต่อครั้ง ซึ่งสูงกว่าเวลาจริงของ syscall เหล่านี้มาก (โดยทั่วไปอยู่ในระดับไม่กี่ไมโครวินาทีหรือต่ำกว่า) เพราะค่าที่วัดรวมการหยุด tracee 2 ครั้งและการสลับ context ไปมาระหว่าง tracer กับ tracee ด้วย

### 5.3 ผลเพิ่มเติม (รอใส่)

**ก) test_fork แบบตาม process ลูก (`-f`)**
รอบแรกพบบั๊กของ state ของลูก (ดูหัวข้อ 4 ข้อ 2) หลังแก้แล้วรัน `./tracer -f ./test_fork` ซ้ำ ได้ผลตามที่คาด: ไม่มี `ENOSYS` เลย เห็น syscall ของลูก (pid 1640) ครบทุกบรรทัด เช่น `set_robust_list(...) = 0`, `getpid() = 1640`, `write(1, "child pid=1640\n", 15) = 15` และ `exit_group(3) = ?` ส่วน error รวมเหลือ 1 ครั้งจริง (จาก `access("/etc/ld.so.preload")` ของฝั่งพ่อ)

```
[pid 1639] clone(0x1200011, 0x0, NULL, 0x7df9ee54aa10, 0x0) = 1640
[pid 1640] set_robust_list(0x7df9ee54aa20, 24) = 0
[pid 1640] getpid() = 1640
[pid 1640] fstat(1, 0x7ffe629a1ba0) = 0
[pid 1640] getrandom(0x7df9ee40b178, 8, 0x1) = 8
[pid 1640] brk(NULL) = 0x620fb99bb000
[pid 1640] brk(0x620fb99dc000) = 0x620fb99dc000
child pid=1640
[pid 1640] write(1, "child pid=1640\n", 15) = 15
[pid 1640] exit_group(3) = ?
[pid 1640] +++ exited with 3 +++
[pid 1639] wait4(1640, 0x7ffe629a1f70, 0x0, NULL) = 1640
[pid 1639] --- Child exited ---
...
===== Syscall Summary =====
total: calls=45, errors=1   (เทียบกับ 44/8 ตอนยังเป็นบั๊ก)

----- แยกตามประเภท (ไม่นับ execve ตอนเริ่มโปรแกรม) -----
process    calls=5   time=0.001850s (39.9%)   <- clone, wait4 ของพ่อ + getpid/exit_group ของลูก

----- การจำแนก workload (heuristic) -----
=> Mixed / waiting-bound (รอ process, lock หรือ sleep)
```

**ข) เทียบกับ `strace -c`**

| Test | tracer (calls / errors) | strace -c (calls / errors) | ส่วนต่าง |
|---|---|---|---|
| test_io | 101 / 1 | 100 / 1 | `exit_group` 1 ครั้ง |
| test_cpu | 35 / 1 | 34 / 1 | `exit_group` 1 ครั้ง |
| test_fork (ไม่ใช้ `-f`) | 37 / 1 | 36 / 1 | `exit_group` 1 ครั้ง |
| test_suspicious | 148 / 21 | 147 / 21 | `exit_group` 1 ครั้ง |

**จำนวนครั้ง:** เมื่อเทียบทีละ syscall ทั้ง 4 test พบว่าจำนวนครั้งและจำนวน error ตรงกันทุกตัว ต่างกันที่ `exit_group` อย่างเดียว เพราะเป็น syscall ที่ไม่คืนค่ากลับ `strace -c` จึงไม่นับ ส่วน tracer นับตั้งแต่ตอน enter ผลนี้ยืนยันว่าการดักและการ decode ของ tracer ถูกต้อง

**เวลา:** ตัวเลขเวลาเทียบกันตรงๆ ไม่ได้ เช่น test_io `strace -c` รวม 0.0014 s แต่ tracer รวม 0.037 s และอันดับที่กินเวลามากสุดต่างกัน (`strace`: `read` 48%, tracer: `write` 56%) เพราะ `strace -c` วัดเวลา CPU ในโหมด kernel เป็นค่าเริ่มต้น (ต้องใส่ `-w` จึงวัด wall-clock) ส่วน tracer วัดเวลาจริงตั้งแต่ enter-stop ถึง exit-stop ซึ่งรวมเวลารอ I/O และ overhead ของ ptrace

**ค) วัด overhead: รันปกติ vs รันผ่าน tracer**

วัดด้วย `time` รันอย่างละ 3 รอบ (หมายเหตุ: รันแบบ `./tracer ./test_xxx` ไม่ใส่ `-c` จึงพิมพ์ log ทุกบรรทัดออกจอด้วย ซึ่งสำหรับ `test_io` ที่มี 101 syscall จะทำให้ overhead ที่วัดได้สูงกว่าการรันแบบ `-c` ที่แสดงแต่สรุป)

| Test | real (ไม่ใช้ tracer) 3 รอบ | เฉลี่ย | real (ผ่าน tracer) 3 รอบ | เฉลี่ย | overhead |
|---|---|---|---|---|---|
| test_io | 0.023s, 0.019s, 0.019s | 0.020s | 0.046s, 0.053s, 0.041s | 0.047s | +0.027s (≈ **2.3 เท่า**) |
| test_cpu | 0.639s, 0.655s, 0.637s | 0.644s | 0.645s, 0.648s, 0.649s | 0.647s | +0.003s (≈ **0.5%**) |

**สรุป:** ตรงตามที่คาดในหัวข้อ 4 — `test_cpu` แทบไม่มี overhead เพราะเรียก syscall แค่ 35 ครั้งตลอดทั้งโปรแกรม (53 ครั้ง/วินาที) เวลาเกือบทั้งหมดเป็นการคำนวณในโหมดผู้ใช้ที่ ptrace ไม่ไปยุ่งด้วย ส่วน `test_io` ช้าลงกว่า 2 เท่า เพราะเรียก syscall ถี่ (101 ครั้งในเวลาสั้นๆ ≈ 2,100–2,700 ครั้ง/วินาทีตามหัวข้อ 5.1) ทำให้ต้องหยุด-ปลุก tracee ผ่าน `waitpid`/`PTRACE_SYSCALL` บ่อยมาก ซึ่งแต่ละครั้งมี context switch ระหว่าง tracer กับ tracee overhead จึงแปรผันตรงกับความถี่ของ syscall ไม่ใช่เวลารวมของโปรแกรม ตัวเลขนี้ยืนยันสิ่งที่อธิบายไว้ในหัวข้อ 4 ว่าเวลาที่ tracer วัดได้ (`usecs/call`) รวม overhead ของ ptrace เข้าไปด้วย ไม่ใช่เวลาจริงของ syscall ในระบบเปล่าๆ

---

## 6. ข้อจำกัด
- รองรับเฉพาะ Linux x86_64; decode เฉพาะ syscall ที่ใช้บ่อย นอกนั้นแสดง `syscall_N` + hex
- ไม่ decode struct (`stat`, `sockaddr`) แสดงเป็น pointer เช่น `fstat(3, 0x7ffe...)` และ `connect(3, 0x7ffc..., 16)` จึงไม่เห็นว่า connect ไปที่ IP/port ใด
- ไม่รองรับ multi-thread เต็มรูปแบบ
- การจำแนก I/O-bound / CPU-bound เป็น heuristic (เกณฑ์ 20%, 2000 syscall/s และ 50% เป็นค่าที่ตั้งจากการทดลอง) และเวลาที่วัดรวม overhead ของ ptrace
- โปรแกรมที่รันสั้นมากจะถูกครอบงำด้วย syscall ตอนเริ่มโปรแกรม (dynamic loader, locale) ทำให้ผลจำแนกคลาดเคลื่อนได้ ตัวอย่างคือ test_suspicious ถูกจัดเป็น I/O-bound ทั้งที่ส่วนใหญ่เป็นการโหลดไฟล์ locale ของ `echo` ไม่ใช่งาน I/O จริงของโปรแกรม
- กฎ alert เป็นแบบ pattern ตายตัว (path, จำนวนครั้ง) ไม่ใช่การวิเคราะห์เชิงลึก

---

## 7. แนวทางพัฒนาต่อ
- ใช้ `PTRACE_GET_SYSCALL_INFO` แทนการอ่าน register เอง
- decode `sockaddr` (แสดง IP:port) และ `stat` รวมถึง flag ของ `clone`/`mmap`
- เพิ่ม filter (`-e trace=open`) เพื่อเลือกดูเฉพาะ syscall ที่สนใจ
- รองรับ ARM64
- ใช้ seccomp-bpf เพื่อลด overhead โดยให้ kernel หยุด tracee เฉพาะ syscall ที่ต้องการดัก

---

## 8. สรุปและอ้างอิง

**สรุป:** โปรเจกต์สร้าง System Call Tracer บน Linux x86_64 ด้วย `ptrace` ที่ดัก syscall ของโปรแกรมเป้าหมาย แสดงชื่อ argument และค่าที่คืนพร้อม errno และวิเคราะห์พฤติกรรมได้ ผลทดสอบให้ผลตรงตามที่คาด และเทียบกับ `strace -c` แล้วจำนวน syscall กับ error ตรงกันทุกตัว (ต่างเฉพาะ `exit_group`): `test_io` เป็น I/O-bound, `test_cpu` เป็น CPU-bound, `test_fork` เห็นวงจร clone–wait4–SIGCHLD และ `test_suspicious` ถูกแจ้งเตือนครบ 4 รายการ ระหว่างทดสอบพบปัญหา 2 เรื่อง คือ การจำแนก workload ต้องหักเวลา `execve` ตอนเริ่มโปรแกรมและใช้อัตราการเรียก syscall ประกอบ จึงจะได้ผลที่นิ่ง และ state ของ process ลูกตอนใช้ `-f` เริ่มผิดจังหวะทำให้ syscall ของลูกถูกบันทึกเป็น ENOSYS ซึ่งแก้แล้ว ส่วนข้อจำกัดคือ heuristic ยังไม่แม่นกับโปรแกรมที่รันสั้นมาก และ overhead ของ ptrace มีผลต่อเวลาที่วัดได้

**อ้างอิง**
- `man 2 ptrace`, `man 2 syscalls`, `man 2 waitpid`
- ซอร์สและเอกสารของ `strace`
- Silberschatz, Galvin, Gagne. *Operating System Concepts*. (บทเรื่อง System Calls / OS Structure)
- เอกสารประกอบวิชา Operating Systems
