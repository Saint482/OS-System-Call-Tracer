/*
 * tracer.c - System Call Tracer (Linux x86_64, ptrace)
 * Phase 2: core loop      (fork / PTRACE_TRACEME / PTRACE_SYSCALL / waitpid)
 * Phase 3: decode         (ชื่อ syscall, argument, return value, errno, อ่าน memory ของ tracee)
 * Phase 4: analysis       (สถิติ, I/O-bound vs CPU-bound, ตรวจพฤติกรรมน่าสงสัย)
 *
 * ใช้: ./tracer [-c] [-f] [-o file] <program> [args...]
 *   -c  แสดงเฉพาะ summary (ไม่ print log ทีละ syscall)
 *   -f  ตาม trace process ลูก (fork/vfork/clone)
 *   -o  เขียน log ลงไฟล์ (default = stderr)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>

#ifndef __x86_64__
#error "รองรับเฉพาะ x86_64 (register layout ต่างกันในแต่ละสถาปัตยกรรม)"
#endif

#define MAXNR    512
#define MAXPROC  1024
#define STR_MAX  64     /* ความยาว string สูงสุดที่แสดง */
#define BUF_MAX  32     /* จำนวน byte ของ buffer ที่แสดง */
#define MAXALERT 64

/* ====================== Phase 3: ตาราง syscall ======================
 * spec ของ argument:
 *  d=int  D=dirfd  l=long  u=unsigned  x=hex  m=mode  p=pointer
 *  f=open flags  s=string(path)  w=buffer(ความยาว=arg ถัดไป)  r=buffer(ความยาว=return value)
 */
enum { C_OTHER, C_FILE, C_MEM, C_PROC, C_NET, C_NCAT };
static const char *cat_name[C_NCAT] = { "other", "file I/O", "memory", "process", "network" };

struct sc_info { const char *name; const char *args; int cat; };

#define S(nr, n, a, c) [nr] = { n, a, c }
static const struct sc_info table[MAXNR] = {
    /* file I/O */
    S(SYS_read, "read", "dru", C_FILE),
    S(SYS_write, "write", "dwu", C_FILE),
    S(SYS_open, "open", "sfm", C_FILE),
    S(SYS_openat, "openat", "Dsfm", C_FILE),
    S(SYS_close, "close", "d", C_FILE),
    S(SYS_stat, "stat", "sp", C_FILE),
    S(SYS_fstat, "fstat", "dp", C_FILE),
    S(SYS_lstat, "lstat", "sp", C_FILE),
    S(SYS_newfstatat, "newfstatat", "Dspx", C_FILE),
    S(SYS_lseek, "lseek", "dlu", C_FILE),
    S(SYS_pread64, "pread64", "druu", C_FILE),
    S(SYS_pwrite64, "pwrite64", "dwuu", C_FILE),
    S(SYS_ioctl, "ioctl", "dxx", C_FILE),
    S(SYS_access, "access", "sx", C_FILE),
    S(SYS_faccessat, "faccessat", "Dsx", C_FILE),
    S(SYS_pipe, "pipe", "p", C_FILE),
    S(SYS_pipe2, "pipe2", "px", C_FILE),
    S(SYS_dup, "dup", "d", C_FILE),
    S(SYS_dup2, "dup2", "dd", C_FILE),
    S(SYS_dup3, "dup3", "ddx", C_FILE),
    S(SYS_fcntl, "fcntl", "dxx", C_FILE),
    S(SYS_getcwd, "getcwd", "pu", C_FILE),
    S(SYS_chdir, "chdir", "s", C_FILE),
    S(SYS_mkdir, "mkdir", "sm", C_FILE),
    S(SYS_rmdir, "rmdir", "s", C_FILE),
    S(SYS_unlink, "unlink", "s", C_FILE),
    S(SYS_unlinkat, "unlinkat", "Dsx", C_FILE),
    S(SYS_rename, "rename", "ss", C_FILE),
    S(SYS_readlink, "readlink", "spu", C_FILE),
    S(SYS_readlinkat, "readlinkat", "Dspu", C_FILE),
    S(SYS_getdents64, "getdents64", "dpu", C_FILE),
    S(SYS_chmod, "chmod", "sm", C_FILE),
    S(SYS_ftruncate, "ftruncate", "du", C_FILE),
    S(SYS_fsync, "fsync", "d", C_FILE),
    S(SYS_poll, "poll", "pud", C_FILE),
    S(SYS_select, "select", "dpppp", C_FILE),
    S(SYS_epoll_create1, "epoll_create1", "x", C_FILE),
    S(SYS_epoll_ctl, "epoll_ctl", "dddp", C_FILE),
    S(SYS_epoll_wait, "epoll_wait", "dpdd", C_FILE),
#ifdef SYS_statx
    S(SYS_statx, "statx", "Dsxxp", C_FILE),
#endif
    /* memory */
    S(SYS_mmap, "mmap", "puxxdx", C_MEM),
    S(SYS_mprotect, "mprotect", "pux", C_MEM),
    S(SYS_munmap, "munmap", "pu", C_MEM),
    S(SYS_mremap, "mremap", "puuxp", C_MEM),
    S(SYS_brk, "brk", "p", C_MEM),
    /* process */
    S(SYS_fork, "fork", "", C_PROC),
    S(SYS_vfork, "vfork", "", C_PROC),
    S(SYS_clone, "clone", "xxppx", C_PROC),
#ifdef SYS_clone3
    S(SYS_clone3, "clone3", "pu", C_PROC),
#endif
    S(SYS_execve, "execve", "spp", C_PROC),
    S(SYS_exit, "exit", "d", C_PROC),
    S(SYS_exit_group, "exit_group", "d", C_PROC),
    S(SYS_wait4, "wait4", "dpxp", C_PROC),
    S(SYS_kill, "kill", "dd", C_PROC),
    S(SYS_getpid, "getpid", "", C_PROC),
    S(SYS_getppid, "getppid", "", C_PROC),
    S(SYS_gettid, "gettid", "", C_PROC),
    S(SYS_ptrace, "ptrace", "lddp", C_PROC),
    /* network */
    S(SYS_socket, "socket", "ddd", C_NET),
    S(SYS_connect, "connect", "dpu", C_NET),
    S(SYS_accept, "accept", "dpp", C_NET),
    S(SYS_bind, "bind", "dpu", C_NET),
    S(SYS_listen, "listen", "dd", C_NET),
    S(SYS_sendto, "sendto", "dwuxpu", C_NET),
    S(SYS_recvfrom, "recvfrom", "druxpp", C_NET),
    S(SYS_sendmsg, "sendmsg", "dpx", C_NET),
    S(SYS_recvmsg, "recvmsg", "dpx", C_NET),
    S(SYS_shutdown, "shutdown", "dd", C_NET),
    /* other */
    S(SYS_rt_sigaction, "rt_sigaction", "dppu", C_OTHER),
    S(SYS_rt_sigprocmask, "rt_sigprocmask", "dppu", C_OTHER),
    S(SYS_rt_sigreturn, "rt_sigreturn", "", C_OTHER),
    S(SYS_nanosleep, "nanosleep", "pp", C_OTHER),
    S(SYS_sched_yield, "sched_yield", "", C_OTHER),
    S(SYS_uname, "uname", "p", C_OTHER),
    S(SYS_umask, "umask", "m", C_OTHER),
    S(SYS_gettimeofday, "gettimeofday", "pp", C_OTHER),
    S(SYS_clock_gettime, "clock_gettime", "dp", C_OTHER),
    S(SYS_futex, "futex", "pxxppx", C_OTHER),
    S(SYS_arch_prctl, "arch_prctl", "xx", C_OTHER),
    S(SYS_set_tid_address, "set_tid_address", "p", C_OTHER),
    S(SYS_set_robust_list, "set_robust_list", "pu", C_OTHER),
    S(SYS_prlimit64, "prlimit64", "dxpp", C_OTHER),
    S(SYS_getuid, "getuid", "", C_OTHER),
    S(SYS_getgid, "getgid", "", C_OTHER),
    S(SYS_geteuid, "geteuid", "", C_OTHER),
    S(SYS_getegid, "getegid", "", C_OTHER),
#ifdef SYS_getrandom
    S(SYS_getrandom, "getrandom", "pux", C_OTHER),
#endif
#ifdef SYS_rseq
    S(SYS_rseq, "rseq", "puxx", C_OTHER),
#endif
};

static const char *errname(int e)
{
    switch (e) {
#define E(x) case x: return #x;
    E(EPERM) E(ENOENT) E(ESRCH) E(EINTR) E(EIO) E(ENXIO) E(E2BIG) E(ENOEXEC)
    E(EBADF) E(ECHILD) E(EAGAIN) E(ENOMEM) E(EACCES) E(EFAULT) E(EBUSY)
    E(EEXIST) E(ENOTDIR) E(EISDIR) E(EINVAL) E(ENFILE) E(EMFILE) E(ENOTTY)
    E(EFBIG) E(ENOSPC) E(ESPIPE) E(EROFS) E(EPIPE) E(ERANGE) E(ENOSYS)
    E(ENOTEMPTY) E(ECONNREFUSED) E(ETIMEDOUT) E(ENOTSOCK) E(EADDRINUSE)
#undef E
    default: return "E?";
    }
}

static const char *sc_name(long nr, char *buf, size_t n)
{
    if (nr >= 0 && nr < MAXNR && table[nr].name)
        return table[nr].name;
    snprintf(buf, n, "syscall_%ld", nr);
    return buf;
}

/* ====================== state ====================== */
struct proc {
    pid_t pid;
    int used, in_syscall, started, primed;
    struct user_regs_struct entry;   /* register ตอนเข้า syscall */
    struct timespec t0;              /* เวลาเข้า syscall */
    char *argstr;                    /* argument ที่ format ไว้ตอน entry */
    char path[256];                  /* path แรกที่เจอใน argument (ไว้ตรวจ alert) */
};

struct stat_ent { long calls, errors; double time; };

static FILE *out;
static int opt_follow, opt_summary_only;
static struct proc procs[MAXPROC];
static struct stat_ent stats[MAXNR];
static char alerts[MAXALERT][300];
static int nalerts, perm_denied, exec_count;
static int startup_exec_seen;      /* เจอ execve ตัวแรก (kernel โหลดโปรแกรมเป้าหมาย) แล้วหรือยัง */
static double startup_exec_time;   /* เวลาของ execve ตัวแรก: หักออกตอนจำแนก workload */

static struct proc *get_proc(pid_t pid, int create)
{
    struct proc *free_slot = NULL;
    for (int i = 0; i < MAXPROC; i++) {
        if (procs[i].used && procs[i].pid == pid) return &procs[i];
        if (!procs[i].used && !free_slot) free_slot = &procs[i];
    }
    if (!create || !free_slot) return NULL;
    memset(free_slot, 0, sizeof *free_slot);
    free_slot->used = 1;
    free_slot->pid = pid;
    return free_slot;
}

static void release_proc(struct proc *p)
{
    free(p->argstr);
    memset(p, 0, sizeof *p);
}

static double elapsed(const struct timespec *a, const struct timespec *b)
{
    return (b->tv_sec - a->tv_sec) + (b->tv_nsec - a->tv_nsec) / 1e9;
}

/* ====================== Phase 3: อ่าน memory ของ tracee ====================== */
/* อ่านทีละ word แบบ align เพื่อไม่ข้ามหน้า memory ที่ map ไม่ถึง */
static size_t read_mem(pid_t pid, unsigned long addr, char *dst, size_t n)
{
    size_t done = 0;
    while (done < n) {
        unsigned long a = addr + done, base = a & ~7UL;
        errno = 0;
        long w = ptrace(PTRACE_PEEKDATA, pid, (void *)base, NULL);
        if (errno) break;
        size_t off = a - base, c = 8 - off;
        if (c > n - done) c = n - done;
        memcpy(dst + done, (char *)&w + off, c);
        done += c;
    }
    return done;
}

/* คืนความยาว string (ไม่รวม NUL), -1 ถ้าอ่านไม่ได้เลย; dst ต้องมีขนาด max+1 */
static long read_str(pid_t pid, unsigned long addr, char *dst, size_t max)
{
    size_t n = 0;
    while (n < max) {
        unsigned long a = addr + n;
        size_t c = 8 - (a & 7);
        if (c > max - n) c = max - n;
        size_t got = read_mem(pid, a, dst + n, c);
        for (size_t k = 0; k < got; k++)
            if (dst[n + k] == '\0') return (long)(n + k);
        n += got;
        if (got < c) break;
    }
    if (n == 0) return -1;
    dst[n] = '\0';
    return (long)n;
}

static void put_escaped(FILE *f, const char *b, size_t n)
{
    fputc('"', f);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = b[i];
        switch (c) {
        case '\n': fputs("\\n", f); break;
        case '\t': fputs("\\t", f); break;
        case '\r': fputs("\\r", f); break;
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        default:
            if (c >= 32 && c < 127) fputc(c, f);
            else fprintf(f, "\\%o", c);
        }
    }
    fputc('"', f);
}

static void put_ptr(FILE *f, unsigned long v)
{
    if (v) fprintf(f, "0x%lx", v); else fputs("NULL", f);
}

static void put_buf(FILE *f, pid_t pid, unsigned long addr, unsigned long len)
{
    char tmp[BUF_MAX];
    size_t want = len < BUF_MAX ? len : BUF_MAX;
    size_t got = addr ? read_mem(pid, addr, tmp, want) : 0;
    if (got == 0) { put_ptr(f, addr); return; }
    put_escaped(f, tmp, got);
    if (len > BUF_MAX) fputs("...", f);
}

/* คืน 1 ถ้ามี O_CREAT (ไว้ตัดสินว่าจะแสดง mode ไหม) */
static int put_open_flags(FILE *f, unsigned long fl)
{
    static const struct { unsigned long v; const char *n; } fs[] = {
        { O_CREAT, "O_CREAT" }, { O_EXCL, "O_EXCL" }, { O_TRUNC, "O_TRUNC" },
        { O_APPEND, "O_APPEND" }, { O_NONBLOCK, "O_NONBLOCK" },
        { O_DIRECTORY, "O_DIRECTORY" }, { O_NOFOLLOW, "O_NOFOLLOW" },
        { O_CLOEXEC, "O_CLOEXEC" },
    };
    switch (fl & O_ACCMODE) {
    case O_RDONLY: fputs("O_RDONLY", f); break;
    case O_WRONLY: fputs("O_WRONLY", f); break;
    case O_RDWR:   fputs("O_RDWR", f); break;
    default:       fprintf(f, "0x%lx", fl & O_ACCMODE);
    }
    for (size_t i = 0; i < sizeof fs / sizeof fs[0]; i++)
        if (fl & fs[i].v) fprintf(f, "|%s", fs[i].n);
    return (fl & O_CREAT) != 0;
}

/* format argument ของ syscall ลง f; pathout เก็บ string แรกที่เจอ */
static void format_args(FILE *f, pid_t pid, const struct user_regs_struct *r,
                        long ret, int at_exit, char *pathout)
{
    unsigned long a[6] = { r->rdi, r->rsi, r->rdx, r->r10, r->r8, r->r9 };
    long nr = (long)r->orig_rax;

    if (nr < 0 || nr >= MAXNR || !table[nr].name) {
        for (int i = 0; i < 6; i++) fprintf(f, "%s0x%lx", i ? ", " : "", a[i]);
        return;
    }
    const char *spec = table[nr].args;
    size_t n = strlen(spec);
    int creat = 1, first = 1;

    for (size_t i = 0; i < n; i++) {
        char t = spec[i];
        if (t == 'm' && !creat) continue;      /* open ที่ไม่มี O_CREAT ไม่แสดง mode */
        if (!first) fputs(", ", f);
        first = 0;
        switch (t) {
        case 'd': fprintf(f, "%d", (int)a[i]); break;
        case 'D':
            if ((int)a[i] == AT_FDCWD) fputs("AT_FDCWD", f);
            else fprintf(f, "%d", (int)a[i]);
            break;
        case 'l': fprintf(f, "%ld", (long)a[i]); break;
        case 'u': fprintf(f, "%lu", a[i]); break;
        case 'x': fprintf(f, "0x%lx", a[i]); break;
        case 'm': fprintf(f, "0%lo", a[i]); break;
        case 'p': put_ptr(f, a[i]); break;
        case 'f': creat = put_open_flags(f, a[i]); break;
        case 's': {
            char tmp[STR_MAX + 1];
            long len = a[i] ? read_str(pid, a[i], tmp, STR_MAX) : -1;
            if (len < 0) { put_ptr(f, a[i]); break; }
            put_escaped(f, tmp, (size_t)len);
            if (len == STR_MAX) fputs("...", f);
            if (pathout && !pathout[0]) {
                strncpy(pathout, tmp, 255);
                pathout[255] = '\0';
            }
            break;
        }
        case 'w': put_buf(f, pid, a[i], a[i + 1]); break;
        case 'r':
            if (at_exit && ret > 0) put_buf(f, pid, a[i], (unsigned long)ret);
            else put_ptr(f, a[i]);
            break;
        }
    }
}

static void format_ret(char *buf, size_t n, long nr, long ret)
{
    if (ret < 0 && ret >= -4095 && -ret < 512)
        snprintf(buf, n, "-1 %s (%s)", errname((int)-ret), strerror((int)-ret));
    else if (nr == SYS_mmap || nr == SYS_brk || nr == SYS_mremap)
        snprintf(buf, n, "0x%lx", ret);
    else
        snprintf(buf, n, "%ld", ret);
}

static void log_line(struct proc *p, long nr, const char *args, const char *ret)
{
    if (opt_summary_only) return;
    char nb[32];
    if (opt_follow) fprintf(out, "[pid %d] ", p->pid);
    fprintf(out, "%s(%s) = %s\n", sc_name(nr, nb, sizeof nb), args, ret);
}

/* ====================== Phase 4: analysis ====================== */
static void add_alert(const char *fmt, ...)
{
    char msg[300];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    for (int i = 0; i < nalerts; i++)
        if (!strcmp(alerts[i], msg)) return;      /* ไม่ซ้ำ */
    if (nalerts < MAXALERT) strcpy(alerts[nalerts++], msg);
}

static void check_alerts(struct proc *p, long nr, long ret)
{
    const char *path = p->path;
    if (path[0] &&
        (!strncmp(path, "/etc/shadow", 11) || !strncmp(path, "/etc/passwd", 11) ||
         strstr(path, "/.ssh/") || (strstr(path, "/proc/") && strstr(path, "/mem"))))
        add_alert("เข้าถึงไฟล์อ่อนไหว: %s (pid %d)", path, p->pid);

    if (ret == -EACCES || ret == -EPERM) {
        if (++perm_denied == 3)
            add_alert("Permission denied ซ้ำ >= 3 ครั้ง (อาจพยายามเข้าถึงสิ่งที่ไม่มีสิทธิ์)");
    }
    if (nr == SYS_execve && ret == 0 && ++exec_count > 1)
        add_alert("exec โปรแกรมอื่นระหว่างรัน: %s (pid %d)", path, p->pid);
    if (nr == SYS_connect)
        add_alert("พยายามเชื่อมต่อ network (connect) (pid %d)", p->pid);
    if (nr == SYS_ptrace)
        add_alert("เรียก ptrace เอง (อาจเป็น anti-debug / debugger) (pid %d)", p->pid);
}

static void account(long nr, double dt, int is_err)
{
    int idx = (nr >= 0 && nr < MAXNR) ? (int)nr : MAXNR - 1;
    stats[idx].calls++;
    stats[idx].time += dt;
    if (is_err) stats[idx].errors++;
}

static int cmp_stat(const void *a, const void *b)
{
    double ta = stats[*(const int *)a].time, tb = stats[*(const int *)b].time;
    return (ta < tb) - (ta > tb);
}

static void print_summary(double wall)
{
    int idx[MAXNR], m = 0;
    double total = 0, cat_time[C_NCAT] = { 0 };
    long total_calls = 0, cat_calls[C_NCAT] = { 0 }, total_err = 0;

    for (int i = 0; i < MAXNR; i++) {
        if (!stats[i].calls) continue;
        idx[m++] = i;
        int c = (table[i].name) ? table[i].cat : C_OTHER;
        total += stats[i].time;
        total_calls += stats[i].calls;
        total_err += stats[i].errors;
        cat_time[c] += stats[i].time;
        cat_calls[c] += stats[i].calls;
    }
    qsort(idx, m, sizeof idx[0], cmp_stat);

    fprintf(out, "\n===== Syscall Summary =====\n");
    fprintf(out, "%6s %11s %11s %9s %9s %s\n",
            "% time", "seconds", "usecs/call", "calls", "errors", "syscall");
    fprintf(out, "------ ----------- ----------- --------- --------- ----------------\n");
    for (int k = 0; k < m; k++) {
        int i = idx[k];
        char nb[32];
        fprintf(out, "%6.2f %11.6f %11.0f %9ld %9ld %s\n",
                total > 0 ? 100.0 * stats[i].time / total : 0.0, stats[i].time,
                stats[i].time / stats[i].calls * 1e6, stats[i].calls, stats[i].errors,
                sc_name(i, nb, sizeof nb));
    }
    fprintf(out, "------ ----------- ----------- --------- --------- ----------------\n");
    fprintf(out, "%6.2f %11.6f %11s %9ld %9ld total\n", 100.0, total, "", total_calls, total_err);

    /* หัก execve ตัวแรก (ตอนโหลดโปรแกรม) ออกก่อนแยกประเภท/จำแนก workload
     * ไม่งั้นหมวด process จะพองและผลแกว่งตามความเร็วของ kernel ตอนโหลดไฟล์ */
    double adj_total = total - startup_exec_time;
    long adj_calls = total_calls - startup_exec_seen;
    cat_time[C_PROC] -= startup_exec_time;
    cat_calls[C_PROC] -= startup_exec_seen;

    fprintf(out, "\n----- แยกตามประเภท (ไม่นับ execve ตอนเริ่มโปรแกรม) -----\n");
    for (int c = 0; c < C_NCAT; c++)
        if (cat_calls[c])
            fprintf(out, "%-10s calls=%-7ld time=%.6fs (%.1f%%)\n", cat_name[c],
                    cat_calls[c], cat_time[c], adj_total > 0 ? 100.0 * cat_time[c] / adj_total : 0.0);

    /* จำแนก workload แบบ heuristic */
    double sys_ratio = wall > 0 ? adj_total / wall : 0;
    double rate = wall > 0 ? adj_calls / wall : 0;     /* syscall ต่อวินาที */
    double io_ratio = adj_total > 0 ? (cat_time[C_FILE] + cat_time[C_NET]) / adj_total : 0;
    const char *verdict;
    /* CPU-bound ต้อง "เวลาใน syscall น้อย" และ "เรียก syscall ไม่ถี่" ทั้งคู่
     * (ใช้ sys_ratio อย่างเดียวไม่ได้ เพราะ overhead ของ ptrace ตอนหยุดทุก syscall
     *  ไปอยู่นอกช่วงที่วัด ทำให้โปรแกรมที่ทำ I/O ถี่ๆ ดูเหมือนใช้ CPU) */
    if (sys_ratio < 0.2 && rate < 2000)
                               verdict = "CPU-bound (เวลาส่วนใหญ่อยู่ใน user space)";
    else if (io_ratio > 0.5)   verdict = "I/O-bound (เวลาส่วนใหญ่อยู่กับ file/network syscall)";
    else                       verdict = "Mixed / waiting-bound (รอ process, lock หรือ sleep)";
    fprintf(out, "\n----- การจำแนก workload (heuristic) -----\n");
    fprintf(out, "wall time = %.6fs | เวลาใน syscall = %.6fs (%.1f%% ของ wall) | %.0f syscall/s\n",
            wall, adj_total, sys_ratio * 100, rate);
    fprintf(out, "สัดส่วน I/O ในเวลา syscall = %.1f%%  =>  %s\n", io_ratio * 100, verdict);
    fprintf(out, "(หมายเหตุ: เวลาที่วัดรวม overhead ของ ptrace ด้วย)\n");

    fprintf(out, "\n----- Alerts (พฤติกรรมน่าสงสัย) -----\n");
    if (!nalerts) fprintf(out, "ไม่พบ\n");
    for (int i = 0; i < nalerts; i++) fprintf(out, "[!] %s\n", alerts[i]);
}

/* ====================== Phase 2: core handlers ====================== */
static void on_entry(struct proc *p)
{
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, p->pid, NULL, &r) < 0) return;
    p->entry = r;
    clock_gettime(CLOCK_MONOTONIC, &p->t0);
    p->path[0] = '\0';
    free(p->argstr);
    p->argstr = NULL;

    /* format argument ตอน entry เพราะ memory (เช่น path ของ execve) จะหายหลัง exec */
    size_t len;
    FILE *f = open_memstream(&p->argstr, &len);
    if (f) { format_args(f, p->pid, &r, 0, 0, p->path); fclose(f); }

    long nr = (long)r.orig_rax;
    if (nr == SYS_exit || nr == SYS_exit_group) {   /* ไม่มี syscall-exit stop */
        log_line(p, nr, p->argstr ? p->argstr : "", "?");
        account(nr, 0, 0);
        return;
    }
    p->in_syscall = 1;
}

static void on_exit_stop(struct proc *p)
{
    struct user_regs_struct r;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    p->in_syscall = 0;
    if (ptrace(PTRACE_GETREGS, p->pid, NULL, &r) < 0) return;

    long nr = (long)p->entry.orig_rax;
    long ret = (long)r.rax;
    int is_err = (ret < 0 && ret >= -4095 && -ret < 512);

    /* read/recv: buffer เพิ่งถูกเติมตอน exit จึง format ใหม่ */
    if (nr >= 0 && nr < MAXNR && table[nr].name && strchr(table[nr].args, 'r') && ret > 0) {
        size_t len;
        char *s = NULL;
        FILE *f = open_memstream(&s, &len);
        if (f) {
            format_args(f, p->pid, &p->entry, ret, 1, NULL);
            fclose(f);
            free(p->argstr);
            p->argstr = s;
        }
    }

    char rb[160];
    format_ret(rb, sizeof rb, nr, ret);
    log_line(p, nr, p->argstr ? p->argstr : "", rb);
    double dt = elapsed(&p->t0, &now);
    account(nr, dt, is_err);
    if (nr == SYS_execve && ret == 0 && !startup_exec_seen) {
        startup_exec_seen = 1;      /* execve ตัวแรก = ตอนเปิดโปรแกรม ไม่ใช่พฤติกรรมของโปรแกรม */
        startup_exec_time = dt;
    }
    check_alerts(p, nr, ret);
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-c] [-f] [-o file] <program> [args...]\n", prog);
    exit(1);
}

int main(int argc, char *argv[])
{
    int opt;
    out = stderr;
    while ((opt = getopt(argc, argv, "+o:cf")) != -1) {
        switch (opt) {
        case 'o': out = fopen(optarg, "w");
                  if (!out) { perror("fopen"); return 1; }
                  break;
        case 'c': opt_summary_only = 1; break;
        case 'f': opt_follow = 1; break;
        default:  usage(argv[0]);
        }
    }
    if (optind >= argc) usage(argv[0]);

    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (child == 0) {
        /* ---- tracee ---- */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);                    /* หยุดรอ tracer ตั้ง option ก่อน */
        execvp(argv[optind], &argv[optind]);
        perror("execvp");
        _exit(127);
    }

    /* ---- tracer ---- */
    int status;
    waitpid(child, &status, 0);            /* รอ SIGSTOP จาก child */
    long opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL;
    if (opt_follow)
        opts |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE;
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, opts) < 0) {
        perror("PTRACE_SETOPTIONS");
        return 1;
    }
    struct proc *root = get_proc(child, 1);
    root->started = root->primed = 1;
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);

    int exit_code = 0;
    for (;;) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == EINTR) continue;
            break;                          /* ECHILD: ไม่เหลือ process แล้ว */
        }
        struct proc *p = get_proc(pid, 1);
        if (!p) continue;

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (!opt_summary_only) {
                if (opt_follow) fprintf(out, "[pid %d] ", pid);
                if (WIFEXITED(status))
                    fprintf(out, "+++ exited with %d +++\n", WEXITSTATUS(status));
                else
                    fprintf(out, "+++ killed by %s +++\n", strsignal(WTERMSIG(status)));
            }
            if (pid == child)
                exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
            release_proc(p);
            continue;
        }
        if (!WIFSTOPPED(status)) continue;

        int sig = WSTOPSIG(status), deliver = 0, event = status >> 16;

        if (sig == (SIGTRAP | 0x80)) {                    /* syscall stop */
            if (!p->in_syscall) on_entry(p); else on_exit_stop(p);
        } else if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
                   event == PTRACE_EVENT_CLONE) {
            unsigned long np = 0;
            ptrace(PTRACE_GETEVENTMSG, pid, NULL, &np);
            struct proc *c = get_proc((pid_t)np, 1);
            if (c) {
                /* stop แรกของลูกที่ถูก trace ผ่าน PTRACE_EVENT_* คือ syscall-ENTRY ของ syscall
                 * แรกที่ลูกเรียกเอง (ไม่มี syscall-exit ของ clone ฝั่งลูก) จึงต้องเริ่มที่ in_syscall = 0
                 * ถ้าตั้งเป็น 1 ทุก stop จะสลับ enter/exit ผิดหนึ่งจังหวะ -> ทุก syscall ของลูกได้ ENOSYS
                 * และ exit_group ของลูกไม่ถูกบันทึก */
                c->in_syscall = 0;
                c->primed = 1;
                if (c->started) ptrace(PTRACE_SYSCALL, (pid_t)np, NULL, NULL);
            }
        } else if (sig == SIGTRAP) {
            /* SIGTRAP หลัง execve สำเร็จ: ไม่ต้อง deliver */
        } else if (sig == SIGSTOP && !p->started) {       /* stop แรกของ process ลูก */
            p->started = 1;
            if (!p->primed) continue;                      /* รอ event จากพ่อก่อนค่อยปล่อย */
        } else {                                           /* signal-delivery-stop */
            if (!opt_summary_only) {
                if (opt_follow) fprintf(out, "[pid %d] ", pid);
                fprintf(out, "--- %s ---\n", strsignal(sig));
            }
            deliver = sig;
        }
        ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(long)deliver);
    }

    clock_gettime(CLOCK_MONOTONIC, &t_end);
    print_summary(elapsed(&t_start, &t_end));
    if (out != stderr) fclose(out);
    return exit_code;
}
