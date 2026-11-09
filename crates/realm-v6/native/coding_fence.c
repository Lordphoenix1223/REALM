/* Coding-only pre-VMM stage. Fixed Linux UAPI; no runtime policy/test flag.
 * Parent must witness this exact ELF at exec-stop, protect the jail, and bind
 * the subsequent official VMM exec. Successful installation alone is NOT a
 * qualified runtime. All errors terminate before the VMM is executed. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

struct ll_ruleset { uint64_t fs, net; };
struct ll_path { uint64_t access; int32_t parent; } __attribute__((packed));
#define LL_EXEC (1ULL << 0)
#define LL_WRITE (1ULL << 1)
#define LL_READ (1ULL << 2)
#define LL_SOCK (1ULL << 9)
#define LL_IOCTL (1ULL << 15)
static void fail(const char *why) { perror(why); _exit(125); }
static void require(int ok, const char *why) { if (!ok) { errno=EPERM; fail(why); } }

static void leaf(int rules, const char *path, uint64_t rights, int kind) {
    int fd=open(path, O_PATH|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0) fail(path);
    struct stat st;
    if(fstat(fd,&st)) fail("leaf stat");
    require((st.st_mode&S_IFMT)==(unsigned)kind, "leaf kind");
    if(kind==S_IFREG) require(st.st_uid==0 && st.st_gid==0 && !(st.st_mode&0222) && st.st_nlink==1,"immutable input");
    if(kind==S_IFCHR) require(major(st.st_rdev)==10 && minor(st.st_rdev)==232,"KVM device");
    struct ll_path rule={rights,fd};
    if(syscall(SYS_landlock_add_rule,rules,1,&rule,0)) fail("Landlock leaf");
    if(close(fd)) fail("leaf close");
}

/* Called only after fresh exec, single-threaded static startup. The caller
 * supplies no resource allowlist. Fresh exec discards inherited shared maps;
 * close_range discards every inherited FD except the declared stdio sinks. */
int realm_coding_fence_install(void) {
    require(getpid()==1,"isolated PID namespace init required");
    require(getuid()!=0 && getuid()==geteuid() && getgid()!=0 && getgid()==getegid(),"non-root identity");
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct caps[2]={{0},{0}};
    if(syscall(SYS_capget,&header,caps)) fail("capget");
    require(!(caps[0].effective|caps[0].permitted|caps[0].inheritable|caps[1].effective|caps[1].permitted|caps[1].inheritable),"capabilities");
    for(int fd=0;fd<3;fd++) {
        struct stat st;
        if(fstat(fd,&st)) fail("stdio");
        if(fd==0) require(S_ISCHR(st.st_mode)&&major(st.st_rdev)==1&&minor(st.st_rdev)==3,"stdin must be null");
        else require(S_ISREG(st.st_mode)&&st.st_uid==0&&st.st_gid==0&&st.st_nlink==1,"stdio must be owned logs");
    }
    if(syscall(SYS_close_range,3U,~0U,0)) fail("close inherited descriptors");
    if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) fail("no new privileges");
    long abi=syscall(SYS_landlock_create_ruleset,0,0,1);
    if(abi<0) fail("Landlock ABI query");
    require(abi>=3,"Landlock truncation coverage required");
    /* No graceful downgrade: mandatory ABI3 rights. KVM is the sole device;
       ABI5 ioctl mediation adds defense, KVM ioctl type-class restriction below is mandatory. */
    struct ll_ruleset attr={(1ULL<<15)-1,abi>=4?3:0};
    if(abi>=5) attr.fs|=LL_IOCTL;
    int rules=syscall(SYS_landlock_create_ruleset,&attr,abi>=4?sizeof(attr):8,0);
    if(rules<0) fail("Landlock ruleset");
    leaf(rules,"/realm-vmm",LL_READ|LL_EXEC,S_IFREG);
    leaf(rules,"/kernel",LL_READ,S_IFREG);
    leaf(rules,"/rootfs.ext4",LL_READ,S_IFREG);
    leaf(rules,"/dev/kvm",LL_READ|LL_WRITE|(abi>=5?LL_IOCTL:0),S_IFCHR);
    leaf(rules,"/run",LL_SOCK,S_IFDIR);
    if(syscall(SYS_landlock_restrict_self,rules,0)) fail("Landlock restrict");
    if(close(rules)) fail("ruleset close");

    struct sock_filter code[512]; unsigned n=0;
#define EMIT(c,jt,jf,k) do {code[n++]=(struct sock_filter){c,jt,jf,k};} while(0)
#define LOAD(off) EMIT(BPF_LD|BPF_W|BPF_ABS,0,0,off)
#define RET(v) EMIT(BPF_RET|BPF_K,0,0,v)
#define EQ(v,t,f) EMIT(BPF_JMP|BPF_JEQ|BPF_K,t,f,v)
#define ALLOW(nr) do {EQ(SYS_##nr,0,1);RET(SECCOMP_RET_ALLOW);} while(0)
#define ARG(i) LOAD(offsetof(struct seccomp_data,args)+(i)*8)
    LOAD(offsetof(struct seccomp_data,arch));
#if defined(__x86_64__)
    EQ(AUDIT_ARCH_X86_64,1,0);
#elif defined(__aarch64__)
    EQ(AUDIT_ARCH_AARCH64,1,0);
#else
#error Unsupported syscall ABI
#endif
    RET(SECCOMP_RET_KILL_PROCESS);
    LOAD(offsetof(struct seccomp_data,nr));
    /* Each block's miss jump is computed from emitted instructions. */
#define BEGIN_SPECIAL(nr) { unsigned gate=n; EQ(SYS_##nr,0,0);
#define END_SPECIAL() require(n-gate-1<256,"filter jump"); code[gate].jf=(unsigned char)(n-gate-1); } LOAD(offsetof(struct seccomp_data,nr));
#define DENY() RET(SECCOMP_RET_ERRNO|EPERM)
#define REQUIRE_EQ(v) EQ(v,1,0); DENY()
#define ALLOW_VALUE(v) EQ(v,0,1); RET(SECCOMP_RET_ALLOW)
    /* No directory/path-only handles or new regular backing objects can be
       acquired after the stage; Landlock still governs every ordinary open. */
    BEGIN_SPECIAL(openat)
        ARG(2); EMIT(BPF_ALU|BPF_AND|BPF_K,0,0,O_PATH|O_CREAT|O_TRUNC|O_TMPFILE);
        REQUIRE_EQ(0); RET(SECCOMP_RET_ALLOW);
    END_SPECIAL()
#ifdef SYS_open
    BEGIN_SPECIAL(open)
        ARG(1); EMIT(BPF_ALU|BPF_AND|BPF_K,0,0,O_PATH|O_CREAT|O_TRUNC|O_TMPFILE);
        REQUIRE_EQ(0); RET(SECCOMP_RET_ALLOW);
    END_SPECIAL()
#endif
    /* Only shared-thread clone; no process descendants, namespace changes or
       private descriptor tables. Opaque clone3 never executes. */
    BEGIN_SPECIAL(clone3) RET(SECCOMP_RET_ERRNO|ENOSYS); END_SPECIAL()
    BEGIN_SPECIAL(clone)
        LOAD(offsetof(struct seccomp_data,args)+4); REQUIRE_EQ(0);
        ARG(0); EMIT(BPF_ALU|BPF_AND|BPF_K,0,0,CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD);
        REQUIRE_EQ(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD);
        ARG(0); EMIT(BPF_ALU|BPF_AND|BPF_K,0,0,~(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID));
        REQUIRE_EQ(0); RET(SECCOMP_RET_ALLOW);
    END_SPECIAL()
    /* Private NET excludes outside abstract peers. Rooted immutable namespace
       plus the native endpoint owners bounds pathname authority. */
    BEGIN_SPECIAL(socket)
        ARG(0); REQUIRE_EQ(AF_UNIX); ARG(1);
        EMIT(BPF_ALU|BPF_AND|BPF_K,0,0,~(SOCK_CLOEXEC|SOCK_NONBLOCK));
        REQUIRE_EQ(SOCK_STREAM); RET(SECCOMP_RET_ALLOW);
    END_SPECIAL()
    /* The entire KVM ioctl type class, NOT a per-command allowlist. Only the
       KVM device/derived objects, declared logs and UNIX streams are reachable.
       Other devices are excluded by Landlock and fresh FD origin. */
    BEGIN_SPECIAL(ioctl)
        ARG(1); ALLOW_VALUE(0x5421); /* FIONBIO */
        EMIT(BPF_ALU|BPF_AND|BPF_K,0,0,0xff00); REQUIRE_EQ(0xae00);
        RET(SECCOMP_RET_ALLOW);
    END_SPECIAL()
    BEGIN_SPECIAL(fcntl)
        ARG(1); ALLOW_VALUE(F_GETFD); ALLOW_VALUE(F_SETFD); ALLOW_VALUE(F_GETFL);
        ALLOW_VALUE(F_SETFL); ALLOW_VALUE(F_DUPFD); ALLOW_VALUE(F_DUPFD_CLOEXEC); DENY();
    END_SPECIAL()
    /* Exclude FD-producing options such as SO_PEERPIDFD; unknown new options
       do not silently extend the admitted capability set. */
    BEGIN_SPECIAL(getsockopt)
        ARG(1); REQUIRE_EQ(SOL_SOCKET); ARG(2);
        ALLOW_VALUE(SO_ERROR); ALLOW_VALUE(SO_TYPE); ALLOW_VALUE(SO_DOMAIN);
        ALLOW_VALUE(SO_PROTOCOL); ALLOW_VALUE(SO_PEERCRED); ALLOW_VALUE(SO_SNDBUF);
        ALLOW_VALUE(SO_RCVBUF); ALLOW_VALUE(SO_ACCEPTCONN); DENY();
    END_SPECIAL()
    BEGIN_SPECIAL(setsockopt)
        ARG(1); REQUIRE_EQ(SOL_SOCKET); ARG(2);
        ALLOW_VALUE(SO_SNDBUF); ALLOW_VALUE(SO_RCVBUF); ALLOW_VALUE(SO_KEEPALIVE);
        ALLOW_VALUE(SO_RCVTIMEO); ALLOW_VALUE(SO_SNDTIMEO); ALLOW_VALUE(SO_REUSEADDR); DENY();
    END_SPECIAL()
    /* More filters can only reduce this policy; no notification listener or
       privilege-changing prctl is available to the target. */
    BEGIN_SPECIAL(seccomp)
        ARG(0); REQUIRE_EQ(SECCOMP_SET_MODE_FILTER); ARG(1); REQUIRE_EQ(0);
        RET(SECCOMP_RET_ALLOW);
    END_SPECIAL()
    BEGIN_SPECIAL(prctl)
        ARG(0); ALLOW_VALUE(PR_SET_NAME); ALLOW_VALUE(PR_GET_NAME);
        ALLOW_VALUE(PR_SET_NO_NEW_PRIVS); ALLOW_VALUE(PR_SET_SECCOMP); DENY();
    END_SPECIAL()
    /* Official Firecracker v1.17.0 uses SIGABRT=6 and vCPU kick=35.
       getpid()==1 above plus thread-only clone means every reachable target
       belongs to this execution; no external process can acquire a signal. */
    BEGIN_SPECIAL(tkill)
        ARG(1); ALLOW_VALUE(6); ALLOW_VALUE(35); DENY();
    END_SPECIAL()
    ALLOW(read); ALLOW(write); ALLOW(readv); ALLOW(writev); ALLOW(close);
    ALLOW(fstat); ALLOW(newfstatat); ALLOW(statx);
#ifdef SYS_open
    ALLOW(stat); ALLOW(lstat); ALLOW(access);
#endif
    ALLOW(lseek); ALLOW(pread64); ALLOW(pwrite64); ALLOW(fsync); ALLOW(fdatasync);
    ALLOW(mmap); ALLOW(mprotect); ALLOW(munmap); ALLOW(mremap); ALLOW(madvise); ALLOW(brk);
    ALLOW(bind); ALLOW(listen); ALLOW(connect); ALLOW(accept4); ALLOW(getsockname);
    ALLOW(getpeername); ALLOW(shutdown);
    ALLOW(sendto); ALLOW(recvfrom);
    ALLOW(epoll_create1); ALLOW(epoll_ctl); ALLOW(epoll_pwait); ALLOW(eventfd2);
#ifdef SYS_epoll_wait
    ALLOW(epoll_wait);
#endif
    ALLOW(timerfd_create); ALLOW(timerfd_settime); ALLOW(timerfd_gettime);
    ALLOW(clock_gettime); ALLOW(clock_getres); ALLOW(clock_nanosleep); ALLOW(nanosleep); ALLOW(gettimeofday);
    ALLOW(futex); ALLOW(getpid); ALLOW(getppid); ALLOW(gettid);
    ALLOW(getuid); ALLOW(geteuid); ALLOW(getgid); ALLOW(getegid);
    ALLOW(sched_yield); ALLOW(sched_getaffinity); ALLOW(sched_getparam); ALLOW(sched_getscheduler);
    ALLOW(rt_sigaction); ALLOW(rt_sigprocmask); ALLOW(rt_sigreturn); ALLOW(sigaltstack);
    ALLOW(set_tid_address); ALLOW(set_robust_list); ALLOW(rseq); ALLOW(getrandom);
#ifdef SYS_arch_prctl
    ALLOW(arch_prctl);
#endif
    ALLOW(execve); ALLOW(execveat); ALLOW(exit); ALLOW(exit_group);
    /* recvmsg/recvmmsg, memfd, io_uring, process_vm, pidfd_getfd, mount,
       namespace, bpf/perf and SysV IPC calls are absent: default refusal. */
    RET(SECCOMP_RET_ERRNO|EPERM);
    require(n<512,"filter capacity");
    struct sock_fprog program={(unsigned short)n,code};
    if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program)) fail("seccomp install");
    return (int)abi;
}

#ifndef REALM_FENCE_LIBRARY
int main(int argc,char **argv) {
    require(argc>1 && argc<64,"fixed jailer argv");
    realm_coding_fence_install();
    argv[0]="/realm-vmm";
    /* Environment is empty; the sole executable allowed by Landlock is the
       original root-owned, native-measured official VMM. */
    char *empty[]={NULL};
    execve("/realm-vmm",argv,empty);
    fail("official VMM exec");
}
#endif
