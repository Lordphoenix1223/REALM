/* Disposable kernel capability probe, not a jailer or REALM qualification.
 * No vCPU, guest instructions, network interface, credentials or host policy changes.
 * Mutations are confined to fresh private paths and a fresh cgroup subtree.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/kvm.h>
#include <linux/kcmp.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <netinet/in.h>

static char work[4096];
static const char *active_capability = "HOST";
static void quote(const char *s) {
    putchar('"');
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') putchar('\\');
        if ((unsigned char)*s < 32) printf("\\u%04x", (unsigned char)*s);
        else putchar(*s);
    }
    putchar('"');
}
static void result(const char *status, const char *reason, int error) {
    printf("{\"event\":\"capability_result\",\"capability\":"); quote(active_capability);
    printf(",\"status\":"); quote(status); printf(",\"reason\":"); quote(reason);
    printf(",\"errno\":%d}\n", error);
}
static void begin(const char *name) {
    active_capability = name; errno = 0;
    printf("{\"event\":\"capability_started\",\"capability\":"); quote(name); puts("}");
}
static void passed(void) { result("PASS", "required behavior observed", 0); }
static void unsupported(const char *why) { result("UNSUPPORTED", why, 0); _exit(78); }
static const char *error_status(int error) {
    if (error == ENOSYS || error == EOPNOTSUPP || error == ENODEV) return "UNSUPPORTED";
    if (error == ENOENT && (!strcmp(active_capability, "KVM") ||
                           !strcmp(active_capability, "CGROUPS"))) return "UNSUPPORTED";
    return "FAIL"; /* EPERM/EACCES are denials, not absent kernel features. */
}
static void need(int ok, const char *why) {
    if (!ok) { int error = errno; result(error_status(error), why, error);
        fprintf(stderr, "%s: %s\n", why, strerror(error)); _exit(1); }
}
static int read_text(const char *path, char *out, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, out, size - 1);
    int saved = errno; close(fd); errno = saved;
    if (n < 0) return -1;
    out[n] = 0; return 0;
}
static int write_text(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = write(fd, text, strlen(text));
    int saved = errno; close(fd); errno = saved;
    return n == (ssize_t)strlen(text) ? 0 : -1;
}
static int killed_and_reaped(pid_t pid) {
    int fd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (fd < 0) return -1;
    int sent = (int)syscall(SYS_pidfd_send_signal, fd, SIGKILL, NULL, 0);
    close(fd);
    int status = 0;
    if (sent || waitpid(pid, &status, 0) != pid) return -1;
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ? 0 : -1;
}
static void kvm_probe(void) {
    begin("KVM");
    int fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    need(fd >= 0, "open KVM without ACL or device changes");
    int api = ioctl(fd, KVM_GET_API_VERSION, 0);
    need(api >= 0, "KVM API query");
    printf("{\"detail\":\"kvm_api_version\",\"value\":%d}\n", api);
    if (api != 12) unsupported("KVM API12 required");
    int vm = ioctl(fd, KVM_CREATE_VM, 0);
    need(vm >= 0, "create empty KVM object; no vCPU or guest");
    need(close(vm) == 0 && close(fd) == 0, "close empty KVM object");
    puts("{\"observation\":\"kvm\",\"api\":12,\"empty_vm_created_and_closed\":true,\"vcpu_created\":false,\"guest_executed\":false}");
    passed();
}
static void ptrace_probe(void) {
    begin("PTRACE_WAITID");
    int held = open("/bin/true", O_RDONLY | O_CLOEXEC);
    struct stat expected, actual;
    need(held >= 0 && fstat(held, &expected) == 0, "hold diagnostic ELF");
    pid_t pid = fork(); need(pid >= 0, "fork ptrace child");
    if (!pid) {
        need(fcntl(held, F_SETFD, 0) == 0, "retain controlled FD for actual cross-process inspection");
        need(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0, "TRACEME");
        raise(SIGSTOP);
        execl("/bin/true", "true", (char *)NULL); _exit(1);
    }
    int status = 0;
    need(waitpid(pid, &status, 0) == pid && WIFSTOPPED(status), "initial trace stop");
    need(ptrace(PTRACE_SETOPTIONS, pid, NULL,
                (void *)(uintptr_t)(PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL)) == 0, "trace options");
    need(ptrace(PTRACE_CONT, pid, NULL, NULL) == 0, "continue only to exec");
    int pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    need(pidfd >= 0 && waitid(P_PIDFD, (id_t)pidfd, &info, WSTOPPED | WNOWAIT) == 0
         && info.si_pid == pid && info.si_code == CLD_TRAPPED, "waitid pidfd owns actual exec stop");
    need(waitpid(pid, &status, 0) == pid && WIFSTOPPED(status)
         && (unsigned)status >> 16 == PTRACE_EVENT_EXEC, "actual exec stop");
    char path[128]; snprintf(path, sizeof(path), "/proc/%ld/exe", (long)pid);
    int live = open(path, O_RDONLY | O_CLOEXEC);
    need(live >= 0 && fstat(live, &actual) == 0, "hold kernel selected exec");
    need(expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino
         && expected.st_size == actual.st_size, "held object matches actual exec");
    char text[8192];
    snprintf(path, sizeof(path), "/proc/%ld/fdinfo/%d", (long)pid, held);
    need(read_text(path, text, sizeof(text)) == 0 && strstr(text, "flags:"), "actual child fdinfo readable");
    snprintf(path, sizeof(path), "/proc/%ld/maps", (long)pid);
    need(read_text(path, text, sizeof(text)) == 0 && text[0], "actual stopped child maps readable");
    snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid);
    need(read_text(path, text, sizeof(text)) == 0 &&
         (strstr(text, "State:\tt") || strstr(text, "State:\tT")), "actual child trace-stop state");
    snprintf(path, sizeof(path), "/proc/%ld/task", (long)pid);
    DIR *tasks = opendir(path); need(tasks != NULL, "actual child task census readable");
    unsigned count = 0; struct dirent *entry;
    while ((entry = readdir(tasks))) if (entry->d_name[0] != '.') count++;
    need(closedir(tasks) == 0 && count == 1, "single-threaded child task census");
    passed();
    begin("PIDFD_GETFD");
    int duplicated = (int)syscall(SYS_pidfd_getfd, pidfd, held, 0);
    need(duplicated >= 0, "actual cross-process pidfd_getfd"); passed();
    begin("KCMP");
    need(syscall(SYS_kcmp, getpid(), pid, KCMP_FILE, duplicated, held) == 0,
         "kcmp confirms same cross-process open description"); passed();
    begin("PTRACE_CLOSURE");
    close(duplicated); close(pidfd);
    close(live); close(held);
    need(killed_and_reaped(pid) == 0, "pidfd kill and reap while exec-stopped");
    puts("{\"observation\":\"ptrace\",\"held_exec_join\":true,\"waitid_pidfd_ownership\":true,\"pidfd_getfd_cross_process\":true,\"kcmp_file_shared\":true,\"proc_task_fdinfo_maps_read\":true,\"continued_after_exec_stop\":false,\"pidfd_killed_and_reaped\":true}");
    passed();
}
struct ll_ruleset { uint64_t fs; };
struct ll_path { uint64_t rights; int32_t parent; } __attribute__((packed));
static void write_fresh(const char *path) {
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0444);
    need(fd >= 0 && write(fd, "canary\n", 7) == 7 && fchmod(fd, 0444) == 0
         && close(fd) == 0, "fresh isolation canary with explicit world-read DAC");
}
static void namespace_inner(const struct stat before[4], const struct stat *oldroot) {
    const char *names[] = {"mnt", "net", "ipc", "pid"};
    need(getpid() == 1, "PID namespace init");
    for (int i = 0; i < 4; i++) {
        char path[128]; struct stat actual;
        snprintf(path, sizeof(path), "/proc/self/ns/%s", names[i]);
        need(stat(path, &actual) == 0 && actual.st_ino != before[i].st_ino,
             "namespace actually differs");
    }
    int net = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in target = {.sin_family = AF_INET, .sin_port = htons(9),
                                 .sin_addr = {.s_addr = htonl(0xc0000201)}};
    need(net >= 0, "private network socket");
    errno = 0; need(connect(net, (struct sockaddr *)&target, sizeof(target)) == -1
                   && errno == ENETUNREACH, "new network namespace has no external route");
    close(net);
    passed();
    begin("PIVOT_ROOT");
    need(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0, "private mount propagation");
    char root[8192]; snprintf(root, sizeof(root), "%s/pivot", work);
    need(mkdir(root, 0700) == 0, "fresh pivot mountpoint");
    need(mount("tmpfs", root, "tmpfs", MS_NODEV | MS_NOSUID, "size=4m") == 0, "private tmpfs");
    need(chdir(root) == 0 && mkdir("old", 0700) == 0, "pivot setup");
    need(syscall(SYS_pivot_root, ".", "old") == 0 && chdir("/") == 0, "actual pivot_root");
    need(umount2("/old", MNT_DETACH) == 0 && rmdir("/old") == 0, "detach former root");
    struct stat now;
    need(stat("/", &now) == 0 && (now.st_dev != oldroot->st_dev || now.st_ino != oldroot->st_ino), "new root object");
    errno = 0; need(access("/etc/os-release", F_OK) == -1 && errno == ENOENT, "old host path unreachable");
    write_fresh("/allowed"); write_fresh("/blocked");
    need(chmod("/", 0755) == 0, "private root traversal");
    passed();
    begin("PRIVILEGE_DROP");
    need(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0, "drop groups UID GID");
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    need(syscall(SYS_capget, &header, caps) == 0, "read actual capabilities");
    need(!(caps[0].effective | caps[0].permitted | caps[0].inheritable |
           caps[1].effective | caps[1].permitted | caps[1].inheritable), "zero capabilities");
    need(getuid() == 65534 && geteuid() == 65534 && getgid() == 65534 && getgroups(0, NULL) == 0, "nonroot identity");
    need(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
         && prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "no new privileges");
    int inherited = dup(STDOUT_FILENO); need(inherited >= 3, "inherited FD canary");
    need(syscall(SYS_close_range, 3U, ~0U, 0) == 0, "close inherited FDs");
    errno = 0; need(fcntl(inherited, F_GETFD) == -1 && errno == EBADF, "inherited FD is closed");
    passed();
    begin("LANDLOCK");
    long abi = syscall(SYS_landlock_create_ruleset, NULL, 0, 1);
    need(abi >= 0, "Landlock ABI query");
    printf("{\"detail\":\"landlock_abi\",\"value\":%ld}\n", abi);
    if (abi < 3) unsupported("Landlock ABI below mandatory version3");
    struct ll_ruleset attr = {(1ULL << 15) - 1};
    int rules = (int)syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
    int allowed = open("/allowed", O_PATH | O_CLOEXEC);
    need(rules >= 0 && allowed >= 0, "Landlock ruleset and allow leaf");
    struct ll_path rule = {1ULL << 2, allowed};
    need(syscall(SYS_landlock_add_rule, rules, 1, &rule, 0) == 0, "Landlock path rule");
    close(allowed);
    need(syscall(SYS_landlock_restrict_self, rules, 0) == 0, "enforce Landlock"); close(rules);
    int fd = open("/allowed", O_RDONLY | O_CLOEXEC); need(fd >= 0, "Landlock permits allowed read"); close(fd);
    errno = 0; fd = open("/blocked", O_RDONLY | O_CLOEXEC);
    need(fd == -1 && errno == EACCES, "Landlock refuses forbidden read");
    passed();
    begin("SECCOMP");
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog filter = {(unsigned short)(sizeof(code) / sizeof(code[0])), code};
    need(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter) == 0, "install seccomp");
    errno = 0; need(syscall(SYS_getppid) == -1 && errno == EPERM, "seccomp actually refuses syscall");
    passed();
    puts("{\"observation\":\"isolation\",\"new_mnt_net_ipc_pid\":true,\"network_route_denied\":true,\"pid\":1,\"pivot_root_and_detach\":true,\"uid\":65534,\"groups\":0,\"capabilities_zero\":true,\"no_new_privs\":true,\"inherited_fds_closed\":true,\"landlock_allowed_and_denied\":true,\"seccomp_denied\":true}");
}
static void namespace_probe(void) {
    begin("NAMESPACES");
    const char *names[] = {"mnt", "net", "ipc", "pid"}; struct stat before[4], root;
    for (int i = 0; i < 4; i++) {
        char path[128]; snprintf(path, sizeof(path), "/proc/self/ns/%s", names[i]);
        need(stat(path, &before[i]) == 0, "starting namespace");
    }
    need(stat("/", &root) == 0, "starting root");
    need(unshare(CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWPID) == 0, "unshare mandatory namespaces");
    pid_t pid = fork(); need(pid >= 0, "fork PID1");
    if (!pid) { namespace_inner(before, &root); _exit(0); }
    int status = 0; need(waitpid(pid, &status, 0) == pid, "reap isolation child");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) _exit(1);
}
static int cgroup_probe(void) {
    begin("CGROUPS");
    char parent[256], leaf[280], path[320], text[8192];
    int parent_created = 0, leaf_created = 0, ok = 0; pid_t child = -1;
#define CG_REQUIRE(expr, why) do { if (!(expr)) { int error = errno; result(error_status(error), why, error); fprintf(stderr, "%s: %s\n", why, strerror(error)); goto done; } } while (0)
    snprintf(parent, sizeof(parent), "/sys/fs/cgroup/realm-capability-%ld", (long)getpid());
    snprintf(leaf, sizeof(leaf), "%s/run", parent);
    CG_REQUIRE(read_text("/sys/fs/cgroup/cgroup.subtree_control", text, sizeof(text)) == 0, "read existing cgroup delegation");
    if (!(strstr(text, "cpu") && strstr(text, "memory") && strstr(text, "pids"))) {
        result("UNSUPPORTED", "required existing cpu/memory/pids delegation absent; host configuration unchanged", 0); goto done;
    }
    CG_REQUIRE(mkdir(parent, 0700) == 0, "fresh protected cgroup parent"); parent_created = 1;
    snprintf(path, sizeof(path), "%s/cgroup.subtree_control", parent);
    CG_REQUIRE(write_text(path, "+cpu +memory +pids") == 0, "delegate only fresh subtree");
    CG_REQUIRE(mkdir(leaf, 0700) == 0, "fresh cgroup leaf"); leaf_created = 1;
    const char *limits[] = {"memory.max", "pids.max", "cpu.max"};
    const char *values[] = {"134217728", "16", "100000 100000"};
    for (int i = 0; i < 3; i++) {
        snprintf(path, sizeof(path), "%s/%s", leaf, limits[i]);
        CG_REQUIRE(write_text(path, values[i]) == 0 && read_text(path, text, sizeof(text)) == 0, "write and read actual cgroup limit");
        text[strcspn(text, "\r\n")] = 0;
        CG_REQUIRE(strcmp(text, values[i]) == 0, "exact cgroup limit");
    }
    child = fork(); CG_REQUIRE(child >= 0, "fork bounded cgroup child");
    if (!child) { for (;;) pause(); }
    snprintf(path, sizeof(path), "%s/cgroup.procs", leaf); snprintf(text, sizeof(text), "%ld", (long)child);
    CG_REQUIRE(write_text(path, text) == 0, "place actual child in cgroup");
    snprintf(path, sizeof(path), "/proc/%ld/cgroup", (long)child);
    CG_REQUIRE(read_text(path, text, sizeof(text)) == 0 && strstr(text, parent + strlen("/sys/fs/cgroup")), "live child membership");
    for (int i = 0; i < 3; i++) {
        snprintf(path, sizeof(path), "%s/%s", leaf, limits[i]);
        CG_REQUIRE(read_text(path, text, sizeof(text)) == 0, "read live cgroup limit");
        text[strcspn(text, "\r\n")] = 0;
        CG_REQUIRE(strcmp(text, values[i]) == 0, "actual limits while child is live");
    }
    passed(); begin("CGROUP_CLOSURE");
    snprintf(path, sizeof(path), "%s/cgroup.kill", leaf);
    CG_REQUIRE(write_text(path, "1") == 0, "actual cgroup.kill closure");
    int status = 0;
    CG_REQUIRE(waitpid(child, &status, 0) == child && WIFSIGNALED(status)
               && WTERMSIG(status) == SIGKILL, "cgroup killed child reaped"); child = -1;
    snprintf(path, sizeof(path), "%s/cgroup.procs", leaf);
    CG_REQUIRE(read_text(path, text, sizeof(text)) == 0 && strspn(text, " \t\r\n") == strlen(text), "terminal empty cgroup");
    ok = 1;
done:
    if (child > 0) { kill(child, SIGKILL); waitpid(child, NULL, 0); }
    if (leaf_created && rmdir(leaf)) { result("FAIL", "fresh leaf cleanup failed", errno); ok = 0; }
    if (parent_created && rmdir(parent)) { result("FAIL", "fresh parent cleanup failed", errno); ok = 0; }
    if (ok) puts("{\"observation\":\"cgroup\",\"live_membership\":true,\"memory_max\":134217728,\"pids_max\":16,\"cpu_max\":\"100000 100000\",\"cgroup_kill\":true,\"terminal_empty\":true,\"fresh_subtree_removed\":true}");
    if (ok) passed();
    return ok;
#undef CG_REQUIRE
}
static int run(const char *name, void (*test)(void)) {
    pid_t child = fork(); need(child >= 0, "fork capability probe");
    if (!child) { alarm(15); test(); _exit(0); }
    int status = 0; need(waitpid(child, &status, 0) == child, "reap capability probe");
    int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    printf("{\"test\":\"%s\",\"status\":\"%s\",\"raw_wait_status\":%d}\n", name, ok ? "PASS" : "FAIL", status);
    return ok;
}
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0); alarm(50); umask(0077);
#if !defined(__x86_64__)
    puts("{\"event\":\"host_precondition\",\"status\":\"UNSUPPORTED\",\"reason\":\"requires Linux x86_64\"}"); return 77;
#endif
    if (argc != 2 || geteuid() != 0 || strlen(argv[1]) >= sizeof(work)) {
        puts("{\"test\":\"host\",\"status\":\"NOT_RUN\",\"reason\":\"fresh private output and root required\"}"); return 77;
    }
    struct stat s; need(lstat(argv[1], &s) == 0 && S_ISDIR(s.st_mode) && s.st_uid == 0 && !(s.st_mode & 0077), "private root-owned output");
    strcpy(work, argv[1]);
    int ok = run("kvm_api_and_empty_vm", kvm_probe);
    ok &= run("ptrace_exec_pidfd", ptrace_probe);
    ok &= run("namespaces_pivot_privileges_landlock_seccomp", namespace_probe);
    int cg = cgroup_probe(); printf("{\"test\":\"cgroup_live_limits_and_closure\",\"status\":\"%s\"}\n", cg ? "PASS" : "FAIL"); ok &= cg;
    return ok ? 0 : 1;
}
