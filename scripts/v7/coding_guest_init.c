/* Development-only read-only-root guest init. No publication authority. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <signal.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static void require(int ok, const char *what) {
    if (!ok) { perror(what); _exit(111); }
}

static volatile sig_atomic_t retirement_requested;
static void request_retirement(int signal_number) {
    (void)signal_number;
    retirement_requested = 1;
}

int main(void) {
    require(getpid() == 1, "requires guest PID 1");
    require(mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == 0, "proc");
    require(mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY, NULL) == 0, "sysfs");
    require(mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, NULL) == 0, "devtmpfs");
#ifdef REALM_CODING_MODEL_DISK
    require(mount("/dev/vdb", "/model-inputs", "ext4",
                  MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == 0, "readonly model inputs");
#endif
    require(mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0700,size=128m") == 0, "run");
    require(mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777,size=64m") == 0, "tmp");
    require(mkdir("/run/realm-task", 0700) == 0, "private run");
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "loopback socket");
    struct ifreq request = { .ifr_name = "lo" };
    require(ioctl(fd, SIOCGIFFLAGS, &request) == 0, "read loopback flags");
    request.ifr_flags |= IFF_UP;
    require(ioctl(fd, SIOCSIFFLAGS, &request) == 0, "enable guest-local loopback");
    close(fd);
    char *args[] = {"/usr/bin/python3", "-I", "-B", "/controller/coding_guest_boot.py", NULL};
    char *environment[] = {"PATH=/usr/bin:/bin", "LC_ALL=C", NULL};
    /* Keep a trusted PID 1 alive after the controller exports its evidence.
       Reuse V6's x86 CAD -> SIGINT -> RB_AUTOBOOT retirement mechanism.
       A receiver ACK is required by the controller before it can exit 0. */
    struct sigaction action = { .sa_handler = request_retirement, .sa_flags = SA_RESTART };
    sigemptyset(&action.sa_mask);
    require(sigaction(SIGINT, &action, NULL) == 0, "retirement handler");
    require(reboot(RB_DISABLE_CAD) == 0, "CAD signal delivery");
    sigset_t blocked, previous;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGINT);
    require(sigprocmask(SIG_BLOCK, &blocked, &previous) == 0, "retirement mask");
    pid_t controller = fork();
    require(controller >= 0, "controller fork");
    if (controller == 0) {
        require(signal(SIGINT, SIG_DFL) != SIG_ERR, "controller signal reset");
        require(sigprocmask(SIG_SETMASK, &previous, NULL) == 0, "controller signal mask");
        execve(args[0], args, environment);
        require(0, "Python guest entry");
    }
    int status = 0;
    pid_t waited;
    do { waited = waitpid(controller, &status, 0); } while (waited < 0 && errno == EINTR);
    require(waited == controller, "controller wait");
    /* Failed/unknown handoffs deliberately cannot take the clean path. Keep
       PID 1 alive so host fallback remains visibly forced, never successful. */
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fputs("CODING_CONTROLLER_HANDOFF_FAILED; AUTHORITY=NONE\n", stderr);
        for (;;) pause();
    }
    while (!retirement_requested) sigsuspend(&previous);
    sync();
    reboot(RB_AUTOBOOT);
    require(0, "x86 retirement reboot returned");
    return 111;
}
