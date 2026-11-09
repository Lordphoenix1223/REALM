/* Test-only shim, NOT the official Firecracker jailer or qualification. */
#define _GNU_SOURCE
#include <sched.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static void check(int rc,const char *s){if(rc<0){perror(s);exit(91);}}
int main(int argc,char **argv){
 if(argc!=3)return 90;
 /* Official v1.17.0 pivots before its CLONE_NEWPID child is created.
  * MS_SLAVE matches chroot.rs; the clone has no SIGCHLD exit signal. */
 check(unshare(CLONE_NEWNS),"shim mount namespace");
 check(mount(0,"/",0,MS_REC|MS_SLAVE,0),"shim mounts");
 /* Match the official jailer's mount isolation, including detached old root.
  * Plain chroot misses proc-exe magic links that have no host pathname. */
 check(mount(argv[1],argv[1],0,MS_BIND|MS_REC,0),"shim bind root");
 check(chdir(argv[1]),"shim enter root");check(mkdir("old_root",0700),"shim old root");
 check(syscall(SYS_pivot_root,".","old_root"),"shim pivot root");
 check(chdir("/"),"shim cwd");check(umount2("/old_root",MNT_DETACH),"shim detach root");
 check(rmdir("/old_root"),"shim remove old root");
 check(chown("/",65534,65534),"shim root chown");check(chown("/firecracker",65534,65534),"shim stage chown");
 if(!strcmp(argv[2],"socket")) {int fd=socket(AF_UNIX,SOCK_STREAM,0);check(fd,"shim socket");struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,"/run/preexisting.sock");check(bind(fd,(void*)&a,sizeof(a)),"shim socket bind");}
 if(!strcmp(argv[2],"symlink"))check(symlink("/kernel","/run/unexpected"),"shim symlink");
 if(mmap((void*)0x600000000000ULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_FIXED_NOREPLACE,200,0)==MAP_FAILED){perror("shim inherited mapping");return 92;}
 /* Keep the deliberate inherited-FD/map challenge above: upstream closes
  * inherited FDs at entry. This shim is an origin-refusal stress fixture,
  * not an implementation of upstream sanitization, devices or cgroups. */
 int session_leader=(getsid(0)==getpid());
 pid_t child=(pid_t)syscall(SYS_clone,CLONE_NEWPID,0,0,0,0);
 check(child,"shim PID clone");
 if(child){
  int pidfile=open("/firecracker.pid",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
  check(pidfile,"shim PID file");check(dprintf(pidfile,"%d",child),"shim PID write");
  check(close(pidfile),"shim PID close");return 0;
 }
 if(session_leader)check(setsid(),"shim child session");
 check(setgroups(0,0),"shim groups");check(setgid(65534),"shim gid");check(setuid(65534),"shim uid");
 if(!strcmp(argv[2],"hang"))for(;;)pause();
 const char *target=!strcmp(argv[2],"bypass")?"/realm-vmm":"/firecracker";
 char *args[]={(char*)target,"--id","component-only",0};char *env[]={0};execve(target,args,env);perror("shim exec");return 93;
}
