#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
#include <signal.h>
static volatile sig_atomic_t kicked;
static void kick(int n){kicked=n;}
static void *thread(void *p){*(int*)p=42;return 0;}
int main(void){
 int fd=open("/kernel",O_RDONLY);char c=0;int readok=fd>=0&&read(fd,&c,1)==1&&c=='K';if(fd>=0)close(fd);
 errno=0;fd=open("/forbidden",O_WRONLY);int newerr=fd<0?errno:0;if(fd>=0){if(pwrite(fd,"N",1,0)!=1)return 81;close(fd);}
 errno=0;int inherit=pwrite(200,"F",1,0)<0?errno:0;
 void *address=(void*)(uintptr_t)0x600000000000ULL;
 errno=0;void *mapping=mmap(address,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);int fresh=mapping==address;if(fresh){*(char*)mapping='M';munmap(mapping,4096);}
 errno=0;int mfd=syscall(SYS_memfd_create,"x",0);int memerr=mfd<0?errno:0;if(mfd>=0)close(mfd);
 errno=0;int net=socket(AF_INET,SOCK_STREAM,0);int neterr=net<0?errno:0;if(net>=0)close(net);
 int unixfd=socket(AF_UNIX,SOCK_STREAM,0);struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,"/run/realm.task_9001");int conn=-1;for(int i=0;i<5000;i++){conn=connect(unixfd,(void*)&a,sizeof(a));if(!conn)break;struct timespec t={0,1000000};nanosleep(&t,0);}int recverr=-1;
 if(!conn){char b;if(write(unixfd,"R",1)!=1||read(unixfd,&b,1)!=1)return 82;struct msghdr msg={0};errno=0;recverr=recvmsg(unixfd,&msg,MSG_DONTWAIT)<0?errno:0;}close(unixfd);
 errno=0;int unlinkerr=unlink("/run/realm.task_9001")<0?errno:0;
 errno=0;int aliaserr=symlink("/run/realm.task_9001","/run/alias")<0?errno:0;
 int rebound=socket(AF_UNIX,SOCK_STREAM,0);errno=0;int rebinderr=bind(rebound,(void*)&a,sizeof(a))<0?errno:0;close(rebound);
 int outside=socket(AF_UNIX,SOCK_STREAM,0);strcpy(a.sun_path,"/tmp/realm-fence-component-outside.sock");errno=0;int outsidepath=connect(outside,(void*)&a,sizeof(a))<0?errno:0;close(outside);
 int abstract=socket(AF_UNIX,SOCK_STREAM,0);memset(&a,0,sizeof(a));a.sun_family=AF_UNIX;memcpy(a.sun_path+1,"realm-fence-component-outside",28);errno=0;int outsideabstract=connect(abstract,(void*)&a,offsetof(struct sockaddr_un,sun_path)+29)<0?errno:0;close(abstract);
 int private=socket(AF_UNIX,SOCK_STREAM,0);memset(&a,0,sizeof(a));a.sun_family=AF_UNIX;strcpy(a.sun_path,"/run/private.sock");int selfok=bind(private,(void*)&a,sizeof(a))==0&&listen(private,1)==0;int self=socket(AF_UNIX,SOCK_STREAM,0);selfok=selfok&&connect(self,(void*)&a,sizeof(a))==0;int accepted=accept4(private,0,0,SOCK_CLOEXEC);struct ucred cred={0};socklen_t length=sizeof(cred);selfok=selfok&&accepted>=0&&getsockopt(accepted,SOL_SOCKET,SO_PEERCRED,&cred,&length)==0&&cred.uid==65534;close(accepted);close(self);close(private);
 struct mmsghdr multi={0};errno=0;int multierr=recvmmsg(-1,&multi,1,MSG_DONTWAIT,0)<0?errno:0;
 int alias=open("/kernel",O_RDONLY);int aliasfd=fcntl(alias,F_DUPFD_CLOEXEC,210);errno=0;int aliaswrite=pwrite(aliasfd,"X",1,0)<0?errno:0;close(alias);close(aliasfd);
 errno=0;int late=open("/run/late-unapproved",O_WRONLY);int lateerr=late<0?errno:0;if(late>=0){if(pwrite(late,"X",1,0)!=1)return 83;close(late);}
 struct sigaction action={0};action.sa_handler=kick;sigemptyset(&action.sa_mask);int signalsetup=sigaction(35,&action,0);
 int kicksend=syscall(SYS_tkill,syscall(SYS_gettid),35);
 errno=0;int othersignal=syscall(SYS_tkill,syscall(SYS_gettid),SIGUSR1)<0?errno:0;
 if(signalsetup||kicksend||kicked!=35||othersignal!=EPERM)return 87;
 printf("{\"pid_namespace_init\":%d,\"vcpu_kick\":%d,\"other_signal_errno\":%d}\n",getpid()==1,kicked,othersignal);
 int threadvalue=0;pthread_t t;int threaderr=pthread_create(&t,0,thread,&threadvalue);if(!threaderr)pthread_join(t,0);
 errno=0;pid_t pid=fork();int forkerr=pid<0?errno:0;if(pid==0)_exit(0);if(pid>0)waitpid(pid,0,0);
 printf("{\"approved_read\":%d,\"new_write_errno\":%d,\"inherited_fd_errno\":%d,\"fresh_mapping\":%d,\"memfd_errno\":%d,\"internet_socket_errno\":%d,\"unix_connect\":%d,\"recvmsg_errno\":%d,\"pthread_error\":%d,\"thread_value\":%d,\"fork_errno\":%d}\n",readok,newerr,inherit,fresh,memerr,neterr,conn,recverr,threaderr,threadvalue,forkerr);
 printf("{\"unlink_errno\":%d,\"symlink_errno\":%d,\"rebind_errno\":%d,\"outside_path_errno\":%d,\"outside_abstract_errno\":%d,\"private_self_peer\":%d,\"self_peer_uid\":%u,\"recvmmsg_errno\":%d,\"readonly_alias_write_errno\":%d,\"late_unapproved_write_errno\":%d}\n",unlinkerr,aliaserr,rebinderr,outsidepath,outsideabstract,selfok,cred.uid,multierr,aliaswrite,lateerr);
 return 0;
}
