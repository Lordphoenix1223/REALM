"""Actual Linux syscall/backend controls; no native VM or authority claims."""
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import unittest

import candidate_channel_guard as guard

SOURCE = Path(__file__).resolve().parents[2]
LINUX = platform.system() == 'Linux' and platform.machine() in ('x86_64', 'aarch64')


def wrapped(source):
    # Same installed policy and post-startup ordering as the existing Supervisor.
    return ('import os,sys,json,socket,subprocess,time,resource,fcntl,ctypes\n'
            'g={}\nexec(' + repr(Path(guard.__file__).read_text()) + ',g)\n'
            'g["install_stage8"]()\nexec(' + repr(source) + ')')


@unittest.skipUnless(LINUX, 'actual supported Linux kernel required; not a VM qualification')
class LinuxStage8Controls(unittest.TestCase):
    def child(self, source, **kwargs):
        return subprocess.run([sys.executable, '-I', '-B', '-S', '-c', wrapped(source)],
                              input=b'', capture_output=True, timeout=10, **kwargs)

    def test_actual_kernel_blocks_mutations_and_process_capabilities(self):
        with tempfile.TemporaryDirectory(prefix='realm-stage8-kernel-') as tmp:
            file = Path(tmp)/'sentinel'; file.write_bytes(b'TEST_ONLY_PUBLIC_SENTINEL')
            body = r'''import os,json,socket,ctypes,resource,fcntl,platform
results={}
def attempt(name,fn):
 try:fn()
 except OSError as e:results[name]=e.errno
 else:results[name]='ALLOWED'
libc=ctypes.CDLL(None,use_errno=True)
def syscall(number,*args):
 value=libc.syscall(number,*args)
 if value == -1:raise OSError(ctypes.get_errno(),'raw guarded syscall')
 return value
attempt('write',lambda:open(FILE,'w').write('bad'))
attempt('open-create',lambda:os.open(FILE+'.new',os.O_RDONLY|os.O_CREAT,0o600))
attempt('openat-truncate',lambda:os.open(FILE,os.O_RDONLY|os.O_TRUNC,dir_fd=-100))
attempt('rename',lambda:os.rename(FILE,FILE+'.renamed'))
attempt('link',lambda:os.link(FILE,FILE+'.linked'))
attempt('truncate',lambda:os.truncate(FILE,0))
attempt('pwrite',lambda:os.pwrite(1,b'bad',0))
attempt('mkdir',lambda:os.mkdir(FILE+'.dir'))
attempt('fork',os.fork)
attempt('clone',lambda:syscall(56 if platform.machine()=='x86_64' else 220,17,0,0,0,0))
attempt('clone3',lambda:syscall(435,0,0))
attempt('setsid',os.setsid)
attempt('unshare',lambda:syscall(272 if platform.machine()=='x86_64' else 97,0x20000000))
attempt('setns',lambda:syscall(308 if platform.machine()=='x86_64' else 268,-1,0))
attempt('exec',lambda:os.execv('/usr/bin/true',['/usr/bin/true']))
attempt('signal',lambda:os.kill(os.getppid(),0))
attempt('network',lambda:socket.socket())
attempt('pipe',os.pipe)
attempt('dup',lambda:os.dup(1))
attempt('fcntl-dup',lambda:fcntl.fcntl(1,fcntl.F_DUPFD,10))
attempt('memfd',lambda:os.memfd_create('forbidden'))
attempt('pidfd',lambda:os.pidfd_open(os.getpid()))
attempt('chmod',lambda:os.chmod(FILE,0o777))
attempt('unlink',lambda:os.unlink(FILE))
attempt('symlink',lambda:os.symlink(FILE,FILE+'.alias'))
attempt('io-uring-setup',lambda:syscall(425,0,0))
attempt('io-uring-enter',lambda:syscall(426,0,0,0,0,0))
attempt('io-uring-register',lambda:syscall(427,0,0,0,0))
attempt('pidfd-getfd',lambda:syscall(438,0,1,0))
limits=(ctypes.c_ulonglong*2)(*resource.getrlimit(resource.RLIMIT_CPU))
attempt('setrlimit',lambda:syscall(302 if platform.machine()=='x86_64' else 261,0,resource.RLIMIT_CPU,ctypes.byref(limits),0))
attempt('replace-filter',lambda:syscall(157 if platform.machine()=='x86_64' else 167,22,2,0,0,0))
word=ctypes.c_int(0)
attempt('shared-futex',lambda:syscall(202 if platform.machine()=='x86_64' else 98,ctypes.byref(word),1,1,0,0,0))
assert open(FILE,'rb').read()==b'TEST_ONLY_PUBLIC_SENTINEL'
assert libc.prctl(39,0,0,0,0)==1 and libc.prctl(21,0,0,0,0)==2
print(json.dumps(results))
'''.replace('FILE', repr(str(file)))
            result = self.child(body)
            self.assertEqual(result.returncode, 0, result.stderr)
            observed = json.loads(result.stdout)
            self.assertEqual(len(observed), 32)
            self.assertEqual(set(observed.values()), {errno.EPERM}, observed)
            self.assertEqual(file.read_bytes(), b'TEST_ONLY_PUBLIC_SENTINEL')
            self.assertEqual(set(Path(tmp).iterdir()), {file})
            print(json.dumps({'actual_kernel_denials':observed},sort_keys=True))
            print('LINUX_STAGE8_SECCOMP=PASS denied=32 authority=NONE filesystem_namespace=SEPARATE_CONTROL')

    def test_kernel_sanitation_refusal_prevents_executor_entry(self):
        # Actual inherited kernel policy makes close_range unavailable. The
        # trusted installer must abort before executing any agent source.
        source = ('import os,sys,json,socket,subprocess,time,resource,fcntl,ctypes\n'
                  'g={}\nexec('+repr(Path(guard.__file__).read_text())+',g)\n'
                  'g["_install"]([(0x20,0,0,0),(0x15,0,1,436),'
                  '(0x06,0,0,0x50001),(0x06,0,0,0x7fff0000)])\n'
                  'g["install_stage8"]()\nprint("EXECUTOR_ENTERED")')
        result = subprocess.run([sys.executable,'-I','-B','-S','-c',source],
                                input=b'',capture_output=True,timeout=10)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn(b'EXECUTOR_ENTERED',result.stdout)
        self.assertIn(b'descriptor sanitation refused',result.stderr)

    def test_kernel_namespace_refusal_has_no_executor_fallback(self):
        with tempfile.TemporaryDirectory(prefix='realm-stage8-no-fallback-') as tmp:
            source = ('import sys\nsys.path.insert(0,'+repr(str(SOURCE/'scripts/v7'))+')\n'
                      'from pathlib import Path\nfrom coding_worker import Sandbox\n'
                      'import candidate_channel_guard as g\n'
                      'g._install([(0x20,0,0,0),(0x15,0,1,'+
                      str(272 if platform.machine()=='x86_64' else 97)+'),'
                      '(0x06,0,0,0x50001),(0x06,0,0,0x7fff0000)])\n'
                      'code,out,err=Sandbox(Path('+repr(tmp)+')).execute('
                      '"print(\'EXECUTOR_ENTERED\')",b"")\n'
                      'assert code!=0 and b"EXECUTOR_ENTERED" not in out\n'
                      'assert b"Operation not permitted" in err,err\n'
                      'print("NAMESPACE_REFUSED_NO_FALLBACK")')
            result = subprocess.run([sys.executable,'-I','-B','-S','-c',source],
                                    input=b'',capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.strip(),b'NAMESPACE_REFUSED_NO_FALLBACK')
            self.assertEqual(list(Path(tmp).iterdir()),[])

    def test_actual_extra_descriptor_is_closed_before_executor(self):
        with tempfile.TemporaryFile() as file:
            result = self.child('try:\n os.fstat('+str(file.fileno())+')\nexcept OSError as e:\n assert e.errno==9\n print("INHERITED_FD_CLOSED")\nelse:raise RuntimeError("inherited descriptor survived")', pass_fds=(file.fileno(),))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), b'INHERITED_FD_CLOSED')

    def test_invalid_high_syscall_abi_kills_child(self):
        result = self.child("ctypes.CDLL(None).syscall(0x40000000);print('ESCAPED')")
        self.assertEqual(result.returncode, -signal.SIGSYS, result.stderr)
        self.assertFalse(result.stdout)

    def test_existing_full_broker_namespace_campaign(self):
        broker = os.environ.get('REALM_STAGE8_LINUX_BROKER')
        if not broker: self.skipTest('explicit compiled real broker required; namespace campaign NOT_RUN')
        with tempfile.TemporaryDirectory(prefix='realm-stage8-full-') as tmp:
            output = Path(tmp)/'campaign'
            result = subprocess.run([sys.executable,'-B',str(SOURCE/'scripts/v7/test_stage8_enforcement.py'),
                '--output',str(output),'--broker',broker],capture_output=True,timeout=180,cwd=SOURCE)
            print(result.stdout.decode(),end='')
            self.assertEqual(result.returncode,0,result.stderr.decode())
            report=json.loads((output/'report.json').read_bytes())
            self.assertEqual(report['authority'],'NONE')
            self.assertEqual(report['status'],'PASS_BOUNDED_STAGE8_DEVELOPMENT')


if __name__ == '__main__': unittest.main()
