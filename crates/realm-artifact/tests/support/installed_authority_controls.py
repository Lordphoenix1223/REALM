from pathlib import Path
import os,sys,json,time,hashlib,subprocess,shutil
assert sys.argv[1:]==['bounded'], 'TEST ONLY: invoke with bounded'
bounded=True; out=Path('/evidence')/('final-linux-controls' if bounded else 'draft-controls');out.mkdir()
base=Path('/fixture-authority'); binary=Path('/tools/installed_authority_fixture'); crypto='/usr/bin/openssl'; records=[]
def call(args,uid=None):
 def principal():
  os.setgroups([]);os.setgid(uid);os.setuid(uid)
 p=subprocess.run([str(binary),*map(str,args)],capture_output=True,timeout=15,preexec_fn=principal if uid is not None else None)
 return p

def keep(name,p,ok,kind='NONE_ONLY_SOFTWARE_CONTROL'):
 (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
 assert (p.returncode==0)==ok,(name,p.returncode,p.stderr.decode(errors='replace'))
 records.append({'case':name,'exit':p.returncode,'expected_success':ok,'authority':'NONE','evidence_class':kind});(out/'PROGRESS.json').write_text(json.dumps(records,indent=2)+'\n')
 return json.loads(p.stdout) if ok else None

def cmd(args):
 p=subprocess.run(args,capture_output=True,timeout=30);assert p.returncode==0,(args,p.stderr);return p

def h(path):return json.loads(call(['hash',path]).stdout)

def write_manifest(root,m):
 (root/'manifest.json').write_text(json.dumps(m,separators=(',',':')));os.chmod(root/'manifest.json',0o644)

assert sys.platform=='linux' and os.geteuid()==0, 'isolated Linux test principal required'
assert os.environ.get('REALM_TEST_ONLY_CONTAINER')=='1', 'explicit test-container marker required'
assert any(len(x.split())>=3 and x.split()[1]=='/fixture-authority' and x.split()[2]=='tmpfs' for x in Path('/proc/mounts').read_text().splitlines()), 'fixture keys require disposable tmpfs'
assert not any(os.path.lexists(p) for p in ['/etc/realm/runtime-admission','/private/etc/realm/runtime-admission']), 'never run fixture authority on configured production host'
assert not Path('/etc/realm/runtime-admission').exists()
good=base/'good';good.mkdir(mode=0o755)
mask=os.umask(0o077)
try:cmd([crypto,'genrsa','-out',str(good/'private.pem'),'3072'])
finally:os.umask(mask)
os.chmod(good/'private.pem',0o600)
cmd([crypto,'rsa','-in',str(good/'private.pem'),'-pubout','-out',str(good/'public.pem')]);os.chmod(good/'public.pem',0o644)
profile=json.loads(call(['candidate']).stdout);now=int(time.time());profile['not_before_unix']=now-10;profile['expires_at_unix']=now+3600
m={'schema':'realm.installed-runtime-authority/v1','public_key_blake3':h(good/'public.pem'),'crypto_path':crypto,'crypto_blake3':h(crypto),'validity_seconds':60,'coding_agent_host_uid':profile['expected']['vmm_uid'],'coding_agent_host_gid':profile['expected']['vmm_gid']}
field='approved_profile_template' if bounded else 'approved_profile';m[field]=profile
if bounded:m.update(issuance_not_before_unix=now-10,issuance_expires_at_unix=now+3600)
write_manifest(good,m)
setup=keep('protected-setup',call(['inspect',good]),True);assert setup['authority']=='NONE'
issued=keep('automatic-issuance',call(['issue',good]),True);assert issued['authority']=='NONE' and issued['evidence_class']=='TEST_ONLY_INSTALLED_STATEMENT'
statement=issued['statement'];sf=base/'statement.json';sf.write_text(json.dumps(statement));os.chmod(sf,0o644)
verified=keep('actual-signature',call(['verify',good,sf]),True);assert verified['authority']=='NONE'
if bounded:
 integrated=keep('actual-auto-issuer-to-receiver',call(['integrate',good,sf]),True)
 assert integrated['authority']=='NONE' and integrated['production_verification']=='REFUSE'
 assert integrated['receiver']['authority']=='NONE' and integrated['realm_artifact'] is None and integrated['destination_access'] is False

second=keep('fresh-automatic-statement',call(['issue',good]),True);assert second['statement']['policy_json']!=statement['policy_json']
actual=json.loads(statement['policy_json']);expected=json.loads(json.dumps(profile))
for k in ['nonce','not_before_unix','expires_at_unix']:expected[k]=actual[k]
assert actual==expected and actual['expires_at_unix']-actual['not_before_unix']<=m['validity_seconds']
keep('fixture-not-global-trust',call(['production-verify',sf]),False)

if bounded:
 for name,path in [('production-namespace',Path('/etc/realm/runtime-admission')),('normalized-production-namespace',Path('/fixture-authority/good/../../etc/realm/runtime-admission'))]:
  for api in ['inspect','issue','verify']:
   args=[api,path]+([sf] if api=='verify' else [])
   p=call(args);keep(name+'-'+api,p,False);assert b'fixture production namespace forbidden' in p.stderr
 agent=base/'agent-owned-temp';agent.mkdir(mode=0o700);os.chown(agent,501,501)
 def list_agent():
  def principal():os.setgroups([]);os.setgid(501);os.setuid(501)
  p=subprocess.run([sys.executable,'-c','import os,json;print(json.dumps(os.listdir('+repr(str(agent))+')))'],capture_output=True,preexec_fn=principal);assert p.returncode==0;return p.stdout
 before=list_agent();previous=os.environ.get('TMPDIR');os.environ['TMPDIR']=str(agent/'must-not-be-created')
 try:
  keep('ignored-untrusted-TMPDIR-issue',call(['issue',good]),True)
  keep('ignored-untrusted-TMPDIR-verify',call(['verify',good,sf]),True)
 finally:
  if previous is None:os.environ.pop('TMPDIR',None)
  else:os.environ['TMPDIR']=previous
 assert before==list_agent()

keep('missing-fixed-production-setup',call(['production-issue']),False)
keep('missing-test-setup',call(['issue',base/'missing']),False)
# An unprivileged verifier can read public material, but neither configured UID
# nor another unprivileged UID can read the secret or mutate the trust inputs.
for uid in sorted({501,profile['expected']['vmm_uid']}):
 keep(f'public-verification-uid-{uid}',call(['verify',good,sf],uid),True)
 keep(f'issuer-uid-{uid}',call(['issue',good],uid),False)
 for name,operation in [('private-read',"open(p,'rb').read()"),('manifest-write',"open(p,'ab').write(b'x')"),('public-write',"open(p,'ab').write(b'x')")]:
  path=good/({'private-read':'private.pem','manifest-write':'manifest.json','public-write':'public.pem'}[name])
  def principal():os.setgroups([]);os.setgid(uid);os.setuid(uid)
  p=subprocess.run([sys.executable,'-c',f"p={str(path)!r};{operation}"],capture_output=True,preexec_fn=principal)
  keep(f'{name}-uid-{uid}',p,False)
 assert (good/'manifest.json').read_text()==json.dumps(m,separators=(',',':'))
# Re-signing a wider policy with the TEST key must fail baseline enforcement.
wide=json.loads(json.dumps(statement));body=json.loads(wide['policy_json']);body['expected']['pids_max']+=1;wide['policy_json']=json.dumps(body,separators=(',',':'))
message=base/'wide-message';message.write_bytes(b'REALM::IndependentRuntimeAdmission/v1\0'+wide['policy_json'].encode());signature=base/'wide-signature'
cmd([crypto,'dgst','-sha256','-sign',str(good/'private.pem'),'-out',str(signature),str(message)]);wide['signature_hex']=signature.read_bytes().hex()
p=cmd([crypto,'dgst','-sha256','-verify',str(good/'public.pem'),'-signature',str(signature),str(message)]);(out/'widened-policy-raw-crypto.stdout').write_bytes(p.stdout)
widepath=base/'wide-statement.json';widepath.write_text(json.dumps(wide));keep('valid-signature-widened-baseline',call(['verify',good,widepath]),False)
for name,key,value in [('signature-substitution','signature_hex','0'*768),('reviewer-substitution','reviewer_key_id','0'*64)]:
 wrong=json.loads(json.dumps(statement));wrong[key]=value;path=base/(name+'.json');path.write_text(json.dumps(wrong));keep(name,call(['verify',good,path]),False)
# Each unsafe installation is separate; the production fixed path is untouched.
def variant(name,mutator,op='issue',ok=False):
 root=base/name;shutil.copytree(good,root);mm=json.loads(json.dumps(m));mutator(root,mm);keep(name,call([op,root]),ok);return root
variant('private-readable',lambda r,m:os.chmod(r/'private.pem',0o644))
variant('private-agent-owned',lambda r,m:os.chown(r/'private.pem',501,501))
variant('manifest-agent-owned',lambda r,m:os.chown(r/'manifest.json',501,501))
variant('group-writable-manifest',lambda r,m:os.chmod(r/'manifest.json',0o664))
variant('group-writable-root',lambda r,m:os.chmod(r,0o775))
def symlink_manifest(r,m):
 (r/'manifest.json').rename(r/'real-manifest.json');(r/'manifest.json').symlink_to('real-manifest.json')
variant('symlink-manifest',symlink_manifest)
link=base/'symlink-parent';link.symlink_to(good,target_is_directory=True);keep('symlink-parent',call(['issue',link]),False)
def bad_field(name,edit):
 def mutate(r,mm):edit(mm);write_manifest(r,mm)
 return variant(name,mutate)
bad_field('root-agent-identity',lambda m:m.update(coding_agent_host_uid=0))
bad_field('wrong-public-pin',lambda m:m.update(public_key_blake3='0'*64))
bad_field('wrong-crypto-pin',lambda m:m.update(crypto_blake3='0'*64))
bad_field('unknown-manifest-field',lambda m:m.update(agent_authorized=True))
bad_field('wrong-source-profile',lambda m:m[field].update(profile_source_blake3='0'*64))
def duplicate(r,mm):
 raw=(r/'manifest.json').read_text();(r/'manifest.json').write_text('{"schema":"duplicate",'+raw[1:])
variant('duplicate-manifest-field',duplicate)
if bounded:
 bad_field('expired-issuance-window',lambda m:m.update(issuance_not_before_unix=1000,issuance_expires_at_unix=2000))
 future=int(time.time())+3600;bad_field('future-issuance-window',lambda m:m.update(issuance_not_before_unix=future,issuance_expires_at_unix=future+3600))
 cap=base/'capped-end-window';shutil.copytree(good,cap);cm=json.loads(json.dumps(m));cm['issuance_expires_at_unix']=int(time.time())+30;cm['validity_seconds']=3600;write_manifest(cap,cm)
 capped=keep('lease-capped-by-independent-window',call(['issue',cap]),True);assert json.loads(capped['statement']['policy_json'])['expires_at_unix']==cm['issuance_expires_at_unix']
 # Held descriptor and protected name must refer to the same actual object.
 executable=base/'installed-executable';shutil.copyfile(binary,executable);os.chmod(executable,0o555)
 keep('held-executable-valid-join',call(['exe-join',executable,executable]),True)
 replacement=base/'identical-bytes-different-object';shutil.copyfile(executable,replacement);os.chmod(replacement,0o555)
 keep('held-executable-substitution',call(['exe-join',replacement,executable]),False)
 alias=base/'symlink-executable';alias.symlink_to(executable);keep('symlink-executable',call(['exe-join',alias,executable]),False)
 hard=base/'hardlink-executable';os.link(executable,hard);keep('hardlink-executable',call(['exe-join',hard,executable]),False);hard.unlink()
 untrusted=base/'untrusted-executable-parent';untrusted.mkdir();badexe=untrusted/'executable';shutil.copyfile(executable,badexe);os.chmod(badexe,0o555);os.chown(untrusted,501,501);keep('untrusted-executable-parent',call(['exe-join',badexe,badexe]),False)
 os.chmod(executable,0o775);keep('group-writable-executable',call(['exe-join',executable,executable]),False)
assert not Path('/etc/realm/runtime-admission').exists()
# Only public signed data is retained. Private keys exist only in disposable tmpfs.
(out/'public.pem').write_bytes((good/'public.pem').read_bytes());(out/'TEST-ONLY-statement.json').write_text(json.dumps(statement));(out/'TEST-ONLY-manifest.json').write_text(json.dumps(m))
(out/'RESULTS.json').write_text(json.dumps({'authority':'NONE','evidence_class':'TEST_ONLY_INSTALLED_AUTHORITY_SOFTWARE','production_setup':'ABSENT_UNCHANGED','native_qualification':'NOT_RUN','binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'cases':records},indent=2)+'\n')
print(json.dumps({'cases':len(records),'authority':'NONE','contract':'bounded' if bounded else 'initial-draft','production_setup':'ABSENT'}))
