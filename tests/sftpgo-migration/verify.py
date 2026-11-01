import subprocess,sys,os,json
sys.path.insert(0,'/root')
from lib import *
bad=0
def check(n,ok,x=''):
    global bad
    if not ok: bad+=1
    print(('PASS ' if ok else 'FAIL ')+n+(f'  -> {str(x)[:200]}' if x!='' and (not ok or len(sys.argv)>1) else ''))
def sh(c):
    p=subprocess.run(c,shell=True,capture_output=True,text=True); return p.returncode,(p.stdout+p.stderr).strip()
A='http://127.0.0.1:8090/api/v2'
check('package state: gonas installed',sh("dpkg -l gonas | tail -1")[1].startswith('ii'),sh("dpkg -l gonas | tail -1")[1])
check('package state: sftpgo removed',not sh("dpkg -l sftpgo 2>/dev/null| tail -1")[1].startswith('ii'),sh("dpkg -l sftpgo | tail -1")[1])
check('gonas.service active',sh('systemctl is-active gonas')[1]=='active',sh('journalctl -u gonas -n 8 --no-pager')[1][-300:])
check('sftpgo.service not running',sh('systemctl is-active sftpgo')[1]!='active')
old=open('/root/old_uid').read().strip()
check('user keeps its id',sh('id -u gonas')[1]==old,sh('id gonas')[1])
check('no sftpgo user left',sh('getent passwd sftpgo')[0]!=0)
check('env file port applied (8090)',call('http://127.0.0.1:8090/healthz')[0]==200)
c,r=call(A+'/token',basic='admin:Seed-Admin-Pass-1'); check('admin password still works',c==200,r)
t=r.get('access_token') if isinstance(r,dict) else ''
users={u['username']:u for u in call(A+'/users',token=t)[1]} if t else {}
check('all users present',sorted(users)==['alice','bob','carol','dave'],list(users))
if users:
    check('home directories unchanged',users['alice']['home_dir']=='/srv/sftpgo/data/alice' and users['bob']['home_dir']=='/mnt/ext/bob')
    sec=users['dave']['filesystem']['s3config']['access_secret']
    check('S3 secret still encrypted, not reset',sec.get('status') not in ('','Plain') and sec.get('payload'),sec.get('status'))
sftp=lambda u,cmds:sh(f"printf '{cmds}' | sftp -q -b - -i /root/client_key -P 2222 -o UserKnownHostsFile=/root/kh -o StrictHostKeyChecking=yes {u}@127.0.0.1")
rc,o=sftp('alice','get f.txt /root/got_a.txt\\nput /root/f.txt new.txt\\nbye\\n')
check('SFTP on env.d port, same host key, key login, read+write in /srv',rc==0 and open('/root/got_a.txt').read().startswith('hello'),o)
rc,o=sftp('bob','get f.txt /root/got_b.txt\\nput /root/f.txt new.txt\\nbye\\n')
check('SFTP read+write in a home outside /srv',rc==0,o)
check('new files owned by the renamed user',sh('stat -c %U /srv/sftpgo/data/alice/new.txt /mnt/ext/bob/new.txt')[1].split()==['gonas','gonas'],sh('stat -c %U /srv/sftpgo/data/alice/new.txt')[1])
sec=open('/root/totp').read().strip()
c,r=call(A+'/user/token',basic='carol:Seed-User-Pass-1'); check('TOTP still required',c==401,(c,r))
c,r=call(A+'/user/token',basic='carol:Seed-User-Pass-1',headers={'X-GONAS-OTP':totp(sec)}); check('TOTP code accepted (KMS key from env.d decrypts)',c==200,(c,r))
key=open('/root/apikey').read().strip()
c,r=call(A+'/admins',headers={'X-GONAS-API-KEY':key}); check('API key still authenticates',c==200,(c,r))
check('systemd override carried over',sh('systemctl show gonas -p Environment')[1].count('GONAS_COMMON__IDLE_TIMEOUT=7')==1,sh('systemctl show gonas -p Environment')[1])
check('config paths rewritten',sh("grep -c sftpgo.db /etc/gonas/gonas.json")[1]=='0' and '/var/lib/gonas/gonas.db' in open('/etc/gonas/gonas.json').read(),sh('grep -n sftpgo /etc/gonas/gonas.json')[1])
check('no SFTPGO_ left in env files',sh("grep -rl SFTPGO_ /etc/gonas")[1]=='',sh("grep -rl SFTPGO_ /etc/gonas")[1])
check('host keys private and owned by gonas',sh('stat -c "%U %a" /etc/gonas/id_ed25519')[1]=='gonas 600',sh('stat -c "%U %a" /etc/gonas/id_ed25519')[1])
check('new secrets not world readable',sh('stat -c "%U %a" /etc/gonas/env.d/custom.env')[1].split()[0]=='gonas' and sh('stat -c %a /etc/gonas')[1]=='750',sh('stat -c "%U %a" /etc/gonas /etc/gonas/env.d/custom.env /etc/gonas/gonas.env')[1])
check('rollback copy intact',os.path.exists('/etc/sftpgo/id_rsa') and os.path.exists('/var/lib/sftpgo/sftpgo.db') and os.path.exists('/etc/sftpgo/env.d/custom.env'))
check('TOTP issuer renamed',sh("grep -c '\"issuer\": \"GoNAS\"' /etc/gonas/gonas.json")[1]=='1')
check('migration marker',os.path.exists('/var/lib/gonas/.migrated-from-sftpgo') and not os.path.exists('/var/lib/gonas/.migrating-from-sftpgo'))
print('FAILED',bad) if bad else print('ALL PASSED')
sys.exit(1 if bad else 0)
