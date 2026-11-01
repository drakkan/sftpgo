import sys; sys.path.insert(0,'/root')
from lib import *
A='http://127.0.0.1:8090/api/v2'
c,r=call(A+'/token',basic='admin:Seed-Admin-Pass-1'); assert c==200,r; t=r['access_token']
pub=open('/root/client_key.pub').read().strip()
def user(n,**k):
    b=dict(username=n,password='Seed-User-Pass-1',status=1,permissions={'/':['*']},home_dir=f'/srv/sftpgo/data/{n}'); b.update(k)
    c,r=call(A+'/users','POST',t,b); assert c==201,(n,r)
user('alice',public_keys=[pub])
user('bob',public_keys=[pub],home_dir='/mnt/ext/bob')
user('dave',filesystem={'provider':1,'s3config':{'bucket':'b','region':'eu-west-1','access_key':'k','access_secret':{'status':'Plain','payload':'super-secret-s3'}}})
user('carol')
c,r=call(A+'/admins/admin','GET',t); r['filters']['allow_api_key_auth']=True; c,x=call(A+'/admins/admin','PUT',t,r); assert c==200,x
c,r=call(A+'/apikeys','POST',t,dict(name='ci',scope=1,admin='admin')); assert c==201,r; open('/root/apikey','w').write(r['key'])
c,r=call(A+'/user/token',basic='carol:Seed-User-Pass-1'); assert c==200,r; u=r['access_token']
c,r=call(A+'/user/totp/configs','GET',u); cfg=r[0]['name']
c,r=call(A+'/user/totp/generate','POST',u,dict(config_name=cfg)); assert c==200,r; sec=r['secret']; open('/root/totp','w').write(sec)
c,r=call(A+'/user/totp/validate','POST',u,dict(config_name=cfg,passcode=totp(sec),secret=sec)); assert c==200,r
c,r=call(A+'/user/totp/save','POST',u,dict(enabled=True,config_name=cfg,secret=dict(status='Plain',payload=sec),protocols=['HTTP'])); assert c==200,r
print('seeded', [x['username'] for x in call(A+'/users',token=t)[1]])
