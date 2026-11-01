import base64,hashlib,hmac,json,struct,time,urllib.request,urllib.error,sys
def totp(s):
    k=base64.b32decode(s+'='*(-len(s)%8)); c=struct.pack('>Q',int(time.time())//30)
    h=hmac.new(k,c,hashlib.sha1).digest(); o=h[19]&15
    return '%06d'%((struct.unpack('>I',h[o:o+4])[0]&0x7fffffff)%1000000)
def call(url,method='GET',token=None,body=None,headers=None,basic=None):
    h=dict(headers or {})
    if token: h['Authorization']='Bearer '+token
    if basic: h['Authorization']='Basic '+base64.b64encode(basic.encode()).decode()
    d=None
    if body is not None: d=json.dumps(body).encode(); h['Content-Type']='application/json'
    r=urllib.request.Request(url,data=d,method=method,headers=h)
    try:
        x=urllib.request.urlopen(r,timeout=10); raw=x.read(); code=x.status
    except urllib.error.HTTPError as e:
        raw=e.read(); code=e.code
    try: return code,json.loads(raw)
    except Exception: return code,raw
