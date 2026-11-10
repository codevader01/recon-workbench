"""Recon Workbench — educational, authorization-aware footprinting workspace."""
from __future__ import annotations
import asyncio
from collections import Counter
from datetime import datetime, timezone
from email import policy
from email.parser import Parser
import io
import ipaddress
import re
import socket
import ssl
from urllib.parse import quote

import dns.asyncresolver
import httpx
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from PIL import Image, ExifTags

app = FastAPI(title="Recon Workbench", version="1.0.0", description="PDF-inspired responsible reconnaissance dashboard")
app.mount('/static', StaticFiles(directory='static'), name='static')
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
DNS_TYPES = ('A','AAAA','MX','NS','TXT','CAA','SOA','CNAME')

class Target(BaseModel):
    domain: str = Field(min_length=4, max_length=253)
    authorized: bool = False

class HeaderBody(BaseModel):
    raw: str = Field(min_length=1, max_length=200000)

class SearchBody(BaseModel):
    domain: str
    keyword: str = Field(default='', max_length=100)
    category: str = 'pdf'

def clean_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip('.')
    if '://' in domain or '/' in domain or ':' in domain or '@' in domain or not DOMAIN_RE.fullmatch(domain):
        raise HTTPException(422, detail='Enter a valid public domain (example.com), not a URL or IP address.')
    return domain

async def dns_data(domain: str):
    async def lookup(kind):
        try:
            answers = await dns.asyncresolver.resolve(domain, kind, lifetime=3.5, raise_on_no_answer=False)
            return kind, [str(x).rstrip('.') for x in answers][:40] if answers.rrset else []
        except Exception:
            return kind, []
    return dict(await asyncio.gather(*(lookup(t) for t in DNS_TYPES)))

def summarize(domain, records, subdomains=None):
    issues=[]
    if not records.get('MX'): issues.append({'level':'info','name':'No MX record','detail':'This domain may not accept inbound email; confirm whether that is intended.'})
    if not records.get('CAA'): issues.append({'level':'medium','name':'No CAA policy observed','detail':'Consider restricting certificate issuers through CAA DNS records.'})
    txt=' '.join(records.get('TXT',[])).lower()
    if not re.search(r'v=spf1\b',txt): issues.append({'level':'medium','name':'SPF not observed','detail':'If this domain sends email, review SPF, DKIM, and DMARC deployment.'})
    if not records.get('A') and not records.get('AAAA'): issues.append({'level':'info','name':'No apex address record','detail':'Apex records were not resolved; this can be intentional.'})
    if subdomains and len(subdomains)>30: issues.append({'level':'info','name':'Broad public subdomain inventory','detail':'Review externally visible names for unnecessary exposure; quantity alone is not a vulnerability.'})
    return issues

@app.get('/')
def index(): return FileResponse('static/index.html')

@app.get('/api/health')
def health(): return {'status':'ok','time': datetime.now(timezone.utc).isoformat()}

@app.post('/api/dns')
async def dns_lookup(t:Target):
    domain=clean_domain(t.domain)
    if not t.authorized: raise HTTPException(403,'Confirm authorization for live DNS queries.')
    records=await dns_data(domain)
    return {'domain':domain,'records':records,'findings':summarize(domain,records), 'method':'Live public DNS resolution; responses are not evidence of exploitability.'}

@app.post('/api/rdap')
async def rdap_lookup(t:Target):
    domain=clean_domain(t.domain)
    # RDAP is public registration data via third-party lookup, no direct host access.
    url=f'https://rdap.org/domain/{quote(domain)}'
    try:
        async with httpx.AsyncClient(timeout=9, follow_redirects=True) as client:
            r=await client.get(url,headers={'Accept':'application/rdap+json'})
        if r.status_code!=200: raise HTTPException(502,f'RDAP registry returned HTTP {r.status_code}')
        obj=r.json()
    except httpx.HTTPError as exc: raise HTTPException(502,f'RDAP service unreachable: {type(exc).__name__}')
    return {'domain':domain,'handle':obj.get('handle'),'status':obj.get('status',[]),'nameservers':[n.get('ldhName') for n in obj.get('nameservers',[]) if n.get('ldhName')], 'events':[{'type':e.get('eventAction'),'date':e.get('eventDate')} for e in obj.get('events',[])][:15], 'notices':[n.get('title') for n in obj.get('notices',[])][:6], 'source':url, 'note':'Personal registration records may be redacted by the registry.'}

@app.post('/api/subdomains')
async def subdomains(t:Target):
    domain=clean_domain(t.domain)
    # Public certificate transparency index; no probing discovered hosts.
    try:
        async with httpx.AsyncClient(timeout=14) as client:
            resp=await client.get('https://crt.sh/',params={'q':f'%.{domain}','output':'json'},headers={'User-Agent':'ReconWorkbench/1.0'})
        if resp.status_code!=200: raise HTTPException(502,f'Certificate transparency service returned {resp.status_code}')
        data=resp.json()
    except (httpx.HTTPError,ValueError) as exc: raise HTTPException(502,f'Certificate transparency lookup failed: {type(exc).__name__}')
    names=set()
    for item in data[:6000]:
        for raw in item.get('name_value','').splitlines():
            host=raw.lower().strip().removeprefix('*.').rstrip('.')
            if DOMAIN_RE.fullmatch(host) and host.endswith('.'+domain): names.add(host)
    return {'domain':domain,'count':len(names),'subdomains':sorted(names)[:500], 'truncated':len(names)>500, 'method':'Certificate transparency (crt.sh), not validated as live or in scope.'}

@app.post('/api/tls')
async def tls_lookup(t:Target):
    domain=clean_domain(t.domain)
    if not t.authorized: raise HTTPException(403,'Confirm authorization for connecting to the target.')
    # Pre-resolution guard against directly targeting private/local address space.
    try:
        infos=await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo,domain,443,type=socket.SOCK_STREAM),timeout=5)
    except Exception: raise HTTPException(502,'Could not resolve target domain')
    addresses=sorted({x[4][0] for x in infos})
    if not addresses or any(not ipaddress.ip_address(x).is_global for x in addresses):
        raise HTTPException(403,'Private, local, or special-use target addresses are blocked.')
    def probe():
        ctx=ssl.create_default_context()
        # Bind to the validated IP while retaining TLS SNI and certificate hostname checking.
        with socket.create_connection((addresses[0],443),timeout=5) as sock:
            with ctx.wrap_socket(sock,server_hostname=domain) as s:
                c=s.getpeercert()
                return {'tls_version':s.version(),'cipher':s.cipher()[0] if s.cipher() else None,'issuer':dict(x[0] for x in c.get('issuer',[])),'subject':dict(x[0] for x in c.get('subject',[])),'valid_from':c.get('notBefore'),'valid_until':c.get('notAfter'),'subject_alt_names':[x[1] for x in c.get('subjectAltName',[]) if x[0]=='DNS'][:100]}
    try: output=await asyncio.wait_for(asyncio.to_thread(probe), timeout=9)
    except Exception as exc: raise HTTPException(502,f'TLS probe unsuccessful: {type(exc).__name__} (certificate validation is enforced)')
    return {'domain':domain,'result':output,'method':'One direct HTTPS TLS handshake, certificate verified.'}

@app.post('/api/headers')
def analyze_headers(body:HeaderBody):
    # No network traffic or external upload.
    message=Parser(policy=policy.default).parsestr(body.raw,headersonly=True)
    received=message.get_all('Received',[])
    auth=message.get_all('Authentication-Results',[])
    def detect(marker):
        matches=[]
        for line in auth:
            matches += re.findall(r'\b'+marker+r'=(pass|fail|softfail|neutral|none|temperror|permerror)\b',str(line),re.I)
        return list(dict.fromkeys(x.lower() for x in matches))
    return {'from':str(message.get('From','')),'to':str(message.get('To','')),'subject':str(message.get('Subject','')),'date':str(message.get('Date','')),'message_id':str(message.get('Message-ID','')),'return_path':str(message.get('Return-Path','')),'reply_to':str(message.get('Reply-To','')),'originating_ip':str(message.get('X-Originating-IP','')),'received_hops':list(reversed([str(x) for x in received]))[:35], 'hop_count':len(received),'authentication':{k:detect(k) for k in ['spf','dkim','dmarc']},'warnings':['Received headers are not guaranteed authentic; a sender can forge some hops.','Many mail providers hide the sending device IP.']}

@app.post('/api/exif')
async def exif_analysis(file:UploadFile=File(...)):
    data=await file.read(10*1024*1024+1)
    if len(data)>10*1024*1024: raise HTTPException(413,'Maximum image size is 10 MB.')
    try:
        im=Image.open(io.BytesIO(data)); im.verify()
        im=Image.open(io.BytesIO(data))
        raw=im.getexif(); exif={ExifTags.TAGS.get(k,str(k)):v for k,v in raw.items()}
        gps=raw.get_ifd(34853) if 34853 in raw else {}
        gps={ExifTags.GPSTAGS.get(k,str(k)):v for k,v in gps.items()}
    except Exception: raise HTTPException(422,'Invalid image file.')
    def coord(value, ref):
        try:
            val=sum(float(v)/60**i for i,v in enumerate(value))
            return -val if str(ref).upper() in ('S','W') else val
        except Exception:return None
    lat=coord(gps.get('GPSLatitude',[]),gps.get('GPSLatitudeRef','N'))
    lon=coord(gps.get('GPSLongitude',[]),gps.get('GPSLongitudeRef','E'))
    fields={}
    for name in ['Make','Model','DateTime','DateTimeOriginal','Software','Artist','Copyright','LensModel']:
        if name in exif: fields[name]=str(exif[name])[:300]
    return {'filename':file.filename,'format':im.format,'dimensions':list(im.size),'fields':fields,'gps':{'latitude':lat,'longitude':lon} if lat is not None and lon is not None and -90<=lat<=90 and -180<=lon<=180 else None,'gps_present':bool(gps),'note':'EXIF may be absent, edited, or stripped by messaging services. Handle location details as sensitive.'}

@app.post('/api/search')
def search_builder(body:SearchBody):
    domain=clean_domain(body.domain)
    keyword=re.sub(r'[^a-zA-Z0-9 ._/-]','',body.keyword).strip()[:80]
    patterns={'pdf':'filetype:pdf','docs':'filetype:docx','pages':'intitle:'+('"'+keyword+'"' if keyword else '"documentation"'),'news':'after:2024-01-01','all':''}
    if body.category not in patterns: raise HTTPException(422,'Unknown search category')
    q=' '.join(x for x in [f'site:{domain}',patterns[body.category],keyword if body.category!='pages' else ''] if x)
    return {'query':q,'google':'https://www.google.com/search?q='+quote(q),'bing':'https://www.bing.com/search?q='+quote(q),'note':'Search is restricted to the submitted domain. Operators are supported differently by search engines.'}
