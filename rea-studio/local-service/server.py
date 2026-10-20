#!/usr/bin/env python3
"""REA Studio loopback analysis bridge. Python 3.10+, stdlib only."""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import json, os, secrets, shutil, subprocess, tempfile, threading, time, uuid, zipfile, urllib.request, urllib.error

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get('REA_STUDIO_DATA', str(Path.home() / '.rea-studio'))).resolve()
DATA.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = DATA / 'providers.json'
MAX_UPLOAD = 100 * 1024 * 1024
TOKEN = os.environ.get('REA_STUDIO_TOKEN') or secrets.token_urlsafe(32)
JOBS = {}
LOCK = threading.Lock()

def config():
    try: return json.loads(CONFIG_PATH.read_text('utf-8'))
    except Exception: return {}

def provider_path(name):
    c = config(); p = c.get(name) or os.environ.get({'ghidra':'REA_GHIDRA_HEADLESS','jadx':'REA_JADX','ida':'REA_IDA'}[name])
    if not p: return None
    path = Path(p).expanduser()
    if path.is_file(): return str(path.resolve())
    return shutil.which(p)

def providers():
    result = {}
    for name in ('ghidra','jadx','ida'):
        p = provider_path(name)
        result[name] = {'configured': bool(p), 'path': p if p else None, 'supported': name in ('ghidra','jadx','ida')}
    return result

def update_job(jid, **kwargs):
    with LOCK:
        if jid in JOBS: JOBS[jid].update(kwargs)

def worker(jid, provider, filename, payload):
    jobdir = DATA / 'jobs' / jid; jobdir.mkdir(parents=True, exist_ok=True)
    source = jobdir / Path(filename).name
    source.write_bytes(payload)
    update_job(jid, status='running', progress=5, message='Input staged in local workspace', started=time.time())
    try:
        exe = provider_path(provider)
        if not exe: raise RuntimeError(f'{provider} is not configured. Set its executable path in providers.json.')
        if provider == 'ghidra':
            project = jobdir / 'project'; project.mkdir(exist_ok=True)
            project_name = 'REA_' + jid[:8]
            export_json = jobdir / 'functions.json'
            cmd = [exe, str(project), project_name, '-scriptPath', str(ROOT / 'ghidra_scripts'), '-import', str(source), '-overwrite', '-analysisTimeoutPerFile', '300', '-max-cpu', '2', '-postScript', 'ExportFunctions.java', str(export_json)]
            update_job(jid, progress=15, message='Running Ghidra headless import and analysis', command_label='Ghidra analyzeHeadless (no shell)')
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace', cwd=str(jobdir))
        elif provider == 'jadx':
            if source.suffix.lower() not in ('.apk','.dex','.jar','.class','.aar','.aab','.zip','.smali','.arsc') and not zipfile.is_zipfile(source): raise RuntimeError('JADX job expects APK, DEX, JAR, AAR, AAB, ZIP, class, or smali input.')
            out = jobdir / 'jadx-out'
            cmd = [exe, '--no-res', '-d', str(out), str(source)]
            update_job(jid, progress=15, message='Running JADX decompilation', command_label='JADX CLI (no shell)')
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace', cwd=str(jobdir))
        elif provider == 'ida':
            if source.suffix.lower() not in ('.exe','.dll','.sys','.efi','.bin','.elf','.so','.dylib','.macho','.o','.obj'):
                raise RuntimeError('IDA job expects a native executable/object. Use JADX for APK/DEX inputs.')
            script = ROOT / 'ida_export.py'; export_json = jobdir / 'ida-evidence.json'
            # IDA batch syntax: -A unattended, -S<script> [script args], then input path. No shell is used.
            cmd = [exe, '-A', '-S' + str(script) + ' ' + str(export_json), str(source)]
            update_job(jid, progress=15, message='Running licensed IDA batch analysis', command_label='IDA batch (-A/-S, no shell)')
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace', cwd=str(jobdir))
        else: raise RuntimeError('Unsupported provider')
        lines=[]; started=time.time()
        while proc.poll() is None:
            if time.time()-started > 360:
                proc.kill(); raise RuntimeError('Analysis timed out after 360 seconds.')
            if JOBS.get(jid,{}).get('cancel_requested'):
                proc.terminate()
                try: proc.wait(timeout=3)
                except subprocess.TimeoutExpired: proc.kill()
                update_job(jid,status='cancelled',progress=0,message='Cancelled by user; partial output retained locally.')
                return
            line=proc.stdout.readline()
            if line:
                lines.append(line.rstrip()[:1000]); lines=lines[-300:]
                update_job(jid, progress=min(90, JOBS.get(jid,{}).get('progress',15)+1), message=line.strip()[:300] or 'Analysis running')
            else: time.sleep(.1)
        remainder=proc.stdout.read()
        if remainder: lines.extend(remainder.splitlines()[-30:])
        log=jobdir/'tool-output.log'; log.write_text('\n'.join(lines),encoding='utf-8',errors='replace')
        if proc.returncode != 0: raise RuntimeError(f'{provider} exited with code {proc.returncode}. See tool-output.log.')
        # Deterministic JADX source-level manifest and cross-reference inventory.
        android_evidence = None
        if provider == 'jadx':
            try:
                from android_analysis import analyze_jadx_tree
                android_evidence = analyze_jadx_tree(jobdir / 'jadx-out')
            except Exception as android_error:
                android_evidence = {'note':'Android evidence extraction failed: '+str(android_error), 'permissions':[], 'components':[], 'methods':[], 'crossReferences':[]}
        # Add structured disassembly evidence to each function for interactive navigation/CFG rendering.
        evidence_file = jobdir / ('functions.json' if provider == 'ghidra' else 'ida-evidence.json')
        try:
            if evidence_file.exists():
                ev=json.loads(evidence_file.read_text('utf-8',errors='replace'))
                update_job(jid, evidence=ev)
        except Exception as parse_error:
            update_job(jid, evidence_warning='Could not parse structured provider evidence: '+str(parse_error))
        artifacts=[]
        for p in jobdir.rglob('*'):
            if p.is_file() and p.name != source.name:
                artifacts.append({'path':str(p.relative_to(jobdir)),'size':p.stat().st_size})
        update_job(jid,status='completed',progress=100,message='Provider finished successfully; inspect generated artifacts and logs.',result={'provider':provider,'input':source.name,'output_dir':str(jobdir),'artifacts':artifacts,'log':str(log),'last_output':lines[-80:], 'android':android_evidence})
    except Exception as e:
        update_job(jid,status='failed',progress=0,message=str(e),error_type=type(e).__name__)

class Handler(BaseHTTPRequestHandler):
    server_version='REAStudioBridge/1.0'
    def log_message(self, fmt, *args): print('[REA Studio]', fmt % args)
    def send_json(self, code, data):
        raw=json.dumps(data).encode(); self.send_response(code); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(raw))); self.send_header('Cache-Control','no-store'); self.send_header('Access-Control-Allow-Origin','http://127.0.0.1:8080'); self.end_headers(); self.wfile.write(raw)
    def authorized(self): return secrets.compare_digest(self.headers.get('Authorization',''), 'Bearer '+TOKEN)
    def do_OPTIONS(self):
        self.send_response(204); self.send_header('Access-Control-Allow-Origin','http://127.0.0.1:8080'); self.send_header('Access-Control-Allow-Headers','Authorization, Content-Type'); self.send_header('Access-Control-Allow-Methods','GET, POST, DELETE, OPTIONS'); self.end_headers()
    def do_GET(self):
        if not self.authorized(): return self.send_json(401,{'error':'Missing or invalid bearer token. See token printed when service starts.'})
        path=urlparse(self.path).path
        if path=='/api/health': return self.send_json(200,{'ok':True,'service':'REA Studio local bridge','version':'1.0','providers':providers(),'maxUploadBytes':MAX_UPLOAD})
        if path=='/api/jobs': return self.send_json(200,{'jobs':list(JOBS.values())[-100:]})
        if path.startswith('/api/jobs/') and path.endswith('/evidence'):
            jid=path.split('/')[-2]; j=JOBS.get(jid)
            return self.send_json(200,{'jobId':jid,'evidence':j.get('evidence',{}),'policy':'Explanations must cite only these provider-derived facts; no evidence means no claim.'}) if j else self.send_json(404,{'error':'Job not found'})
        if path.startswith('/api/jobs/'):
            jid=path.rsplit('/',1)[-1]; j=JOBS.get(jid)
            return self.send_json(200,j) if j else self.send_json(404,{'error':'Job not found'})
        return self.send_json(404,{'error':'Not found'})
    def do_POST(self):
        if not self.authorized(): return self.send_json(401,{'error':'Missing or invalid bearer token.'})
        path=urlparse(self.path).path
        if path=='/api/providers':
            n=int(self.headers.get('Content-Length','0'))
            if n>65536: return self.send_json(413,{'error':'Configuration too large'})
            try:
                body=json.loads(self.rfile.read(n)); clean={k:str(body[k]) for k in ('ghidra','jadx','ida') if body.get(k)}
                CONFIG_PATH.write_text(json.dumps(clean,indent=2),encoding='utf-8')
                return self.send_json(200,{'saved':True,'providers':providers()})
            except Exception as e: return self.send_json(400,{'error':str(e)})
        if path=='/api/explain':
            n=int(self.headers.get('Content-Length','0'))
            if n<=0 or n>65536: return self.send_json(413,{'error':'Request body must be 1..65536 bytes'})
            try:
                body=json.loads(self.rfile.read(n)); jid=str(body.get('jobId','')); entry=str(body.get('entry',''))
                j=JOBS.get(jid); ev=(j or {}).get('evidence') or {}; funcs=ev.get('functions') or []
                fn=next((f for f in funcs if str(f.get('entry',''))==entry),None)
                if not fn: return self.send_json(404,{'error':'Function evidence not found in completed provider results'})
                endpoint=os.environ.get('REA_AI_BASE_URL'); api_key=os.environ.get('REA_AI_API_KEY'); model=os.environ.get('REA_AI_MODEL')
                if not endpoint or not api_key or not model:
                    return self.send_json(503,{'error':'AI explanation is not configured. Set REA_AI_BASE_URL, REA_AI_API_KEY, and REA_AI_MODEL before starting the bridge.'})
                evidence={'provider':ev.get('provider'),'program':ev.get('program'),'function':fn,'relatedFunctions':[f for f in funcs if any(str(c.get('address'))==str(f.get('entry')) for c in fn.get('calls',[]))][:20]}
                system='You are a reverse-engineering assistant. Explain only what the supplied static-analysis evidence supports. Cite exact function entry addresses, instruction addresses, call target names/addresses, and basic-block edges. Distinguish observation from inference; state uncertainty and missing evidence. Never invent instruction bytes, xrefs, APIs, or behaviour. If evidence is insufficient, say so. Do not provide exploit instructions.'
                user='Question: '+str(body.get('question') or 'Explain this function and its control flow.')[:2000]+'\nEvidence JSON:\n'+json.dumps(evidence,ensure_ascii=False)[:90000]
                req=urllib.request.Request(endpoint.rstrip('/')+'/chat/completions',data=json.dumps({'model':model,'messages':[{'role':'system','content':system},{'role':'user','content':user}],'temperature':0.1}).encode(),headers={'Authorization':'Bearer '+api_key,'Content-Type':'application/json'},method='POST')
                try:
                    with urllib.request.urlopen(req,timeout=45) as resp: answer=json.loads(resp.read(2*1024*1024))
                except urllib.error.HTTPError as e: return self.send_json(502,{'error':'Configured AI endpoint returned HTTP '+str(e.code)})
                choices=answer.get('choices') or []; content=((choices[0].get('message') or {}).get('content') if choices else None)
                if not content: return self.send_json(502,{'error':'AI endpoint returned no assistant content'})
                return self.send_json(200,{'jobId':jid,'entry':entry,'provider':ev.get('provider'),'model':model,'answer':content,'evidenceAnchors':{'entry':fn.get('entry'),'instructions':[i.get('address') for i in (fn.get('instructions') or [])[:100]],'calls':fn.get('calls') or [],'basicBlocks':fn.get('basicBlocks') or []}})
            except Exception as e: return self.send_json(400,{'error':'Could not prepare evidence explanation: '+str(e)})
        if path=='/api/jobs':
            provider=parse_qs(urlparse(self.path).query).get('provider',[''])[0]
            if provider not in ('ghidra','jadx','ida'): return self.send_json(400,{'error':'provider must be ghidra, jadx, or ida'})
            try: n=int(self.headers.get('Content-Length','0'))
            except ValueError: return self.send_json(411,{'error':'Content-Length required'})
            if n<=0 or n>MAX_UPLOAD: return self.send_json(413,{'error':f'Upload must be between 1 byte and {MAX_UPLOAD} bytes'})
            filename=Path(parse_qs(urlparse(self.path).query).get('filename',['artifact.bin'])[0]).name
            payload=self.rfile.read(n); jid=uuid.uuid4().hex
            job={'id':jid,'provider':provider,'filename':filename,'status':'queued','progress':0,'message':'Queued','created':time.time()}
            with LOCK: JOBS[jid]=job
            threading.Thread(target=worker,args=(jid,provider,filename,payload),daemon=True).start()
            return self.send_json(202,job)
        return self.send_json(404,{'error':'Not found'})
    def do_DELETE(self):
        if not self.authorized(): return self.send_json(401,{'error':'Missing or invalid bearer token.'})
        jid=urlparse(self.path).path.rsplit('/',1)[-1]
        if jid not in JOBS: return self.send_json(404,{'error':'Job not found'})
        update_job(jid,cancel_requested=True,message='Cancellation requested')
        return self.send_json(202,{'ok':True,'id':jid,'message':'Cancellation requested'})

if __name__=='__main__':
    host='127.0.0.1'; port=int(os.environ.get('REA_STUDIO_PORT','8765'))
    print('\nREA Studio local analysis bridge')
    print(f'Listening only on http://{host}:{port}')
    print(f'Bearer token (keep private): {TOKEN}')
    print(f'Provider config: {CONFIG_PATH}')
    print('Ctrl+C to stop. Only launch on files you are authorized to analyze.\n')
    ThreadingHTTPServer((host,port),Handler).serve_forever()
