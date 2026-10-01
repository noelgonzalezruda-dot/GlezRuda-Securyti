import os, sys, json, hashlib, shutil, sqlite3, time, signal
from pathlib import Path

BASE = Path(os.getenv('LOCALAPPDATA', str(Path.home()))) / 'GlezRudaSecurity'
DB=BASE/'security.db'; QUAR=BASE/'quarantine'; CFG=BASE/'config.json'; SIG=BASE/'signatures.txt'
PID=BASE/'engine.pid'; LOG=BASE/'engine.log'
BASE.mkdir(parents=True, exist_ok=True); QUAR.mkdir(exist_ok=True)
DEFAULT_CFG={'exclusions':[], 'max_file_mb':250, 'realtime_enabled':True, 'realtime_auto_quarantine':True}
BUILTIN_SIGS={'275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f':'EICAR-Test-File'}

def log(msg):
    try:
        with LOG.open('a',encoding='utf-8') as f: f.write(f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] {msg}\n')
    except: pass

def init_db():
    con=sqlite3.connect(DB); cur=con.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, ts TEXT, path TEXT, sha256 TEXT, verdict TEXT, threat TEXT)')
    cur.execute('CREATE TABLE IF NOT EXISTS quarantine(id INTEGER PRIMARY KEY, ts TEXT, original TEXT, stored TEXT, sha256 TEXT, threat TEXT)')
    con.commit(); con.close()

def load_cfg():
    if not CFG.exists(): CFG.write_text(json.dumps(DEFAULT_CFG,indent=2),encoding='utf-8')
    try: return {**DEFAULT_CFG, **json.loads(CFG.read_text(encoding='utf-8'))}
    except: return DEFAULT_CFG.copy()

def signatures():
    s=dict(BUILTIN_SIGS)
    if SIG.exists():
        for line in SIG.read_text(encoding='utf-8',errors='ignore').splitlines():
            line=line.strip()
            if not line or line.startswith('#'): continue
            p=line.split(',',1); h=p[0].strip().lower()
            if len(h)==64: s[h]=p[1].strip() if len(p)>1 else 'Known threat'
    return s

def excluded(path,cfg):
    try: p=os.path.normcase(os.path.abspath(path))
    except: return False
    for x in cfg.get('exclusions',[]):
        try:
            q=os.path.normcase(os.path.abspath(x))
            if p==q or p.startswith(q+os.sep): return True
        except: pass
    return False

def sha256(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()

def record(path,h,verdict,threat=''):
    con=sqlite3.connect(DB,timeout=10); con.execute('INSERT INTO scans(ts,path,sha256,verdict,threat) VALUES(datetime("now","localtime"),?,?,?,?)',(path,h,verdict,threat)); con.commit(); con.close()

def quarantine_file(path,h,threat):
    stamp=str(int(time.time()*1000)); dest=QUAR/(stamp+'_'+h[:12]+'.qtn')
    shutil.move(path,dest)
    con=sqlite3.connect(DB,timeout=10); con.execute('INSERT INTO quarantine(ts,original,stored,sha256,threat) VALUES(datetime("now","localtime"),?,?,?,?)',(path,str(dest),h,threat)); con.commit(); con.close()

def targets(cfg):
    home=Path.home(); candidates=[home/'Downloads',home/'Desktop',home/'Documents']
    return [p for p in candidates if p.exists() and not excluded(str(p),cfg)]

def already_running():
    if not PID.exists(): return False
    try:
        pid=int(PID.read_text().strip())
        if pid==os.getpid(): return False
        import ctypes
        SYNCHRONIZE=0x00100000
        h=ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE,False,pid)
        if h: ctypes.windll.kernel32.CloseHandle(h); return True
    except: pass
    try: PID.unlink()
    except: pass
    return False

def main():
    if already_running(): return
    init_db(); PID.write_text(str(os.getpid()),encoding='ascii'); log('Motor V1.4 iniciado')
    seen={}
    try:
        while True:
            cfg=load_cfg()
            if not cfg.get('realtime_enabled',True): time.sleep(2); continue
            sigs=signatures()
            for base in targets(cfg):
                for root,dirs,files in os.walk(base):
                    dirs[:]=[d for d in dirs if not excluded(os.path.join(root,d),cfg)]
                    for name in files:
                        path=os.path.join(root,name)
                        if excluded(path,cfg): continue
                        try:
                            st=os.stat(path); marker=(st.st_mtime_ns,st.st_size)
                            if seen.get(path)==marker: continue
                            seen[path]=marker
                            if st.st_size>cfg.get('max_file_mb',250)*1024*1024: continue
                            h=sha256(path); threat=sigs.get(h,'')
                            if threat:
                                record(path,h,'AMENAZA-TIEMPO-REAL',threat)
                                log(f'Amenaza detectada: {threat} | {path}')
                                if cfg.get('realtime_auto_quarantine',True):
                                    try: quarantine_file(path,h,threat); log('Cuarentena automática completada')
                                    except Exception as e: log(f'Error de cuarentena: {e}')
                        except (PermissionError,FileNotFoundError,OSError): pass
            time.sleep(2)
    finally:
        try: PID.unlink()
        except: pass
        log('Motor detenido')

if __name__=='__main__': main()
