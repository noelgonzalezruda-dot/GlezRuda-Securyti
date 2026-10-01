import os, sys, json, hashlib, hmac, base64, platform, uuid, shutil, sqlite3, threading, queue, time, subprocess
from datetime import date, datetime, timedelta
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_NAME='GlezRuda Security V1.4'
LICENSE_FILE_NAME='license.json'
# Cambia este secreto antes de distribuir comercialmente la app y conserva el generador en privado.
LICENSE_SECRET=b'GLEZRUDA-SECURITY-V1-CHANGE-THIS-PRIVATE-SECRET'
LICENSE_DAYS=365
BASE = Path(os.getenv('LOCALAPPDATA', str(Path.home()))) / 'GlezRudaSecurity'
DB=BASE/'security.db'; QUAR=BASE/'quarantine'; CFG=BASE/'config.json'; SIG=BASE/'signatures.txt'
BASE.mkdir(parents=True, exist_ok=True); QUAR.mkdir(exist_ok=True)
ENGINE_PID=BASE/'engine.pid'; ENGINE_LOG=BASE/'engine.log'
DEFAULT_CFG={'exclusions':[], 'max_file_mb':250, 'realtime_enabled':True, 'realtime_auto_quarantine':True}

# EICAR SHA256: harmless industry test file signature; no malware payload is bundled.
BUILTIN_SIGS={
 '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f':'EICAR-Test-File'
}



def machine_id():
    raw = f"{platform.node()}|{uuid.getnode()}|{platform.system()}|{platform.machine()}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:20].upper()

def license_path(): return BASE/LICENSE_FILE_NAME

def license_signature(mid, expiry):
    msg=f"{mid}|{expiry}|GLEZRUDA-SECURITY".encode()
    return hmac.new(LICENSE_SECRET,msg,hashlib.sha256).hexdigest()[:32].upper()

def make_key(mid, expiry):
    sig=license_signature(mid,expiry)
    raw=f"{expiry}|{sig}".encode()
    token=base64.b32encode(raw).decode().rstrip('=')
    return '-'.join(token[i:i+5] for i in range(0,len(token),5))

def decode_key(key):
    clean=''.join(c for c in key.upper() if c.isalnum())
    clean += '='*((8-len(clean)%8)%8)
    try:
        raw=base64.b32decode(clean).decode()
        expiry,sig=raw.split('|',1); return expiry,sig
    except Exception: return None,None

def validate_key(mid,key):
    expiry,sig=decode_key(key)
    if not expiry or not sig: return False,'Formato de clave inválido.'
    try: exp=date.fromisoformat(expiry)
    except: return False,'Fecha de licencia inválida.'
    if not hmac.compare_digest(sig,license_signature(mid,expiry)): return False,'La clave no corresponde a este equipo.'
    if exp < date.today(): return False,f'La licencia venció el {expiry}.'
    return True,expiry

def saved_license_status():
    lp=license_path()
    if not lp.exists(): return False,'Sin activar'
    try:
        d=json.loads(lp.read_text(encoding='utf-8'))
        return validate_key(machine_id(),d.get('key',''))
    except: return False,'Licencia dañada'

def activation_dialog(root):
    ok,info=saved_license_status()
    if ok:return True
    result={'ok':False}; mid=machine_id()
    w=tk.Toplevel(root); w.title('Activación • GlezRuda Security'); w.geometry('590x360'); w.resizable(False,False); w.configure(bg='#0b1220'); w.grab_set()
    tk.Label(w,text='ACTIVACIÓN DE GLEZRUDA SECURITY',bg='#0b1220',fg='white',font=('Segoe UI Semibold',17)).pack(pady=(24,8))
    tk.Label(w,text='ID de este equipo',bg='#0b1220',fg='#b8c4d8').pack()
    idv=tk.StringVar(value=mid); e=tk.Entry(w,textvariable=idv,justify='center',font=('Consolas',13),state='readonly',readonlybackground='#111c2f',fg='white');e.pack(fill='x',padx=55,pady=7)
    def copyid(): w.clipboard_clear();w.clipboard_append(mid);messagebox.showinfo('ID','ID del equipo copiado.')
    tk.Button(w,text='Copiar ID',command=copyid).pack()
    tk.Label(w,text='Clave de activación',bg='#0b1220',fg='#b8c4d8').pack(pady=(18,3))
    kv=tk.StringVar(); tk.Entry(w,textvariable=kv,justify='center',font=('Consolas',10)).pack(fill='x',padx=35,pady=5)
    msg=tk.Label(w,text=info,bg='#0b1220',fg='#ffb4a9');msg.pack(pady=4)
    def activate():
        good,detail=validate_key(mid,kv.get().strip())
        if not good: msg.config(text=detail);return
        license_path().write_text(json.dumps({'machine_id':mid,'key':kv.get().strip(),'expires':detail,'activated':datetime.now().isoformat()},indent=2),encoding='utf-8')
        result['ok']=True;messagebox.showinfo('Activación',f'Licencia activada correctamente.\nVálida hasta: {detail}');w.destroy()
    tk.Button(w,text='ACTIVAR',command=activate,font=('Segoe UI Semibold',11),padx=28,pady=8).pack(pady=10)
    w.protocol('WM_DELETE_WINDOW',w.destroy); root.wait_window(w); return result['ok']

def load_cfg():
    if not CFG.exists(): CFG.write_text(json.dumps(DEFAULT_CFG,indent=2),encoding='utf-8')
    try: return {**DEFAULT_CFG, **json.loads(CFG.read_text(encoding='utf-8'))}
    except: return DEFAULT_CFG.copy()

def save_cfg(c): CFG.write_text(json.dumps(c,indent=2),encoding='utf-8')

def init_db():
    con=sqlite3.connect(DB); cur=con.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, ts TEXT, path TEXT, sha256 TEXT, verdict TEXT, threat TEXT)')
    cur.execute('CREATE TABLE IF NOT EXISTS quarantine(id INTEGER PRIMARY KEY, ts TEXT, original TEXT, stored TEXT, sha256 TEXT, threat TEXT)')
    con.commit(); con.close()

def signatures():
    s=dict(BUILTIN_SIGS)
    if SIG.exists():
        for line in SIG.read_text(encoding='utf-8',errors='ignore').splitlines():
            line=line.strip()
            if not line or line.startswith('#'): continue
            p=line.split(',',1); h=p[0].strip().lower()
            if len(h)==64: s[h]=p[1].strip() if len(p)>1 else 'Known threat'
    else:
        SIG.write_text('# One SHA-256 per line: hash,name\n',encoding='utf-8')
    return s

def sha256(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()

def excluded(path,cfg):
    try: p=os.path.normcase(os.path.abspath(path))
    except: return False
    for x in cfg['exclusions']:
        try:
            q=os.path.normcase(os.path.abspath(x))
            if p==q or p.startswith(q+os.sep): return True
        except: pass
    return False

def quarantine_file(path,h,threat):
    stamp=str(int(time.time()*1000)); dest=QUAR/(stamp+'_'+h[:12]+'.qtn')
    shutil.move(path,dest)
    con=sqlite3.connect(DB); con.execute('INSERT INTO quarantine(ts,original,stored,sha256,threat) VALUES(datetime("now","localtime"),?,?,?,?)',(path,str(dest),h,threat)); con.commit(); con.close()
    return dest

def record(path,h,verdict,threat=''):
    con=sqlite3.connect(DB); con.execute('INSERT INTO scans(ts,path,sha256,verdict,threat) VALUES(datetime("now","localtime"),?,?,?,?)',(path,h,verdict,threat)); con.commit(); con.close()

def engine_executable():
    if getattr(sys,'frozen',False): return Path(sys.executable).with_name('GlezRuda_Security_Engine.exe')
    return Path(__file__).with_name('security_engine.py')

def engine_running():
    if not ENGINE_PID.exists(): return False
    try:
        pid=int(ENGINE_PID.read_text().strip())
        if os.name=='nt':
            import ctypes
            h=ctypes.windll.kernel32.OpenProcess(0x00100000,False,pid)
            if h: ctypes.windll.kernel32.CloseHandle(h); return True
    except: pass
    return False

def start_engine():
    if engine_running(): return True
    target=engine_executable()
    try:
        flags=0
        if os.name=='nt': flags=0x08000000 | 0x00000008
        if getattr(sys,'frozen',False): cmd=[str(target)]
        else: cmd=[sys.executable,str(target)]
        subprocess.Popen(cmd,creationflags=flags,close_fds=True)
        for _ in range(20):
            time.sleep(.1)
            if engine_running(): return True
    except Exception: pass
    return False

def startup_cmd():
    if getattr(sys,'frozen',False): return f'"{engine_executable()}"'
    return f'"{sys.executable}" "{engine_executable()}"'

def set_windows_startup(enabled=True):
    if os.name!='nt': return False
    try:
        import winreg
        key=winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Run',0,winreg.KEY_SET_VALUE)
        if enabled: winreg.SetValueEx(key,'GlezRudaSecurityEngine',0,winreg.REG_SZ,startup_cmd())
        else:
            try: winreg.DeleteValue(key,'GlezRudaSecurityEngine')
            except FileNotFoundError: pass
        winreg.CloseKey(key); return True
    except: return False

class App(tk.Tk):
    def __init__(self):
        super().__init__(); init_db(); self.cfg=load_cfg(); self.q=queue.Queue(); self.running=False
        self.title(APP_NAME); self.geometry('1050x690'); self.minsize(900,600); self.configure(bg='#0b1220')
        style=ttk.Style(self); style.theme_use('clam')
        style.configure('TFrame',background='#0b1220'); style.configure('Card.TFrame',background='#111c2f')
        style.configure('TLabel',background='#0b1220',foreground='#e8eef8',font=('Segoe UI',10))
        style.configure('Title.TLabel',background='#0b1220',foreground='#ffffff',font=('Segoe UI Semibold',24))
        style.configure('Status.TLabel',background='#111c2f',foreground='#64e6a7',font=('Segoe UI Semibold',18))
        style.configure('TButton',font=('Segoe UI Semibold',10),padding=9)
        style.configure('Treeview',background='#111c2f',fieldbackground='#111c2f',foreground='#e8eef8',rowheight=28)
        style.configure('Treeview.Heading',font=('Segoe UI Semibold',10))
        self.rt_stop=threading.Event(); self.rt_seen={}
        self.build(); self.after(150,self.poll); self.after(800,self.refresh_engine_status)

    def build(self):
        head=ttk.Frame(self); head.pack(fill='x',padx=24,pady=(20,10))
        ttk.Label(head,text='GLEZRUDA SECURITY',style='Title.TLabel').pack(side='left')
        ttk.Label(head,text='V1.4 • Motor independiente • Licencia activada').pack(side='left',padx=16,pady=12)
        card=ttk.Frame(self,style='Card.TFrame'); card.pack(fill='x',padx=24,pady=10)
        self.status=ttk.Label(card,text='◌  VERIFICANDO MOTOR…',style='Status.TLabel'); self.status.pack(anchor='w',padx=20,pady=(18,5))
        self.detail=ttk.Label(card,text='Comprobando protección en segundo plano…',background='#111c2f'); self.detail.pack(anchor='w',padx=20,pady=(0,8))
        self.rt_var=tk.BooleanVar(value=bool(self.cfg.get('realtime_enabled',True)))
        self.rt_check=ttk.Checkbutton(card,text='Protección en tiempo real',variable=self.rt_var,command=self.toggle_realtime); self.rt_check.pack(anchor='w',padx=20,pady=(0,18))
        bar=ttk.Frame(self); bar.pack(fill='x',padx=24,pady=10)
        ttk.Button(bar,text='Escanear archivo',command=self.pick_file).pack(side='left',padx=(0,8))
        ttk.Button(bar,text='Escanear carpeta',command=self.pick_folder).pack(side='left',padx=8)
        ttk.Button(bar,text='Escaneo rápido',command=self.quick).pack(side='left',padx=8)
        ttk.Button(bar,text='Cuarentena',command=self.show_quarantine).pack(side='left',padx=8)
        ttk.Button(bar,text='Exclusiones',command=self.exclusions).pack(side='left',padx=8)
        ttk.Button(bar,text='Actualizar firmas',command=self.open_sigs).pack(side='left',padx=8)
        self.pb=ttk.Progressbar(self,mode='indeterminate'); self.pb.pack(fill='x',padx=24,pady=(2,10))
        cols=('verdict','threat','path','hash')
        self.tree=ttk.Treeview(self,columns=cols,show='headings')
        for c,t,w in [('verdict','Resultado',110),('threat','Amenaza',150),('path','Archivo',500),('hash','SHA-256',220)]: self.tree.heading(c,text=t); self.tree.column(c,width=w,anchor='w')
        self.tree.pack(fill='both',expand=True,padx=24,pady=(0,12))
        foot=ttk.Label(self,text='Motor independiente: vigila archivos nuevos/modificados incluso con el panel cerrado. Microsoft Defender permanece activo.')
        foot.pack(anchor='w',padx=24,pady=(0,18))


    def toggle_realtime(self):
        self.cfg['realtime_enabled']=bool(self.rt_var.get()); save_cfg(self.cfg)
        if self.cfg['realtime_enabled']:
            set_windows_startup(True); start_engine()
        state='activada' if self.cfg['realtime_enabled'] else 'desactivada'
        self.detail.config(text=f'Protección en tiempo real {state}. El motor de fondo es independiente del panel.')
        self.refresh_engine_status()

    def refresh_engine_status(self):
        if self.cfg.get('realtime_enabled',True):
            running=engine_running()
            if not running: running=start_engine()
            if running:
                self.status.config(text='✓  PROTECCIÓN EN SEGUNDO PLANO ACTIVA')
                self.detail.config(text='Puede cerrar esta ventana: el motor continuará funcionando. Microsoft Defender permanece activo.')
            else:
                self.status.config(text='⚠  MOTOR DE PROTECCIÓN DETENIDO')
                self.detail.config(text='No se pudo iniciar el motor. Revise que GlezRuda_Security_Engine.exe esté junto al programa.')
        else:
            self.status.config(text='○  PROTECCIÓN EN TIEMPO REAL DESACTIVADA')
        self.after(3000,self.refresh_engine_status)

    def realtime_targets(self):
        home=Path.home()
        candidates=[home/'Downloads',home/'Desktop',home/'Documents']
        return [p for p in candidates if p.exists() and not excluded(str(p),self.cfg)]

    def realtime_worker(self):
        # Polling deliberadamente simple: no instala drivers ni interfiere con Defender.
        while not self.rt_stop.is_set():
            if not self.cfg.get('realtime_enabled',True):
                time.sleep(2); continue
            sig=signatures()
            for base in self.realtime_targets():
                for root,dirs,files in os.walk(base):
                    dirs[:]=[d for d in dirs if not excluded(os.path.join(root,d),self.cfg)]
                    for name in files:
                        path=os.path.join(root,name)
                        if excluded(path,self.cfg): continue
                        try:
                            st=os.stat(path); marker=(st.st_mtime_ns,st.st_size)
                            if self.rt_seen.get(path)==marker: continue
                            self.rt_seen[path]=marker
                            if st.st_size>self.cfg['max_file_mb']*1024*1024: continue
                            h=sha256(path); threat=sig.get(h,'')
                            if threat:
                                record(path,h,'AMENAZA-TIEMPO-REAL',threat)
                                if self.cfg.get('realtime_auto_quarantine',True):
                                    try:
                                        quarantine_file(path,h,threat)
                                        self.q.put(('rt_threat',(path,threat,'Cuarentena automática')))
                                    except Exception as e:
                                        self.q.put(('rt_threat',(path,threat,'No se pudo aislar: '+str(e))))
                                else:
                                    self.q.put(('rt_threat',(path,threat,'Detectada')))
                        except (PermissionError,FileNotFoundError,OSError): pass
            time.sleep(2)

    def setbusy(self,on,msg=''):
        self.running=on
        if on: self.pb.start(10); self.status.config(text='◌  ANALIZANDO…'); self.detail.config(text=msg)
        else: self.pb.stop(); self.status.config(text='✓  PROTECCIÓN LISTA')

    def pick_file(self):
        p=filedialog.askopenfilename()
        if p:self.start([p],False)
    def pick_folder(self):
        p=filedialog.askdirectory()
        if p:self.start([p],True)
    def quick(self):
        targets=[]
        for env in ('USERPROFILE','TEMP'):
            p=os.getenv(env)
            if p: targets.append(p)
        self.start(targets,True)
    def start(self,targets,recurse):
        if self.running:return
        self.tree.delete(*self.tree.get_children()); self.setbusy(True,'Preparando archivos…')
        threading.Thread(target=self.worker,args=(targets,recurse),daemon=True).start()
    def worker(self,targets,recurse):
        sig=signatures(); count=bad=0
        paths=[]
        for t in targets:
            if os.path.isfile(t): paths.append(t)
            elif os.path.isdir(t):
                if recurse:
                    for root,dirs,files in os.walk(t):
                        dirs[:]=[d for d in dirs if not excluded(os.path.join(root,d),self.cfg)]
                        paths.extend(os.path.join(root,f) for f in files)
                else: paths.extend(str(p) for p in Path(t).iterdir() if p.is_file())
        for p in paths:
            if excluded(p,self.cfg): continue
            try:
                if os.path.getsize(p)>self.cfg['max_file_mb']*1024*1024: continue
                h=sha256(p); threat=sig.get(h,''); verdict='AMENAZA' if threat else 'Limpio'
                record(p,h,verdict,threat); count+=1
                if threat: bad+=1
                self.q.put(('row',(verdict,threat,p,h)))
            except (PermissionError,OSError): pass
        self.q.put(('done',(count,bad)))
    def poll(self):
        try:
            while True:
                typ,data=self.q.get_nowait()
                if typ=='row': self.tree.insert('',0,values=data)
                elif typ=='rt_threat':
                    path,threat,action=data
                    self.tree.insert('',0,values=('TIEMPO REAL',threat,path,''))
                    self.status.config(text='⚠  AMENAZA BLOQUEADA')
                    self.detail.config(text=f'{threat} • {action}')
                    messagebox.showwarning('GlezRuda Security • Protección en tiempo real',f'Amenaza detectada: {threat}\n\n{path}\n\nAcción: {action}')
                elif typ=='done':
                    count,bad=data; self.setbusy(False); self.detail.config(text=f'Escaneo terminado: {count} archivos • {bad} amenaza(s) detectada(s).')
                    if bad: messagebox.showwarning('GlezRuda Security',f'Se detectaron {bad} archivo(s) por firma. Selecciona una fila AMENAZA y usa clic derecho para ponerla en cuarentena.')
        except queue.Empty: pass
        self.after(150,self.poll)
    def quarantine_selected(self):
        sel=self.tree.selection()
        if not sel:return
        vals=self.tree.item(sel[0])['values']; verdict,threat,path,h=vals
        if verdict!='AMENAZA': return messagebox.showinfo('Cuarentena','Este archivo no está marcado como amenaza.')
        if messagebox.askyesno('Confirmar',f'¿Mover a cuarentena?\n\n{path}'):
            try: quarantine_file(path,h,threat); self.tree.set(sel[0],'verdict','Cuarentena'); messagebox.showinfo('Cuarentena','Archivo aislado correctamente.')
            except Exception as e: messagebox.showerror('Error',str(e))
    def show_quarantine(self):
        w=tk.Toplevel(self); w.title('Cuarentena'); w.geometry('850x420')
        tr=ttk.Treeview(w,columns=('id','threat','original','stored'),show='headings')
        for c,t in [('id','ID'),('threat','Amenaza'),('original','Ruta original'),('stored','Archivo aislado')]:tr.heading(c,text=t)
        tr.pack(fill='both',expand=True,padx=12,pady=12)
        con=sqlite3.connect(DB); rows=con.execute('SELECT id,threat,original,stored FROM quarantine ORDER BY id DESC').fetchall(); con.close()
        for r in rows: tr.insert('', 'end', values=r)
        def restore():
            s=tr.selection()
            if not s:return
            rid,th,orig,stored=tr.item(s[0])['values']
            if not messagebox.askyesno('Restaurar','Restaurar este archivo a su ubicación original?'):return
            try:
                Path(orig).parent.mkdir(parents=True,exist_ok=True); shutil.move(stored,orig)
                con=sqlite3.connect(DB); con.execute('DELETE FROM quarantine WHERE id=?',(rid,));con.commit();con.close(); tr.delete(s[0])
            except Exception as e:messagebox.showerror('Error',str(e))
        ttk.Button(w,text='Restaurar seleccionado',command=restore).pack(pady=(0,12))
    def exclusions(self):
        p=filedialog.askdirectory(title='Selecciona una carpeta para excluir')
        if p and p not in self.cfg['exclusions']:
            self.cfg['exclusions'].append(p); save_cfg(self.cfg); messagebox.showinfo('Exclusiones',f'Agregada:\n{p}')
    def open_sigs(self):
        signatures()
        try: os.startfile(SIG)
        except: messagebox.showinfo('Firmas',str(SIG))

    def popup(self,event):
        iid=self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid); m=tk.Menu(self,tearoff=0);m.add_command(label='Mover amenaza a cuarentena',command=self.quarantine_selected);m.tk_popup(event.x_root,event.y_root)

if __name__=='__main__':
    gate=tk.Tk(); gate.withdraw()
    if not activation_dialog(gate):
        gate.destroy(); sys.exit(0)
    gate.destroy()
    cfg=load_cfg()
    if cfg.get('realtime_enabled',True):
        set_windows_startup(True); start_engine()
    app=App(); app.tree.bind('<Button-3>',app.popup); app.mainloop()
