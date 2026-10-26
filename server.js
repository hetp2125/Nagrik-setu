'use strict';
const express=require('express'),helmet=require('helmet'),rate=require('express-rate-limit'),cookie=require('cookie-parser'),multer=require('multer'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),Database=require('better-sqlite3'),crypto=require('crypto'),fs=require('fs'),path=require('path');
const PROD=process.env.NODE_ENV==='production',DATA=process.env.DATA_DIR||path.join(__dirname,'data');
fs.mkdirSync(DATA+'/uploads',{recursive:true});
const rand=n=>crypto.randomBytes(n).toString('hex');
/* ---- secrets: env first, else generated once into data/secrets.json (0600). In production use a KMS/HSM. ---- */
const sf=DATA+'/secrets.json';let S={};
if(fs.existsSync(sf))S=JSON.parse(fs.readFileSync(sf));
else{const k=crypto.generateKeyPairSync('rsa',{modulusLength:3072,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
 S={jwt:rand(48),dk:rand(32),pepper:rand(32),pub:k.publicKey,priv:k.privateKey};fs.writeFileSync(sf,JSON.stringify(S),{mode:0o600});}
if(process.env.JWT_SECRET)S.jwt=process.env.JWT_SECRET;if(process.env.DATA_KEY)S.dk=process.env.DATA_KEY;if(process.env.PEPPER)S.pepper=process.env.PEPPER;
const KEY=Buffer.from(S.dk,'hex');if(KEY.length!==32)throw new Error('DATA_KEY must be 32 bytes hex');
/* ---- AES-256-GCM field + file encryption (envelope: iv|tag|cipher) ---- */
const encB=b=>{const iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',KEY,iv),x=Buffer.concat([c.update(b),c.final()]);return Buffer.concat([iv,c.getAuthTag(),x])};
const decB=b=>{const d=crypto.createDecipheriv('aes-256-gcm',KEY,b.subarray(0,12));d.setAuthTag(b.subarray(12,28));return Buffer.concat([d.update(b.subarray(28)),d.final()])};
const enc=t=>encB(Buffer.from(String(t))).toString('base64'),dec=s=>decB(Buffer.from(s,'base64')).toString();
const hmac=t=>crypto.createHmac('sha256',S.pepper).update(t).digest('hex');
/* ---- database ---- */
const db=new Database(DATA+'/portal.db');db.pragma('journal_mode=WAL');db.pragma('foreign_keys=ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email_idx TEXT UNIQUE,email_enc TEXT,name_enc TEXT,phone_enc TEXT,pw_hash TEXT,
 aadhaar_ref TEXT,aadhaar_last4 TEXT,aadhaar_verified INTEGER DEFAULT 0,consent_at TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,deleted_at TEXT);
CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY,email TEXT UNIQUE,name TEXT,pw_hash TEXT,role TEXT DEFAULT 'officer',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS aadhaar_txn(id TEXT PRIMARY KEY,user_id INTEGER,ref TEXT,last4 TEXT,expires INTEGER,tries INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS complaints(id INTEGER PRIMARY KEY,user_id INTEGER REFERENCES users(id),title TEXT,description_enc TEXT,location_text TEXT,lat REAL,lng REAL,
 status TEXT DEFAULT 'submitted',ai_risk REAL DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP,deleted_at TEXT);
CREATE TABLE IF NOT EXISTS verification_status(complaint_id INTEGER PRIMARY KEY REFERENCES complaints(id),state TEXT DEFAULT 'pending',reviewer_id INTEGER,note TEXT,reviewed_at TEXT);
CREATE TABLE IF NOT EXISTS complaint_files(id INTEGER PRIMARY KEY,complaint_id INTEGER REFERENCES complaints(id),kind TEXT,name TEXT,mime TEXT,path TEXT,sha256 TEXT,ai_score REAL,ai_notes TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,complaint_id INTEGER,actor TEXT,action TEXT,note TEXT,ts TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_c_user ON complaints(user_id);CREATE INDEX IF NOT EXISTS ix_c_status ON complaints(status);CREATE INDEX IF NOT EXISTS ix_f_sha ON complaint_files(sha256);`);
if(!db.prepare('SELECT 1 FROM admins').get()){
 const em=process.env.ADMIN_EMAIL||'admin@nagriksetu.local',pw=process.env.ADMIN_PASSWORD||rand(9);
 db.prepare('INSERT INTO admins(email,name,pw_hash,role) VALUES(?,?,?,?)').run(em,'Chief Officer',bcrypt.hashSync(pw,12),'superadmin');
 console.log(`\n  Seed admin -> ${em} / ${pw}   (change it; shown only once)\n`);}
/* ---- helpers ---- */
const ev=(cid,actor,action,note='')=>db.prepare('INSERT INTO events(complaint_id,actor,action,note) VALUES(?,?,?,?)').run(cid,actor,action,note);
const MAGIC=[['image/jpeg',b=>b[0]===0xFF&&b[1]===0xD8],['image/png',b=>b.subarray(1,4).toString()==='PNG'],['image/webp',b=>b.subarray(0,4).toString()==='RIFF'&&b.subarray(8,12).toString()==='WEBP'],['application/pdf',b=>b.subarray(0,4).toString()==='%PDF']];
const sniff=b=>(MAGIC.find(m=>m[1](b))||[])[0];
async function aiScan(buf,mime){
 if(mime==='application/pdf')return{score:0,notes:'pdf: manual review'};
 if(process.env.AI_DETECT_URL){try{const r=await fetch(process.env.AI_DETECT_URL,{method:'POST',headers:{'content-type':mime,authorization:'Bearer '+(process.env.AI_DETECT_KEY||'')},body:buf,signal:AbortSignal.timeout(15000)});const j=await r.json();return{score:+j.ai_probability||0,notes:'provider'}}catch(e){}}
 const head=buf.subarray(0,65536).toString('latin1'),n=[];let s=.15;
 if(/midjourney|stable diffusion|dall-?e|firefly|trainedAlgorithmicMedia|c2pa|jumb/i.test(head)){s=.95;n.push('generator/C2PA marker')}
 else{if(mime==='image/jpeg'&&!head.includes('Exif')){s+=.3;n.push('no camera EXIF')}if(mime==='image/png'){s+=.15;n.push('png')}if(mime==='image/webp'){s+=.15;n.push('webp')}}
 return{score:Math.min(s,1),notes:n.join(', ')||'no anomalies (heuristic)'};}
async function saveFiles(files,cid,kind){let risk=0,dup=false;
 for(const f of files||[]){const mime=sniff(f.buffer);if(!mime)continue;
  const sha=crypto.createHash('sha256').update(f.buffer).digest('hex'),a=await aiScan(f.buffer,mime);
  if(kind==='evidence'&&db.prepare("SELECT 1 FROM complaint_files WHERE sha256=? AND kind='evidence' AND complaint_id!=?").get(sha,cid)){dup=true;a.score=Math.max(a.score,.9);a.notes+=' | duplicate of earlier report'}
  const p=rand(16);fs.writeFileSync(`${DATA}/uploads/${p}.bin`,encB(f.buffer),{mode:0o600});
  db.prepare('INSERT INTO complaint_files(complaint_id,kind,name,mime,path,sha256,ai_score,ai_notes) VALUES(?,?,?,?,?,?,?,?)').run(cid,kind,path.basename(f.originalname).slice(0,80),mime,p,sha,a.score,a.notes);
  if(kind==='evidence')risk=Math.max(risk,a.score);}
 return{risk,dup};}
/* ---- Aadhaar (UIDAI) adapter: Verhoeff check + pluggable AUA/KUA provider; mock only outside production ---- */
const D=[[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]],P=[[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
const verhoeff=n=>{let c=0;[...n].reverse().forEach((x,i)=>c=D[c][P[i%8][+x]]);return c===0};
const mockOk=!process.env.AADHAAR_PROVIDER_URL&&(!PROD||process.env.ALLOW_MOCK_AADHAAR==='true');
const provider={async start(num){if(mockOk)return true;const r=await fetch(process.env.AADHAAR_PROVIDER_URL+'/otp',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+process.env.AADHAAR_PROVIDER_KEY},body:JSON.stringify({uid:num})});return r.ok},
 async check(num,otp){if(mockOk)return otp==='123456';const r=await fetch(process.env.AADHAAR_PROVIDER_URL+'/verify',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+process.env.AADHAAR_PROVIDER_KEY},body:JSON.stringify({uid:num,otp})});return r.ok&&(await r.json()).verified===true}};
/* ---- app ---- */
const app=express();app.set('trust proxy',1);
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'","'unsafe-inline'"],scriptSrcAttr:["'unsafe-inline'"],upgradeInsecureRequests:PROD?[]:null,styleSrc:["'self'","'unsafe-inline'","https://fonts.googleapis.com"],fontSrc:["https://fonts.gstatic.com"],imgSrc:["'self'","data:","blob:"],frameAncestors:["'none'"]}},hsts:PROD}));
app.use(express.json({limit:'20kb'}));app.use(cookie());
app.use('/api',rate({windowMs:60000,limit:120}));
const strict=rate({windowMs:15*60000,limit:15,message:{error:'Too many attempts. Try again later.'}});
app.use('/api',(q,r,n)=>{if(q.method!=='GET'&&q.get('x-requested-with')!=='portal')return r.status(403).json({error:'Blocked (CSRF)'});n()});
const up=multer({storage:multer.memoryStorage(),limits:{fileSize:10*1024*1024,files:6}});
const sign=(id,role)=>jwt.sign({id,role},S.jwt,{expiresIn:'8h'});
const setTk=(r,t)=>r.cookie('tk',t,{httpOnly:true,sameSite:'strict',secure:PROD,maxAge:8*3600e3});
const auth=role=>(q,r,n)=>{try{const t=jwt.verify(q.cookies.tk||'',S.jwt);if(role&&t.role!==role)throw 0;q.u=t;n()}catch{r.status(401).json({error:'Please sign in'})}};
const wrap=f=>(q,r,n)=>Promise.resolve(f(q,r,n)).catch(e=>{console.error(e);r.status(500).json({error:'Server error'})});
const need=(o,...k)=>k.every(x=>typeof o[x]==='string'&&o[x].trim());
const UST=['submitted','pending_review'];
const view=(c,admin)=>{const files=db.prepare('SELECT id,kind,name,mime,ai_score,ai_notes FROM complaint_files WHERE complaint_id=?').all(c.id).map(f=>admin?f:{id:f.id,kind:f.kind,name:f.name,mime:f.mime});
 const v=db.prepare('SELECT state,note FROM verification_status WHERE complaint_id=?').get(c.id)||{};
 const o={id:c.id,title:c.title,description:c.description_enc?dec(c.description_enc):'',location:c.location_text,lat:c.lat,lng:c.lng,status:c.status,created_at:c.created_at,updated_at:c.updated_at,verification:v.state,review_note:v.note,files,
  events:db.prepare('SELECT actor,action,note,ts FROM events WHERE complaint_id=? ORDER BY id').all(c.id).filter(e=>admin||e.actor!=='ai_scan').map(e=>admin||!e.actor.startsWith('admin:')?e:{...e,actor:'Officer'})};
 if(admin){o.ai_risk=c.ai_risk;const u=db.prepare('SELECT * FROM users WHERE id=?').get(c.user_id);o.citizen={name:u.name_enc?dec(u.name_enc):'(erased)',phone:u.phone_enc?'••••••'+dec(u.phone_enc).slice(-4):'(erased)',aadhaar:'XXXX-XXXX-'+(u.aadhaar_last4||'----'),verified:!!u.aadhaar_verified};}return o};
/* crypto + citizen auth */
app.get('/api/crypto/pubkey',(q,r)=>r.json({pem:S.pub}));
app.post('/api/register',strict,wrap(async(q,r)=>{const b=q.body;
 if(!need(b,'name','email','phone','password')||!/^\S+@\S+\.\S+$/.test(b.email)||!/^[6-9]\d{9}$/.test(b.phone)||b.password.length<10)return r.status(400).json({error:'Enter a valid name, email, 10-digit mobile and a password of 10+ characters.'});
 if(b.consent!==true)return r.status(400).json({error:'Consent under the DPDP Act is required to continue.'});
 const idx=hmac(b.email.toLowerCase());if(db.prepare('SELECT 1 FROM users WHERE email_idx=?').get(idx))return r.status(409).json({error:'An account with this email already exists.'});
 const i=db.prepare('INSERT INTO users(email_idx,email_enc,name_enc,phone_enc,pw_hash,consent_at) VALUES(?,?,?,?,?,CURRENT_TIMESTAMP)').run(idx,enc(b.email),enc(b.name.trim()),enc(b.phone),await bcrypt.hash(b.password,12)).lastInsertRowid;
 setTk(r,sign(i,'citizen'));r.json({ok:true})}));
app.post('/api/login',strict,wrap(async(q,r)=>{const u=need(q.body,'email','password')&&db.prepare('SELECT * FROM users WHERE email_idx=? AND deleted_at IS NULL').get(hmac(q.body.email.toLowerCase()));
 if(!u||!await bcrypt.compare(q.body.password,u.pw_hash))return r.status(401).json({error:'Email or password is incorrect.'});setTk(r,sign(u.id,'citizen'));r.json({ok:true})}));
app.post('/api/admin/login',strict,wrap(async(q,r)=>{const a=need(q.body,'email','password')&&db.prepare('SELECT * FROM admins WHERE email=?').get(q.body.email.toLowerCase());
 if(!a||!await bcrypt.compare(q.body.password,a.pw_hash))return r.status(401).json({error:'Credentials are incorrect.'});setTk(r,sign(a.id,'admin'));r.json({ok:true})}));
app.post('/api/logout',(q,r)=>{r.clearCookie('tk');r.json({ok:true})});
app.get('/api/me',auth(),(q,r)=>{if(q.u.role==='admin'){const a=db.prepare('SELECT name,email,role FROM admins WHERE id=?').get(q.u.id);return r.json({...a,role:'admin',level:a.role})}
 const u=db.prepare('SELECT * FROM users WHERE id=?').get(q.u.id);r.json({role:'citizen',name:dec(u.name_enc),verified:!!u.aadhaar_verified,aadhaar:u.aadhaar_last4?'XXXX-XXXX-'+u.aadhaar_last4:null})});
app.delete('/api/me',auth('citizen'),(q,r)=>{db.prepare("UPDATE users SET deleted_at=datetime('now'),email_idx=NULL,email_enc=NULL,phone_enc=NULL,name_enc=?,aadhaar_ref=NULL WHERE id=?").run(enc('Erased user'),q.u.id);r.clearCookie('tk');r.json({ok:true})});
/* Aadhaar: client sends RSA-OAEP ciphertext; plaintext number lives in memory only, we persist an HMAC reference + last 4 */
app.post('/api/aadhaar/start',auth('citizen'),strict,wrap(async(q,r)=>{let num;
 try{num=crypto.privateDecrypt({key:S.priv,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},Buffer.from(q.body.enc,'base64')).toString()}catch{return r.status(400).json({error:'Could not read encrypted payload.'})}
 if(!/^[2-9]\d{11}$/.test(num)||!verhoeff(num))return r.status(400).json({error:'This Aadhaar number is not valid.'});
 if(!mockOk&&!process.env.AADHAAR_PROVIDER_URL)return r.status(503).json({error:'Aadhaar provider is not configured.'});
 const ref=hmac('aadhaar:'+num);if(db.prepare('SELECT 1 FROM users WHERE aadhaar_ref=? AND id!=? AND aadhaar_verified=1').get(ref,q.u.id))return r.status(409).json({error:'This Aadhaar is already linked to another account.'});
 if(!await provider.start(num))return r.status(502).json({error:'Could not send OTP. Try again.'});
 const id=rand(12);db.prepare('INSERT INTO aadhaar_txn(id,user_id,ref,last4,expires) VALUES(?,?,?,?,?)').run(id,q.u.id,ref,num.slice(-4),Date.now()+600000);
 aadhaarMem.set(id,num);setTimeout(()=>aadhaarMem.delete(id),600000);r.json({txn:id,hint:mockOk?'Demo mode: OTP is 123456':undefined})}));
const aadhaarMem=new Map();
app.post('/api/aadhaar/verify',auth('citizen'),strict,wrap(async(q,r)=>{const t=db.prepare('SELECT * FROM aadhaar_txn WHERE id=? AND user_id=?').get(String(q.body.txn),q.u.id),num=aadhaarMem.get(String(q.body.txn));
 if(!t||!num||t.expires<Date.now()||t.tries>=3)return r.status(400).json({error:'This verification expired. Start again.'});
 db.prepare('UPDATE aadhaar_txn SET tries=tries+1 WHERE id=?').run(t.id);
 if(!await provider.check(num,String(q.body.otp)))return r.status(400).json({error:'OTP did not match.'});
 db.prepare('UPDATE users SET aadhaar_ref=?,aadhaar_last4=?,aadhaar_verified=1 WHERE id=?').run(t.ref,t.last4,q.u.id);aadhaarMem.delete(t.id);db.prepare('DELETE FROM aadhaar_txn WHERE id=?').run(t.id);r.json({ok:true})}));
/* citizen complaints CRUD */
app.get('/api/complaints',auth('citizen'),(q,r)=>r.json(db.prepare('SELECT * FROM complaints WHERE user_id=? AND deleted_at IS NULL ORDER BY id DESC').all(q.u.id).map(c=>view(c,false))));
app.post('/api/complaints',auth('citizen'),up.array('files',6),wrap(async(q,r)=>{const b=q.body;
 if(!db.prepare('SELECT aadhaar_verified v FROM users WHERE id=?').get(q.u.id).v)return r.status(403).json({error:'Verify your Aadhaar before filing a report.'});
 if(!need(b,'title','location'))return r.status(400).json({error:'Add a title and the road location.'});
 if(!(q.files||[]).length)return r.status(400).json({error:'Attach at least one photo of the damage.'});
 if(q.files.some(f=>!sniff(f.buffer)))return r.status(400).json({error:'Only JPG, PNG, WebP or PDF files are accepted.'});
 const id=db.prepare('INSERT INTO complaints(user_id,title,description_enc,location_text,lat,lng) VALUES(?,?,?,?,?,?)').run(q.u.id,b.title.slice(0,140),b.description?enc(b.description.slice(0,2000)):null,b.location.slice(0,240),+b.lat||null,+b.lng||null).lastInsertRowid;
 const {risk,dup}=await saveFiles(q.files,id,'evidence'),flag=risk>=.7;
 db.prepare('UPDATE complaints SET ai_risk=?,status=? WHERE id=?').run(risk,flag?'flagged':'pending_review',id);
 db.prepare('INSERT INTO verification_status(complaint_id,state) VALUES(?,?)').run(id,flag?'flagged':'pending');
 ev(id,'citizen','submitted');ev(id,'ai_scan',flag?'flagged for manual review':'screened',`risk ${(risk*100).toFixed(0)}%${dup?' (duplicate image)':''}`);r.json({id})}));
app.get('/api/complaints/:id',auth('citizen'),(q,r)=>{const c=db.prepare('SELECT * FROM complaints WHERE id=? AND user_id=? AND deleted_at IS NULL').get(q.params.id,q.u.id);c?r.json(view(c,false)):r.status(404).json({error:'Not found'})});
app.put('/api/complaints/:id',auth('citizen'),(q,r)=>{const c=db.prepare('SELECT * FROM complaints WHERE id=? AND user_id=? AND deleted_at IS NULL').get(q.params.id,q.u.id);
 if(!c)return r.status(404).json({error:'Not found'});if(!UST.includes(c.status)&&c.status!=='flagged')return r.status(409).json({error:'Reports under repair can no longer be edited.'});
 db.prepare("UPDATE complaints SET title=?,description_enc=?,location_text=?,updated_at=datetime('now') WHERE id=?").run((q.body.title||c.title).slice(0,140),q.body.description!=null?enc(String(q.body.description).slice(0,2000)):c.description_enc,(q.body.location||c.location_text).slice(0,240),c.id);ev(c.id,'citizen','edited');r.json({ok:true})});
app.delete('/api/complaints/:id',auth('citizen'),(q,r)=>{const c=db.prepare('SELECT * FROM complaints WHERE id=? AND user_id=? AND deleted_at IS NULL').get(q.params.id,q.u.id);
 if(!c)return r.status(404).json({error:'Not found'});if(!UST.includes(c.status)&&c.status!=='flagged')return r.status(409).json({error:'Only unreviewed reports can be withdrawn.'});
 db.prepare("UPDATE complaints SET status='withdrawn',deleted_at=datetime('now') WHERE id=?").run(c.id);ev(c.id,'citizen','withdrawn');r.json({ok:true})});
/* decrypt-on-read file streaming (owner or officer only) */
app.get('/api/files/:id',auth(),(q,r)=>{const f=db.prepare('SELECT f.*,c.user_id FROM complaint_files f JOIN complaints c ON c.id=f.complaint_id WHERE f.id=?').get(q.params.id);
 if(!f||(q.u.role==='citizen'&&f.user_id!==q.u.id))return r.status(404).end();
 r.set({'Content-Type':f.mime,'Content-Disposition':`inline; filename="${f.name.replace(/[^\w.\-]/g,'_')}"`,'X-Content-Type-Options':'nosniff','Cache-Control':'private, no-store'});r.send(decB(fs.readFileSync(`${DATA}/uploads/${f.path}.bin`)))});
/* officer console */
const A=auth('admin');
app.get('/api/admin/stats',A,(q,r)=>r.json(Object.fromEntries(db.prepare('SELECT status,COUNT(*) n FROM complaints WHERE deleted_at IS NULL GROUP BY status').all().map(x=>[x.status,x.n]))));
app.get('/api/admin/complaints',A,(q,r)=>{const s=q.query.status;const rows=s&&s!=='all'?db.prepare('SELECT * FROM complaints WHERE deleted_at IS NULL AND status=? ORDER BY ai_risk DESC,id DESC').all(s):db.prepare('SELECT * FROM complaints WHERE deleted_at IS NULL ORDER BY id DESC LIMIT 200').all();r.json(rows.map(c=>view(c,true)))});
app.get('/api/admin/complaints/:id',A,(q,r)=>{const c=db.prepare('SELECT * FROM complaints WHERE id=? AND deleted_at IS NULL').get(q.params.id);c?r.json(view(c,true)):r.status(404).json({error:'Not found'})});
const adm=q=>db.prepare('SELECT name FROM admins WHERE id=?').get(q.u.id).name;
app.post('/api/admin/complaints/:id/review',A,(q,r)=>{const c=db.prepare('SELECT * FROM complaints WHERE id=? AND deleted_at IS NULL').get(q.params.id),d=q.body.decision;
 if(!c||!['verified','rejected','flagged'].includes(d))return r.status(400).json({error:'Invalid request'});if(d==='rejected'&&!need(q.body,'note'))return r.status(400).json({error:'Add a reason for rejection.'});
 db.prepare("UPDATE complaints SET status=?,updated_at=datetime('now') WHERE id=?").run(d,c.id);
 db.prepare("INSERT INTO verification_status(complaint_id,state,reviewer_id,note,reviewed_at) VALUES(?,?,?,?,datetime('now')) ON CONFLICT(complaint_id) DO UPDATE SET state=excluded.state,reviewer_id=excluded.reviewer_id,note=excluded.note,reviewed_at=excluded.reviewed_at").run(c.id,d,q.u.id,(q.body.note||'').slice(0,500));
 ev(c.id,'admin:'+adm(q),'review: '+d,q.body.note||'');r.json({ok:true})});
app.post('/api/admin/complaints/:id/start',A,(q,r)=>{const c=db.prepare("SELECT * FROM complaints WHERE id=? AND status='verified'").get(q.params.id);if(!c)return r.status(409).json({error:'Only verified reports can be sent for repair.'});
 db.prepare("UPDATE complaints SET status='in_repair',updated_at=datetime('now') WHERE id=?").run(c.id);ev(c.id,'admin:'+adm(q),'repair started',q.body.note||'');r.json({ok:true})});
app.post('/api/admin/complaints/:id/repair',A,up.array('files',6),wrap(async(q,r)=>{const c=db.prepare("SELECT * FROM complaints WHERE id=? AND status IN('in_repair','repair_submitted')").get(q.params.id);
 if(!c)return r.status(409).json({error:'Report is not in repair.'});if(!(q.files||[]).length||q.files.some(f=>!sniff(f.buffer)))return r.status(400).json({error:'Attach repair photos (JPG, PNG, WebP) or PDF.'});
 await saveFiles(q.files,c.id,'repair');db.prepare("UPDATE complaints SET status='repair_submitted',updated_at=datetime('now') WHERE id=?").run(c.id);ev(c.id,'admin:'+adm(q),'repair proof submitted',q.body.note||'');r.json({ok:true})}));
app.post('/api/admin/complaints/:id/close',A,(q,r)=>{const c=db.prepare("SELECT * FROM complaints WHERE id=? AND status='repair_submitted'").get(q.params.id);
 if(!c||!db.prepare("SELECT 1 FROM complaint_files WHERE complaint_id=? AND kind='repair'").get(c.id))return r.status(409).json({error:'Repair proof is required before closing.'});
 db.prepare("UPDATE complaints SET status='closed',updated_at=datetime('now') WHERE id=?").run(c.id);ev(c.id,'admin:'+adm(q),'closed',q.body.note||'');r.json({ok:true})});
app.delete('/api/admin/complaints/:id',A,(q,r)=>{if(db.prepare('SELECT role FROM admins WHERE id=?').get(q.u.id).role!=='superadmin')return r.status(403).json({error:'Superadmin only'});
 db.prepare("UPDATE complaints SET deleted_at=datetime('now') WHERE id=?").run(q.params.id);ev(q.params.id,'admin:'+adm(q),'deleted');r.json({ok:true})});
app.get('/api/admin/officers',A,(q,r)=>r.json(db.prepare('SELECT id,name,email,role FROM admins').all()));
app.post('/api/admin/officers',A,wrap(async(q,r)=>{if(db.prepare('SELECT role FROM admins WHERE id=?').get(q.u.id).role!=='superadmin')return r.status(403).json({error:'Superadmin only'});
 if(!need(q.body,'name','email','password')||q.body.password.length<12)return r.status(400).json({error:'Name, email and a 12+ character password are required.'});
 try{db.prepare('INSERT INTO admins(email,name,pw_hash) VALUES(?,?,?)').run(q.body.email.toLowerCase(),q.body.name,await bcrypt.hash(q.body.password,12));r.json({ok:true})}catch{r.status(409).json({error:'Officer already exists.'})}}));
app.delete('/api/admin/officers/:id',A,(q,r)=>{if(db.prepare('SELECT role FROM admins WHERE id=?').get(q.u.id).role!=='superadmin'||+q.params.id===q.u.id)return r.status(403).json({error:'Not allowed'});db.prepare('DELETE FROM admins WHERE id=?').run(q.params.id);r.json({ok:true})});
app.get('/healthz',(q,r)=>r.send('ok'));
app.use(express.static(path.join(__dirname,'public'),{maxAge:'1h'}));
app.use('/api',(q,r)=>r.status(404).json({error:'Not found'}));
app.listen(process.env.PORT||3000,()=>console.log('Nagrik Setu running on :'+(process.env.PORT||3000)));
