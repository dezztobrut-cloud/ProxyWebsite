const express = require('express');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', true);
app.use(express.json({ limit: '2mb' }));

// --- DATABASE & PATHS ---
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(__dirname, 'internal_db.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) {
    // Master key di-generate random, bukan hardcoded!
    const masterKey = 'mk_' + crypto.randomBytes(24).toString('hex');
    fs.writeFileSync(DB_FILE, JSON.stringify({ keys: {}, bans: [], config: { master_key: masterKey } }, null, 2));
    console.log('\n🔑 MASTER KEY (simpan baik-baik!):', masterKey, '\n');
}

const getDB = () => JSON.parse(fs.readFileSync(DB_FILE));
const saveDB = (db) => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
const getIP = (req) => (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim().replace('::ffff:', '');
const getNS = (key) => crypto.createHash('sha256').update(key).digest('hex').substring(0, 16);

// Sanitize filename - hanya huruf, angka, dash, underscore. Blokir path traversal.
const sanitizeFilename = (name) => {
    if (!name || typeof name !== 'string') return null;
    const clean = name.replace(/[^a-zA-Z0-9_\-]/g, '').substring(0, 64);
    if (!clean || clean.length < 1) return null;
    return clean;
};

// --- BAN MIDDLEWARE ---
app.use((req, res, next) => {
    const db = getDB();
    if (db.bans.includes(getIP(req))) return res.status(403).send('FORBIDDEN');
    next();
});

// --- AUTH MIDDLEWARE ---
const auth = (perm) => (req, res, next) => {
    const key = req.headers['x-api-key'] || req.query.key;
    if (!key) return res.status(401).json({ error: 'No API key provided' });
    const db = getDB();

    if (key === db.config.master_key) {
        req.is_admin = true;
        req.namespace = '__admin__';
        return next();
    }

    const k = db.keys[key];
    if (k && !k.revoked && k.perms.includes(perm)) {
        req.namespace = getNS(key);
        req.key_info = k;
        return next();
    }
    res.status(401).json({ error: 'Unauthorized' });
};

// ==========================================
// API CORE
// ==========================================

// Rate limit lebih ketat untuk key creation
const createLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, message: { error: 'Too many requests' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, message: { error: 'Rate limit exceeded' } });
app.use('/api/', apiLimiter);

// Create key
app.post('/api/key/create', createLimiter, (req, res) => {
    const { name } = req.body;
    const cleanName = (name || 'Project').replace(/[<>"&]/g, '').substring(0, 32);
    const db = getDB();
    const key = 'plta_' + crypto.randomBytes(16).toString('hex');
    db.keys[key] = {
        name: cleanName,
        perms: ['READ', 'WRITE', 'DELETE'],
        revoked: false,
        ip: getIP(req),
        created_at: new Date().toISOString()
    };
    saveDB(db);
    res.json({ success: true, key });
});

// List files
app.get('/api/files', auth('READ'), (req, res) => {
    const dir = path.join(DATA_DIR, req.namespace);
    if (!fs.existsSync(dir)) return res.json([]);
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.json')).map(f => {
        const stat = fs.statSync(path.join(dir, f));
        return {
            name: f.replace('.json', ''),
            size: (stat.size / 1024).toFixed(2) + ' KB',
            updated: stat.mtime.toISOString()
        };
    });
    res.json(files);
});

// Get raw file
app.get('/api/raw/:name', auth('READ'), (req, res) => {
    const safeName = sanitizeFilename(req.params.name);
    if (!safeName) return res.status(400).json({ error: 'Invalid filename' });

    const p = path.join(DATA_DIR, req.namespace, safeName + '.json');
    if (fs.existsSync(p)) res.sendFile(p);
    else res.status(404).json({ error: 'Not Found' });
});

// Save file
app.post('/api/save', auth('WRITE'), (req, res) => {
    const { filename, content } = req.body;
    const safeName = sanitizeFilename(filename);
    if (!safeName) return res.status(400).json({ error: 'Invalid filename. Use only letters, numbers, dash, underscore.' });

    const dir = path.join(DATA_DIR, req.namespace);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    try {
        const parsed = typeof content === 'string' ? JSON.parse(content) : content;
        const cleanJson = JSON.stringify(parsed, null, 2);
        if (Buffer.byteLength(cleanJson) > 1024 * 1024) return res.status(413).json({ error: 'File too large (max 1MB)' });
        fs.writeFileSync(path.join(dir, safeName + '.json'), cleanJson);
        res.json({ success: true });
    } catch (e) {
        res.status(400).json({ error: 'Invalid JSON format' });
    }
});

// Delete file
app.delete('/api/delete/:name', auth('DELETE'), (req, res) => {
    const safeName = sanitizeFilename(req.params.name);
    if (!safeName) return res.status(400).json({ error: 'Invalid filename' });

    const p = path.join(DATA_DIR, req.namespace, safeName + '.json');
    if (fs.existsSync(p)) { fs.unlinkSync(p); res.json({ success: true }); }
    else res.status(404).json({ error: 'Not Found' });
});

// Revoke key
app.post('/api/key/revoke', auth('READ'), (req, res) => {
    if (!req.is_admin) return res.sendStatus(403);
    const { key } = req.body;
    const db = getDB();
    if (db.keys[key]) { db.keys[key].revoked = true; saveDB(db); }
    res.json({ success: true });
});

// Admin stats
app.get('/api/admin/stats', auth('READ'), (req, res) => {
    if (!req.is_admin) return res.sendStatus(403);
    const db = getDB();
    const keySummary = Object.entries(db.keys).map(([k, v]) => ({
        key_preview: k.substring(0, 12) + '...',
        name: v.name,
        revoked: v.revoked,
        ip: v.ip,
        created_at: v.created_at
    }));
    res.json({ total_keys: keySummary.length, keys: keySummary, bans: db.bans });
});

// Admin ban
app.post('/api/admin/ban', auth('READ'), (req, res) => {
    if (!req.is_admin) return res.sendStatus(403);
    const { ip } = req.body;
    if (!ip || !/^[\d.:\w]+$/.test(ip)) return res.status(400).json({ error: 'Invalid IP' });
    const db = getDB();
    if (!db.bans.includes(ip)) db.bans.push(ip);
    saveDB(db);
    res.json({ success: true });
});

// Admin unban
app.post('/api/admin/unban', auth('READ'), (req, res) => {
    if (!req.is_admin) return res.sendStatus(403);
    const { ip } = req.body;
    const db = getDB();
    db.bans = db.bans.filter(b => b !== ip);
    saveDB(db);
    res.json({ success: true });
});

// ==========================================
// UI
// ==========================================

const UI = (body, title = 'DezzDB') => `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>${title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.32.2/ace.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#060608;
  --surface:#0d0d12;
  --surface2:#141419;
  --border:#1e1e28;
  --border-hi:#2e2e3e;
  --text:#e0e0ee;
  --muted:#5a5a72;
  --accent:#6c63ff;
  --accent2:#ff6584;
  --green:#22d3a0;
  --red:#ff4d6d;
  --yellow:#fbbf24;
  --radius:14px;
}
html{scroll-behavior:smooth}
body{font-family:'Syne',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;-webkit-tap-highlight-color:transparent;overflow-x:hidden}
a{color:var(--accent);text-decoration:none}

/* Scrollbar */
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border-hi);border-radius:99px}

/* Layout */
.container{max-width:1000px;margin:0 auto;padding:24px 16px}
.page{min-height:100vh}

/* Glass card */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius)}
.card-hi{background:var(--surface2);border:1px solid var(--border-hi);border-radius:var(--radius)}

/* Typography */
h1.logo{font-size:20px;font-weight:800;letter-spacing:-0.5px;color:var(--text)}
h1.logo span{color:var(--accent)}
.display{font-size:clamp(32px,7vw,64px);font-weight:800;letter-spacing:-2px;line-height:1.05;color:#fff}
.display em{font-style:normal;color:var(--accent)}
.lead{font-size:clamp(14px,2.5vw,16px);color:var(--muted);line-height:1.7;max-width:460px}
.mono{font-family:'JetBrains Mono',monospace}
.label{font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--muted)}
.tag{display:inline-flex;align-items:center;gap:5px;font-size:10px;font-weight:700;padding:3px 8px;border-radius:99px;letter-spacing:1px}
.tag-green{background:rgba(34,211,160,.12);color:var(--green);border:1px solid rgba(34,211,160,.2)}
.tag-red{background:rgba(255,77,109,.12);color:var(--red);border:1px solid rgba(255,77,109,.2)}
.tag-purple{background:rgba(108,99,255,.12);color:var(--accent);border:1px solid rgba(108,99,255,.2)}

/* Buttons */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 20px;border-radius:10px;font-family:'Syne',sans-serif;font-size:13px;font-weight:700;cursor:pointer;border:none;transition:all .15s;outline:none;white-space:nowrap}
.btn:active{transform:scale(.97)}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#7c73ff;box-shadow:0 0 20px rgba(108,99,255,.3)}
.btn-ghost{background:transparent;color:var(--text);border:1px solid var(--border-hi)}
.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
.btn-danger{background:rgba(255,77,109,.1);color:var(--red);border:1px solid rgba(255,77,109,.2)}
.btn-danger:hover{background:rgba(255,77,109,.2)}
.btn-sm{padding:6px 12px;font-size:11px;border-radius:8px}
.btn-full{width:100%}
.btn-pill{border-radius:99px;padding:12px 28px;font-size:14px}

/* Input */
.input{background:var(--surface2);border:1px solid var(--border-hi);color:var(--text);border-radius:10px;padding:10px 14px;font-family:'Syne',sans-serif;font-size:13px;width:100%;outline:none;transition:border .15s}
.input:focus{border-color:var(--accent)}
.input::placeholder{color:var(--muted)}
textarea.input{resize:vertical;min-height:120px}

/* Overlay Modal */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.8);backdrop-filter:blur(8px);z-index:100;display:flex;align-items:center;justify-content:center;padding:16px;opacity:0;pointer-events:none;transition:opacity .2s}
.overlay.show{opacity:1;pointer-events:all}
.modal{background:var(--surface);border:1px solid var(--border-hi);border-radius:20px;width:100%;max-width:580px;max-height:90vh;overflow:hidden;display:flex;flex-direction:column;transform:translateY(20px);transition:transform .2s}
.overlay.show .modal{transform:translateY(0)}
.modal-header{padding:20px 24px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;flex-shrink:0}
.modal-body{padding:20px 24px;overflow-y:auto;flex:1}
.modal-footer{padding:16px 24px;border-top:1px solid var(--border);display:flex;gap:10px;justify-content:flex-end;flex-shrink:0}
.close-btn{background:none;border:none;color:var(--muted);cursor:pointer;font-size:20px;line-height:1;padding:4px}
.close-btn:hover{color:var(--text)}

/* Nav */
nav{display:flex;justify-content:space-between;align-items:center;padding:18px 16px;border-bottom:1px solid var(--border);position:sticky;top:0;background:rgba(6,6,8,.9);backdrop-filter:blur(12px);z-index:50}
.nav-inner{max-width:1000px;width:100%;margin:0 auto;display:flex;justify-content:space-between;align-items:center}
.nav-actions{display:flex;gap:8px;align-items:center}

/* Hero */
.hero{text-align:center;padding:60px 16px 50px;display:flex;flex-direction:column;align-items:center;gap:24px}
.hero-badge{display:inline-flex;align-items:center;gap:6px;background:var(--surface2);border:1px solid var(--border-hi);border-radius:99px;padding:6px 14px;font-size:11px;font-weight:700;color:var(--muted);letter-spacing:1px;text-transform:uppercase}
.hero-badge .dot{width:6px;height:6px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.hero-actions{display:flex;gap:10px;flex-wrap:wrap;justify-content:center}

/* Feature grid */
.feature-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:48px}
.feature-card{padding:20px;border-radius:14px;border:1px solid var(--border)}
.feature-card:hover{border-color:var(--border-hi);background:var(--surface)}
.feature-icon{font-size:20px;margin-bottom:10px}
.feature-card h4{font-size:13px;font-weight:700;color:var(--text);margin-bottom:4px}
.feature-card p{font-size:11px;color:var(--muted);line-height:1.5}

/* Dashboard */
.dash-header{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:24px;flex-wrap:wrap}
.dash-title{font-size:22px;font-weight:800;color:#fff;letter-spacing:-0.5px}
.key-display{display:flex;align-items:center;gap:8px;background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:8px 12px;flex:1;min-width:0;max-width:400px;cursor:pointer}
.key-display:hover{border-color:var(--border-hi)}
.key-text{font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.copy-icon{flex-shrink:0;color:var(--muted);font-size:14px}
.key-display:hover .copy-icon{color:var(--accent)}

/* File grid */
.file-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.file-card{padding:18px 20px;border-radius:14px;background:var(--surface);border:1px solid var(--border);transition:all .15s;cursor:default}
.file-card:hover{border-color:var(--border-hi);transform:translateY(-2px)}
.file-name{font-size:13px;font-weight:700;color:#fff;font-family:'JetBrains Mono',monospace;word-break:break-all;margin-bottom:4px}
.file-meta{font-size:10px;color:var(--muted);margin-bottom:14px}
.file-actions{display:flex;gap:6px}

/* Empty state */
.empty{text-align:center;padding:60px 20px}
.empty-icon{font-size:40px;margin-bottom:12px;opacity:.4}
.empty h3{font-size:16px;font-weight:700;color:var(--muted);margin-bottom:6px}
.empty p{font-size:12px;color:var(--muted);opacity:.6}

/* Toast */
.toast-container{position:fixed;bottom:24px;right:24px;z-index:999;display:flex;flex-direction:column;gap:8px;pointer-events:none}
.toast{background:var(--surface2);border:1px solid var(--border-hi);border-radius:12px;padding:12px 16px;font-size:12px;font-weight:600;display:flex;align-items:center;gap:8px;min-width:200px;max-width:300px;transform:translateX(calc(100% + 32px));transition:transform .3s cubic-bezier(.34,1.56,.64,1);pointer-events:all}
.toast.show{transform:translateX(0)}
.toast.success{border-left:3px solid var(--green)}
.toast.error{border-left:3px solid var(--red)}
.toast.info{border-left:3px solid var(--accent)}

/* Editor */
#ace-editor{height:300px;width:100%;border-radius:10px;border:1px solid var(--border-hi);overflow:hidden}
.form-group{margin-bottom:16px}
.form-label{display:block;font-size:11px;font-weight:700;color:var(--muted);letter-spacing:1px;text-transform:uppercase;margin-bottom:6px}

/* Tabs */
.tabs{display:flex;gap:2px;background:var(--surface2);border-radius:10px;padding:3px;margin-bottom:20px}
.tab{flex:1;padding:7px;border-radius:8px;text-align:center;font-size:11px;font-weight:700;cursor:pointer;color:var(--muted);letter-spacing:.5px;transition:all .15s}
.tab.active{background:var(--surface);color:var(--text);box-shadow:0 1px 4px rgba(0,0,0,.3)}

/* Code block */
.code-block{background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:16px;font-family:'JetBrains Mono',monospace;font-size:11px;color:#a5b4fc;line-height:1.8;overflow-x:auto;white-space:pre}
.code-block .comment{color:var(--muted)}

/* Stats */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:24px}
.stat-card{padding:16px;border-radius:12px;border:1px solid var(--border)}
.stat-num{font-size:28px;font-weight:800;color:#fff;letter-spacing:-1px}
.stat-label{font-size:10px;color:var(--muted);font-weight:700;letter-spacing:1px;text-transform:uppercase;margin-top:2px}

/* Divider */
.divider{border:none;border-top:1px solid var(--border);margin:24px 0}

/* Loading */
.spinner{width:16px;height:16px;border:2px solid var(--border-hi);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.loading{display:flex;align-items:center;justify-content:center;gap:10px;color:var(--muted);font-size:13px;padding:40px}

/* IP list */
.ip-item{display:flex;justify-content:space-between;align-items:center;padding:10px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:10px;font-size:11px;font-family:'JetBrains Mono',monospace}

/* Responsive */
@media(max-width:600px){
  .dash-header{flex-direction:column;align-items:stretch}
  .key-display{max-width:100%}
  .hero{padding:40px 8px 32px}
  .modal{border-radius:16px}
  .file-grid{grid-template-columns:1fr}
  .toast-container{bottom:16px;right:16px;left:16px}
  .toast{min-width:unset;max-width:100%}
}
</style>
</head>
<body>
${body}
<div class="toast-container" id="toastContainer"></div>
<script>
// Toast system
function toast(msg, type='info', duration=3000){
  const el=document.createElement('div');
  el.className='toast '+type;
  const icon=type==='success'?'✓':type==='error'?'✕':'ℹ';
  el.innerHTML='<span>'+icon+'</span><span>'+msg+'</span>';
  document.getElementById('toastContainer').appendChild(el);
  requestAnimationFrame(()=>requestAnimationFrame(()=>el.classList.add('show')));
  setTimeout(()=>{el.classList.remove('show');setTimeout(()=>el.remove(),400)},duration);
}

// Copy to clipboard
function copyText(text, label='Copied!'){
  navigator.clipboard.writeText(text).then(()=>toast(label,'success')).catch(()=>toast('Copy failed','error'));
}

// Modal system
function openModal(id){document.getElementById(id).classList.add('show')}
function closeModal(id){document.getElementById(id).classList.remove('show')}
document.addEventListener('click',e=>{
  if(e.target.classList.contains('overlay'))closeModal(e.target.id);
});
</script>
</body>
</html>`;

// ==========================================
// MAIN PAGE
// ==========================================
app.get('/', (req, res) => {
    res.send(UI(`
<nav>
  <div class="nav-inner">
    <h1 class="logo">Dezz<span>DB</span></h1>
    <div class="nav-actions">
      <a href="/docs" class="btn btn-ghost btn-sm">Docs</a>
      <button class="btn btn-primary btn-sm" onclick="openEnterModal()">Open Dashboard</button>
    </div>
  </div>
</nav>

<main class="container">
  <!-- Landing -->
  <div id="landingView">
    <section class="hero">
      <div class="hero-badge"><div class="dot"></div>Live Service</div>
      <h2 class="display">JSON Storage<br>Done <em>Right.</em></h2>
      <p class="lead">Database berbasis namespace otomatis. Simpan, baca, dan kelola JSON file lewat REST API dengan isolasi penuh per API key.</p>
      <div class="hero-actions">
        <button onclick="openSetupModal()" class="btn btn-primary btn-pill">🚀 Buat Project Baru</button>
        <a href="/docs" class="btn btn-ghost btn-pill">Lihat Docs</a>
      </div>
    </section>

    <div class="feature-grid">
      <div class="feature-card">
        <div class="feature-icon">🔐</div>
        <h4>Namespace Isolation</h4>
        <p>Setiap API key punya namespace tersendiri. Data lu ga akan keliatan orang lain.</p>
      </div>
      <div class="feature-card">
        <div class="feature-icon">⚡</div>
        <h4>REST API</h4>
        <p>Akses penuh via HTTP. Cocok buat WA bot, Discord bot, atau app apapun.</p>
      </div>
      <div class="feature-card">
        <div class="feature-icon">🛡️</div>
        <h4>Rate Limited</h4>
        <p>Perlindungan built-in dari spam dan abuse. IP ban otomatis tersedia.</p>
      </div>
      <div class="feature-card">
        <div class="feature-icon">📝</div>
        <h4>JSON Editor</h4>
        <p>Edit data langsung dari browser dengan syntax highlighting lengkap.</p>
      </div>
    </div>
  </div>

  <!-- Dashboard -->
  <div id="dashView" style="display:none">
    <div class="dash-header">
      <div>
        <p class="label" style="margin-bottom:4px">Project</p>
        <div class="dash-title" id="dashProjectName">—</div>
      </div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <div class="key-display" onclick="copyText(window._KEY,'API key copied!')">
          <span class="copy-icon">⌘</span>
          <span class="key-text" id="keyPreview">—</span>
          <span class="copy-icon">⎘</span>
        </div>
        <button onclick="openNewFileModal()" class="btn btn-primary btn-sm">+ New File</button>
        <button onclick="logoutDash()" class="btn btn-ghost btn-sm">Logout</button>
      </div>
    </div>

    <div id="fileGrid" class="file-grid">
      <div class="loading"><div class="spinner"></div> Loading...</div>
    </div>
  </div>
</main>

<!-- Modal: Setup project baru -->
<div class="overlay" id="setupModal">
  <div class="modal">
    <div class="modal-header">
      <span style="font-weight:800;font-size:15px">Buat Project Baru</span>
      <button class="close-btn" onclick="closeModal('setupModal')">×</button>
    </div>
    <div class="modal-body">
      <div class="form-group">
        <label class="form-label">Nama Project</label>
        <input type="text" id="setupName" class="input" placeholder="My Awesome Bot" maxlength="32">
      </div>
      <p style="font-size:11px;color:var(--muted);line-height:1.6">API key akan di-generate secara otomatis. <strong>Simpan key-nya</strong> karena cuma muncul sekali dan tidak bisa di-recover.</p>
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="closeModal('setupModal')">Batal</button>
      <button class="btn btn-primary" onclick="createProject()">Generate Key</button>
    </div>
  </div>
</div>

<!-- Modal: Tampil API key -->
<div class="overlay" id="keyResultModal">
  <div class="modal">
    <div class="modal-header">
      <span style="font-weight:800;font-size:15px">🎉 Key Berhasil Dibuat!</span>
    </div>
    <div class="modal-body">
      <p style="font-size:12px;color:var(--muted);margin-bottom:12px">Ini API key kamu. <strong style="color:var(--red)">Simpan sekarang!</strong> Key ini tidak akan muncul lagi.</p>
      <div style="background:var(--surface2);border:1px solid var(--border-hi);border-radius:10px;padding:14px;margin-bottom:14px">
        <div class="mono" style="font-size:12px;color:var(--accent);word-break:break-all" id="newKeyDisplay">—</div>
      </div>
      <button onclick="copyText(document.getElementById('newKeyDisplay').innerText,'Key copied!')" class="btn btn-ghost btn-full btn-sm">Copy Key</button>
    </div>
    <div class="modal-footer">
      <button class="btn btn-primary" onclick="proceedToDash()">Buka Dashboard →</button>
    </div>
  </div>
</div>

<!-- Modal: Enter key -->
<div class="overlay" id="enterModal">
  <div class="modal">
    <div class="modal-header">
      <span style="font-weight:800;font-size:15px">Masukkan API Key</span>
      <button class="close-btn" onclick="closeModal('enterModal')">×</button>
    </div>
    <div class="modal-body">
      <div class="form-group">
        <label class="form-label">API Key</label>
        <input type="password" id="enterKeyInput" class="input mono" placeholder="plta_..." autocomplete="off" onkeydown="if(event.key==='Enter')enterDash()">
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="closeModal('enterModal')">Batal</button>
      <button class="btn btn-primary" onclick="enterDash()">Masuk →</button>
    </div>
  </div>
</div>

<!-- Modal: Edit/New file -->
<div class="overlay" id="fileModal">
  <div class="modal" style="max-width:680px">
    <div class="modal-header">
      <span style="font-weight:800;font-size:15px" id="fileModalTitle">New File</span>
      <button class="close-btn" onclick="closeModal('fileModal')">×</button>
    </div>
    <div class="modal-body">
      <div class="form-group">
        <label class="form-label">Filename</label>
        <div style="display:flex;align-items:center;gap:8px">
          <input type="text" id="fileNameInput" class="input mono" placeholder="users" maxlength="64" style="flex:1">
          <span class="mono" style="color:var(--muted);font-size:12px;flex-shrink:0">.json</span>
        </div>
        <p style="font-size:10px;color:var(--muted);margin-top:4px">Hanya huruf, angka, dash (-), underscore (_)</p>
      </div>
      <div class="form-group">
        <label class="form-label">Content (JSON)</label>
        <div id="ace-editor"></div>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="closeModal('fileModal')">Batal</button>
      <button class="btn btn-primary" id="saveFileBtn" onclick="saveFile()">Simpan</button>
    </div>
  </div>
</div>

<script>
let _aceEditor = null;
let _newKey = null;

function initAce(){
  if(_aceEditor) return;
  _aceEditor = ace.edit("ace-editor");
  _aceEditor.setTheme("ace/theme/tomorrow_night");
  _aceEditor.session.setMode("ace/mode/json");
  _aceEditor.setOptions({fontSize:"12px",showPrintMargin:false,tabSize:2,useSoftTabs:true});
}

// === AUTH ===
window._KEY = sessionStorage.getItem('dzk') || localStorage.getItem('dzk');
if(window._KEY) showDashboard();

function openSetupModal(){
  document.getElementById('setupName').value='';
  openModal('setupModal');
}

function openEnterModal(){
  document.getElementById('enterKeyInput').value='';
  openModal('enterModal');
}

async function createProject(){
  const name = document.getElementById('setupName').value.trim();
  if(!name){ toast('Isi nama project dulu','error'); return; }
  const btn = event.target; btn.disabled=true; btn.textContent='Creating...';
  try{
    const r = await fetch('/api/key/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
    const d = await r.json();
    if(!d.key) throw new Error();
    _newKey = d.key;
    document.getElementById('newKeyDisplay').textContent = d.key;
    closeModal('setupModal');
    openModal('keyResultModal');
  }catch(e){ toast('Gagal membuat project','error'); }
  finally{ btn.disabled=false; btn.textContent='Generate Key'; }
}

function proceedToDash(){
  if(!_newKey) return;
  saveKey(_newKey);
  closeModal('keyResultModal');
  showDashboard();
}

async function enterDash(){
  const key = document.getElementById('enterKeyInput').value.trim();
  if(!key){ toast('Masukkan API key dulu','error'); return; }
  // Verify key
  const r = await fetch('/api/files',{headers:{'x-api-key':key}});
  if(!r.ok){ toast('API key tidak valid','error'); return; }
  saveKey(key);
  closeModal('enterModal');
  showDashboard();
}

function saveKey(key){
  window._KEY = key;
  sessionStorage.setItem('dzk', key);
  localStorage.setItem('dzk', key);
}

function showDashboard(){
  document.getElementById('landingView').style.display='none';
  document.getElementById('dashView').style.display='block';
  // Mask key
  const k = window._KEY || '';
  document.getElementById('keyPreview').textContent = k.substring(0,14)+'...'+k.substring(k.length-6);
  document.getElementById('dashProjectName').textContent = 'My Files';
  loadFiles();
}

function logoutDash(){
  sessionStorage.removeItem('dzk');
  localStorage.removeItem('dzk');
  window._KEY = null;
  location.reload();
}

// === FILES ===
async function loadFiles(){
  const grid = document.getElementById('fileGrid');
  grid.innerHTML = '<div class="loading"><div class="spinner"></div> Loading...</div>';
  try{
    const r = await fetch('/api/files',{headers:{'x-api-key':window._KEY}});
    if(!r.ok){ toast('Gagal load files. Cek API key.','error'); return; }
    const files = await r.json();
    if(!files.length){
      grid.innerHTML = '<div class="empty"><div class="empty-icon">📂</div><h3>Belum ada file</h3><p>Klik "+ New File" untuk mulai</p></div>';
      return;
    }
    grid.innerHTML = files.map(f=>{
      const date = new Date(f.updated).toLocaleDateString('id-ID',{day:'2-digit',month:'short',year:'numeric'});
      return \`<div class="file-card">
        <div class="file-name">\${escHtml(f.name)}.json</div>
        <div class="file-meta">\${f.size} &nbsp;·&nbsp; \${date}</div>
        <div class="file-actions">
          <button class="btn btn-ghost btn-sm" onclick="editFile('\${escHtml(f.name)}')">✎ Edit</button>
          <button class="btn btn-danger btn-sm" onclick="deleteFile('\${escHtml(f.name)}')">✕ Hapus</button>
        </div>
      </div>\`;
    }).join('');
  }catch(e){ toast('Error loading files','error'); }
}

function openNewFileModal(){
  document.getElementById('fileModalTitle').textContent = 'New File';
  document.getElementById('fileNameInput').value = '';
  document.getElementById('fileNameInput').readOnly = false;
  initAce();
  _aceEditor.setValue(JSON.stringify({status:"ok",data:[]},null,2), -1);
  openModal('fileModal');
}

async function editFile(name){
  document.getElementById('fileModalTitle').textContent = 'Edit: '+name+'.json';
  document.getElementById('fileNameInput').value = name;
  document.getElementById('fileNameInput').readOnly = true;
  initAce();
  try{
    const r = await fetch('/api/raw/'+encodeURIComponent(name),{headers:{'x-api-key':window._KEY}});
    const data = await r.json();
    _aceEditor.setValue(JSON.stringify(data,null,2),-1);
  }catch(e){ _aceEditor.setValue('{}'); }
  openModal('fileModal');
}

async function saveFile(){
  const filename = document.getElementById('fileNameInput').value.trim();
  if(!filename){ toast('Isi nama file dulu','error'); return; }
  const content = _aceEditor.getValue();
  const btn = document.getElementById('saveFileBtn'); btn.disabled=true; btn.textContent='Saving...';
  try{
    const r = await fetch('/api/save',{
      method:'POST',
      headers:{'Content-Type':'application/json','x-api-key':window._KEY},
      body:JSON.stringify({filename, content})
    });
    const d = await r.json();
    if(!r.ok){ toast(d.error || 'Save gagal','error'); return; }
    closeModal('fileModal');
    toast('File tersimpan ✓','success');
    loadFiles();
  }catch(e){ toast('Error saving file','error'); }
  finally{ btn.disabled=false; btn.textContent='Simpan'; }
}

async function deleteFile(name){
  if(!confirm('Hapus "'+name+'.json"?')) return;
  const r = await fetch('/api/delete/'+encodeURIComponent(name),{method:'DELETE',headers:{'x-api-key':window._KEY}});
  if(r.ok){ toast('File dihapus','success'); loadFiles(); }
  else toast('Gagal hapus file','error');
}

function escHtml(s){ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
</script>
`));
});

// ==========================================
// DOCS PAGE
// ==========================================
app.get('/docs', (req, res) => {
    res.send(UI(`
<nav>
  <div class="nav-inner">
    <h1 class="logo">Dezz<span>DB</span></h1>
    <div class="nav-actions">
      <a href="/" class="btn btn-ghost btn-sm">← Back</a>
    </div>
  </div>
</nav>
<div class="container" style="max-width:740px">
  <div style="padding:40px 0 24px">
    <p class="label" style="margin-bottom:8px">Developer Guide</p>
    <h2 style="font-size:clamp(26px,5vw,42px);font-weight:800;color:#fff;letter-spacing:-1.5px;margin-bottom:12px">Integration Docs.</h2>
    <p style="color:var(--muted);font-size:14px">Semua endpoint yang kamu butuhin, dengan contoh kode lengkap.</p>
  </div>

  <hr class="divider">

  <!-- Auth -->
  <section style="margin-bottom:36px">
    <h3 style="font-size:15px;font-weight:800;color:#fff;margin-bottom:8px">Authentication</h3>
    <p style="font-size:13px;color:var(--muted);margin-bottom:12px">Kirim API key di header setiap request:</p>
    <div class="code-block">x-api-key: plta_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
Content-Type: application/json</div>
  </section>

  <!-- Endpoints -->
  <section style="margin-bottom:36px">
    <h3 style="font-size:15px;font-weight:800;color:#fff;margin-bottom:16px">Endpoints</h3>
    <div style="display:flex;flex-direction:column;gap:10px">
      ${[
        ['GET', '/api/files', 'List semua file'],
        ['GET', '/api/raw/:name', 'Baca isi file'],
        ['POST', '/api/save', 'Simpan / update file'],
        ['DELETE', '/api/delete/:name', 'Hapus file'],
        ['POST', '/api/key/create', 'Buat API key baru'],
      ].map(([m, p, d]) => `
      <div style="display:flex;align-items:center;gap:12px;padding:12px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:10px">
        <span class="tag ${m==='GET'?'tag-green':m==='POST'?'tag-purple':'tag-red'}">${m}</span>
        <span class="mono" style="font-size:12px;flex:1">${p}</span>
        <span style="font-size:11px;color:var(--muted)">${d}</span>
      </div>`).join('')}
    </div>
  </section>

  <!-- Contoh Node.js -->
  <section style="margin-bottom:36px">
    <h3 style="font-size:15px;font-weight:800;color:#fff;margin-bottom:8px">Node.js / WA Bot</h3>
    <div class="code-block"><span class="comment">// Install: npm install axios</span>
const axios = require('axios');
const BASE = 'https://yourserver.com';
const KEY = 'plta_your_key_here';

const headers = { 'x-api-key': KEY };

<span class="comment">// Baca data</span>
const getData = async (filename) => {
  const res = await axios.get(\`\${BASE}/api/raw/\${filename}\`, { headers });
  return res.data;
};

<span class="comment">// Simpan data</span>
const saveData = async (filename, content) => {
  await axios.post(\`\${BASE}/api/save\`, { filename, content }, { headers });
};

<span class="comment">// Hapus file</span>
const delData = async (filename) => {
  await axios.delete(\`\${BASE}/api/delete/\${filename}\`, { headers });
};</div>
  </section>

  <!-- Contoh Python -->
  <section style="margin-bottom:36px">
    <h3 style="font-size:15px;font-weight:800;color:#fff;margin-bottom:8px">Python</h3>
    <div class="code-block"><span class="comment"># pip install requests</span>
import requests, json

BASE = 'https://yourserver.com'
KEY = 'plta_your_key_here'
H = {'x-api-key': KEY, 'Content-Type': 'application/json'}

<span class="comment"># Baca file</span>
data = requests.get(f'{BASE}/api/raw/users', headers=H).json()

<span class="comment"># Simpan file</span>
requests.post(f'{BASE}/api/save', json={
  'filename': 'users',
  'content': {'data': []}
}, headers=H)</div>
  </section>

  <!-- Save payload -->
  <section style="margin-bottom:36px">
    <h3 style="font-size:15px;font-weight:800;color:#fff;margin-bottom:8px">POST /api/save — Body</h3>
    <div class="code-block">{
  "filename": "users",       <span class="comment">// tanpa .json</span>
  "content": { "key": "val" } <span class="comment">// JSON object / array</span>
}</div>
  </section>

  <!-- Aturan filename -->
  <section style="margin-bottom:48px">
    <h3 style="font-size:15px;font-weight:800;color:#fff;margin-bottom:8px">Aturan Filename</h3>
    <ul style="font-size:13px;color:var(--muted);line-height:2;padding-left:16px">
      <li>Hanya <code class="mono" style="font-size:11px;color:var(--accent)">a-z A-Z 0-9 - _</code></li>
      <li>Max 64 karakter</li>
      <li>Tanpa ekstensi <code class="mono" style="font-size:11px;color:var(--accent)">.json</code></li>
      <li>Max file size: 1MB</li>
    </ul>
  </section>
</div>
`, 'DezzDB — Docs'));
});

// ==========================================
// ADMIN PAGE
// ==========================================
app.get('/admin', (req, res) => {
    res.send(UI(`
<nav>
  <div class="nav-inner">
    <h1 class="logo">Dezz<span>DB</span> <span style="font-size:11px;color:var(--red);font-weight:700;letter-spacing:1px">ADMIN</span></h1>
    <div class="nav-actions">
      <button class="btn btn-ghost btn-sm" onclick="logout()">Logout</button>
    </div>
  </div>
</nav>
<div class="container">
  <div id="loginView" style="max-width:400px;margin:80px auto">
    <h2 style="font-size:24px;font-weight:800;color:#fff;margin-bottom:4px">Control Tower</h2>
    <p style="font-size:13px;color:var(--muted);margin-bottom:24px">Masukkan master key untuk lanjut.</p>
    <div class="form-group">
      <input type="password" id="mkInput" class="input mono" placeholder="mk_..." autocomplete="off" onkeydown="if(event.key==='Enter')adminLogin()">
    </div>
    <button onclick="adminLogin()" class="btn btn-primary btn-full">Masuk</button>
  </div>

  <div id="adminView" style="display:none">
    <div class="stat-grid" id="statGrid"></div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px" class="keys-bans-grid">
      <!-- Keys -->
      <div class="card" style="padding:20px">
        <p class="label" style="margin-bottom:14px">API Keys</p>
        <div id="keysList" style="display:flex;flex-direction:column;gap:6px;max-height:300px;overflow-y:auto"></div>
      </div>
      <!-- Bans -->
      <div class="card" style="padding:20px">
        <p class="label" style="margin-bottom:14px">Banned IPs</p>
        <div id="bansList" style="display:flex;flex-direction:column;gap:6px;max-height:260px;overflow-y:auto;margin-bottom:12px"></div>
        <div style="display:flex;gap:8px">
          <input type="text" id="banIpInput" class="input mono" placeholder="192.168.1.1" style="font-size:11px">
          <button onclick="banIP()" class="btn btn-danger btn-sm" style="flex-shrink:0">Ban</button>
        </div>
      </div>
    </div>
  </div>
</div>

<style>
@media(max-width:600px){
  .keys-bans-grid{grid-template-columns:1fr!important}
}
</style>

<script>
let MK = sessionStorage.getItem('admin_mk');
if(MK) loadAdmin();

async function adminLogin(){
  MK = document.getElementById('mkInput').value.trim();
  if(!MK){ toast('Masukkan master key','error'); return; }
  const r = await fetch('/api/admin/stats',{headers:{'x-api-key':MK}});
  if(!r.ok){ toast('Master key salah','error'); MK=null; return; }
  sessionStorage.setItem('admin_mk',MK);
  loadAdmin();
}

async function loadAdmin(){
  const r = await fetch('/api/admin/stats',{headers:{'x-api-key':MK}});
  if(!r.ok){ sessionStorage.removeItem('admin_mk'); MK=null; return; }
  const d = await r.json();

  document.getElementById('loginView').style.display='none';
  document.getElementById('adminView').style.display='block';

  document.getElementById('statGrid').innerHTML = \`
    <div class="stat-card"><div class="stat-num">\${d.total_keys}</div><div class="stat-label">Total Keys</div></div>
    <div class="stat-card"><div class="stat-num">\${d.bans.length}</div><div class="stat-label">Banned IPs</div></div>
    <div class="stat-card"><div class="stat-num">\${d.keys.filter(k=>!k.revoked).length}</div><div class="stat-label">Active Keys</div></div>
    <div class="stat-card"><div class="stat-num">\${d.keys.filter(k=>k.revoked).length}</div><div class="stat-label">Revoked</div></div>
  \`;

  document.getElementById('keysList').innerHTML = d.keys.length
    ? d.keys.map(k=>\`
      <div class="ip-item">
        <div>
          <div style="color:var(--text);font-size:11px">\${k.name}</div>
          <div style="color:var(--muted);font-size:9px">\${k.key_preview} &nbsp;·&nbsp; \${k.ip || '?'}</div>
        </div>
        <span class="tag \${k.revoked?'tag-red':'tag-green'}">\${k.revoked?'Revoked':'Active'}</span>
      </div>
    \`).join('')
    : '<p style="font-size:11px;color:var(--muted)">Belum ada keys</p>';

  document.getElementById('bansList').innerHTML = d.bans.length
    ? d.bans.map(ip=>\`
      <div class="ip-item">
        <span>\${ip}</span>
        <button class="btn btn-ghost btn-sm" onclick="unbanIP('\${ip}')">Unban</button>
      </div>
    \`).join('')
    : '<p style="font-size:11px;color:var(--muted)">Tidak ada banned IP</p>';
}

async function banIP(){
  const ip = document.getElementById('banIpInput').value.trim();
  if(!ip){ toast('Masukkan IP','error'); return; }
  const r = await fetch('/api/admin/ban',{method:'POST',headers:{'Content-Type':'application/json','x-api-key':MK},body:JSON.stringify({ip})});
  if(r.ok){ document.getElementById('banIpInput').value=''; toast('IP di-ban','success'); loadAdmin(); }
  else toast('Gagal ban IP','error');
}

async function unbanIP(ip){
  const r = await fetch('/api/admin/unban',{method:'POST',headers:{'Content-Type':'application/json','x-api-key':MK},body:JSON.stringify({ip})});
  if(r.ok){ toast('IP di-unban','success'); loadAdmin(); }
  else toast('Gagal unban','error');
}

function logout(){
  sessionStorage.removeItem('admin_mk');
  MK=null;
  location.reload();
}
</script>
`, 'DezzDB Admin'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('🚀 DezzDB Pro running on port', PORT));
