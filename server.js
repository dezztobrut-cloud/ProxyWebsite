const express = require('express');
const fs = require('fs');
const path = require('path');
const archiver = require('archiver');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', true);
app.use(express.json());

// --- DATABASE & PATHS ---
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(__dirname, 'internal_db.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ 
        keys: {}, bans: [], config: { master_key: 'admin_dezz_123' } 
    }));
}

const getDB = () => JSON.parse(fs.readFileSync(DB_FILE));
const saveDB = (db) => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
const getIP = (req) => (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim().replace('::ffff:', '');
const getNS = (key) => crypto.createHash('md5').update(key).digest('hex').substring(0, 12);

// --- SECURITY & BAN ---
app.use((req, res, next) => {
    const db = getDB();
    if (db.bans.includes(getIP(req))) return res.status(403).send('BANNED');
    next();
});

// --- AUTH MIDDLEWARE ---
const auth = (perm) => (req, res, next) => {
    const key = req.headers['x-api-key'] || req.query.key;
    const db = getDB();
    if (key === db.config.master_key) { req.is_admin = true; return next(); }
    const k = db.keys[key];
    if (k && !k.revoked && k.perms.includes(perm)) {
        req.namespace = getNS(key);
        req.key_info = k;
        return next();
    }
    res.status(401).json({ error: 'Unauthorized' });
};

// ==========================================
// 🚀 API CORE
// ==========================================

app.post('/api/key/create', rateLimit({ windowMs: 60000, max: 5 }), (req, res) => {
    const { name } = req.body;
    const db = getDB();
    const key = 'plta_' + crypto.randomBytes(12).toString('hex');
    db.keys[key] = { name: name || 'Project', perms: ['READ', 'WRITE', 'DELETE'], revoked: false, ip: getIP(req) };
    saveDB(db);
    res.json({ success: true, key });
});

app.get('/api/files', auth('READ'), (req, res) => {
    const dir = path.join(DATA_DIR, req.namespace);
    if (!fs.existsSync(dir)) return res.json([]);
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.json')).map(f => ({
        name: f.replace('.json', ''),
        size: (fs.statSync(path.join(dir, f)).size / 1024).toFixed(2) + ' KB'
    }));
    res.json(files);
});

app.get('/api/raw/:name', auth('READ'), (req, res) => {
    const p = path.join(DATA_DIR, req.namespace, req.params.name + '.json');
    if (fs.existsSync(p)) res.send(fs.readFileSync(p));
    else res.status(404).json({ error: 'Not Found' });
});

app.post('/api/save', auth('WRITE'), (req, res) => {
    const { filename, content } = req.body;
    const dir = path.join(DATA_DIR, req.namespace);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    try {
        const cleanJson = JSON.stringify(typeof content === 'string' ? JSON.parse(content) : content, null, 2);
        fs.writeFileSync(path.join(dir, filename + '.json'), cleanJson);
        res.json({ success: true });
    } catch (e) { res.status(400).json({ error: 'JSON Error' }); }
});

app.delete('/api/delete/:name', auth('DELETE'), (req, res) => {
    const p = path.join(DATA_DIR, req.namespace, req.params.name + '.json');
    if (fs.existsSync(p)) { fs.unlinkSync(p); res.json({ success: true }); }
    else res.status(404).send('Not Found');
});

// Admin Control
app.get('/api/admin/stats', auth('READ'), (req, res) => {
    if(!req.is_admin) return res.sendStatus(403);
    const db = getDB();
    res.json({ keys: db.keys, bans: db.bans });
});

app.post('/api/admin/ban', auth('READ'), (req, res) => {
    if(!req.is_admin) return res.sendStatus(403);
    const { ip } = req.body;
    const db = getDB();
    if(!db.bans.includes(ip)) db.bans.push(ip);
    saveDB(db);
    res.json({ success: true });
});

// ==========================================
// 🎨 PROFESSIONAL UI (Titanium Dark)
// ==========================================
const UI = (body) => `
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0">
    <title>DezzDB Pro</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.32.2/ace.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background: #08090a; color: #a0a0a0; -webkit-tap-highlight-color: transparent; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        .card { background: #111214; border: 1px solid #1c1e21; }
        .btn-blue { background: #2563eb; color: #fff; }
        .input-dark { background: #16171a; border: 1px solid #2a2d31; color: #fff; }
        #editor { height: 400px; width: 100%; border-radius: 12px; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-thumb { background: #2a2d31; border-radius: 10px; }
    </style>
</head>
<body class="p-4 md:p-8">${body}</body>
</html>`;

app.get('/', (req, res) => {
    res.send(UI(`
    <div class="max-w-5xl mx-auto">
        <header class="flex justify-between items-center mb-10">
            <h1 class="text-xl font-800 text-white tracking-tighter uppercase">Dezz<span class="text-blue-500">DB</span></h1>
            <button onclick="switchView()" id="navBtn" class="text-sm font-semibold text-blue-500">Dashboard</button>
        </header>

        <div id="landing" class="text-center py-10 md:py-20">
            <h2 class="text-4xl md:text-6xl font-800 text-white mb-6">Scale JSON <br>without limits.</h2>
            <p class="max-w-md mx-auto mb-10 text-sm md:text-base leading-relaxed">Sistem database PLTA dengan isolasi namespace otomatis. Data lu aman, pribadi, dan gampang diakses.</p>
            <button onclick="setupProject()" class="btn-blue px-10 py-4 rounded-full font-bold shadow-xl shadow-blue-500/10">Get Started</button>
        </div>

        <div id="dashboard" class="hidden">
            <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-8">
                <div>
                    <h3 class="text-white text-xl font-bold">My Projects</h3>
                    <p class="text-[10px] font-mono text-gray-600 truncate" id="keyLabel"></p>
                </div>
                <div class="flex gap-2 w-full md:w-auto">
                    <button onclick="openDocs()" class="flex-1 md:flex-none card px-4 py-2 rounded-xl text-xs">Docs</button>
                    <button onclick="editFile()" class="flex-1 md:flex-none btn-blue px-4 py-2 rounded-xl text-xs font-bold">+ New File</button>
                </div>
            </div>
            <div id="fileList" class="grid grid-cols-1 md:grid-cols-3 gap-4"></div>
        </div>
    </div>

    <script>
        let KEY = localStorage.getItem('dezz_v4_key');
        const view = {
            landing: document.getElementById('landing'),
            dash: document.getElementById('dashboard'),
            nav: document.getElementById('navBtn'),
            list: document.getElementById('fileList')
        };

        if(KEY) showDashboard();

        function switchView() {
            if(!KEY) {
                Swal.fire({
                    title: 'Access Key',
                    input: 'password',
                    background: '#111214', color: '#fff',
                    confirmButtonColor: '#2563eb'
                }).then(r => { if(r.value) { KEY = r.value; localStorage.setItem('dezz_v4_key', KEY); showDashboard(); }});
            } else {
                localStorage.removeItem('dezz_v4_key');
                location.reload();
            }
        }

        async function setupProject() {
            const { value: name } = await Swal.fire({
                title: 'Project Name', input: 'text', background: '#111214', color: '#fff',
                confirmButtonColor: '#2563eb'
            });
            if(name) {
                const r = await fetch('/api/key/create', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({name}) });
                const d = await r. r.json();
                KEY = d.key;
                localStorage.setItem('dezz_v4_key', KEY);
                Swal.fire('Created!', 'Key lu: ' + KEY, 'success').then(showDashboard);
            }
        }

        function showDashboard() {
            view.landing.classList.add('hidden');
            view.dash.classList.remove('hidden');
            view.nav.innerText = "Logout";
            document.getElementById('keyLabel').innerText = KEY;
            loadFiles();
        }

        async function loadFiles() {
            const r = await fetch('/api/files', { headers: {'x-api-key': KEY} });
            const files = await r.json();
            view.list.innerHTML = files.map(f => \`
                <div class="card p-5 rounded-2xl group transition-all hover:border-blue-500/50">
                    <div class="flex justify-between items-start mb-4">
                        <span class="text-white font-bold italic text-sm">\${f.name}.json</span>
                        <span class="text-[9px] text-gray-700">\${f.size}</span>
                    </div>
                    <div class="flex gap-2">
                        <button onclick="editFile('\${f.name}')" class="text-[10px] text-blue-500 font-bold uppercase tracking-wider">Edit</button>
                        <button onclick="deleteFile('\${f.name}')" class="text-[10px] text-red-500 font-bold uppercase tracking-wider">Delete</button>
                    </div>
                </div>
            \`).join('');
        }

        async function editFile(name = '') {
            let content = "{\\n  \\"status\\": \\"ok\\"\\n}";
            if(name) {
                const r = await fetch('/api/raw/' + name, { headers: {'x-api-key': KEY} });
                content = JSON.stringify(await r.json(), null, 2);
            }

            const { value: formValues } = await Swal.fire({
                title: name ? 'Edit JSON' : 'Create JSON',
                html: \`
                    <input id="fName" class="w-full card p-3 rounded-xl mb-4 text-sm" placeholder="Filename" value="\${name}">
                    <div id="editor">\${content}</div>
                \`,
                background: '#111214', color: '#fff',
                width: '95%',
                didOpen: () => {
                    window.aceEditor = ace.edit("editor");
                    window.aceEditor.setTheme("ace/theme/tomorrow_night");
                    window.aceEditor.session.setMode("ace/mode/json");
                    window.aceEditor.setOptions({ fontSize: "12px", showPrintMargin: false });
                },
                preConfirm: () => [document.getElementById('fName').value, window.aceEditor.getValue()]
            });

            if(formValues) {
                const r = await fetch('/api/save', {
                    method: 'POST',
                    headers: {'Content-Type':'application/json', 'x-api-key': KEY},
                    body: JSON.stringify({ filename: formValues[0], content: formValues[1] })
                });
                if(r.ok) loadFiles();
                else Swal.fire('Error', 'Invalid JSON Format', 'error');
            }
        }

        async function deleteFile(name) {
            Swal.fire({ title: 'Hapus?', text: name, icon: 'warning', showCancelButton: true, background: '#111214', color: '#fff' }).then(async (r) => {
                if(r.isConfirmed) {
                    await fetch('/api/delete/'+name, { method: 'DELETE', headers: {'x-api-key': KEY} });
                    loadFiles();
                }
            });
        }

        function openDocs() {
            location.href = '/docs';
        }
    </script>
    `));
});

// DOCS PAGE
app.get('/docs', (req, res) => {
    res.send(UI(`
    <div class="max-w-3xl mx-auto py-10">
        <a href="/" class="text-blue-500 text-sm font-bold mb-8 inline-block tracking-tighter uppercase">← Back</a>
        <h1 class="text-4xl font-800 text-white mb-10 leading-tight">Integration <br>Developer Guide.</h1>
        
        <div class="space-y-12">
            <section>
                <h3 class="text-white font-bold mb-4 italic">HTTP Headers</h3>
                <div class="card p-5 rounded-2xl font-mono text-xs text-blue-400">
                    x-api-key: your_plta_key_here <br>
                    Content-Type: application/json
                </div>
            </section>

            <section>
                <h3 class="text-white font-bold mb-4 italic text-sm uppercase">Example: WA Bot / Node.js</h3>
                <div class="card p-5 rounded-2xl font-mono text-xs text-gray-400 leading-relaxed">
                    const axios = require('axios');<br><br>
                    // GET DATA<br>
                    const getData = async () => {<br>
                    &nbsp;&nbsp;const res = await axios.get('https://domainlu.com/api/db/users', {<br>
                    &nbsp;&nbsp;&nbsp;&nbsp;headers: { 'x-api-key': 'KEY_LU' }<br>
                    &nbsp;&nbsp;});<br>
                    &nbsp;&nbsp;return res.data;<br>
                    }
                </div>
            </section>
        </div>
    </div>
    `));
});

// ADMIN PAGE
app.get('/admin', (req, res) => {
    res.send(UI(`
    <div class="max-w-4xl mx-auto">
        <h1 class="text-2xl font-800 text-white mb-10 italic">Control Tower</h1>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div class="card p-6 rounded-3xl">
                <h3 class="text-red-500 text-xs font-bold uppercase mb-4 tracking-widest">Banned IPs</h3>
                <div id="banList" class="space-y-2 text-[10px] font-mono"></div>
                <button onclick="manualBan()" class="mt-6 w-full card p-3 rounded-xl text-[10px] font-bold">Ban Manual IP</button>
            </div>
            <div class="card p-6 rounded-3xl">
                <h3 class="text-blue-500 text-xs font-bold uppercase mb-4 tracking-widest">Global Stats</h3>
                <div id="stats" class="space-y-2 text-[10px] font-mono"></div>
            </div>
        </div>
    </div>
    <script>
        const mk = () => localStorage.getItem('mk') || prompt('Master Key:');
        async function loadAdmin() {
            const r = await fetch('/api/admin/stats', { headers: {'x-api-key': mk()} });
            if(r.status === 401) return;
            localStorage.setItem('mk', mk());
            const d = await r.json();
            document.getElementById('banList').innerHTML = d.bans.map(ip => \`
                <div class="flex justify-between items-center p-2 bg-black/20 rounded-lg border border-white/5">
                    <span>\${ip}</span>
                    <button class="text-red-500">Unban</button>
                </div>
            \`).join('');
            document.getElementById('stats').innerHTML = \`Total Keys: \${Object.keys(d.keys).length}\`;
        }
        loadAdmin();
    </script>
    `));
});

const PORT = 3000;
app.listen(PORT, () => console.log('🚀 DezzDB Pro Active on ' + PORT));
