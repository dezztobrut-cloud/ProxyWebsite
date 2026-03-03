const express = require('express');
const fs = require('fs');
const path = require('path');
const archiver = require('archiver');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', true);
app.use(express.json());

// --- DATABASE CONFIG ---
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(__dirname, 'internal_db.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ keys: {}, bans: [], config: { master_key: 'admin_dezz_123' } }));
}

const getDB = () => JSON.parse(fs.readFileSync(DB_FILE));
const saveDB = (db) => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));

const getIP = (req) => {
    let ip = req.headers['x-forwarded-for'] || req.ip;
    if (ip.includes('::ffff:')) ip = ip.split(':').pop();
    return ip;
};

// --- SECURITY ---
const checkBan = (req, res, next) => {
    const db = getDB();
    if (db.bans.includes(getIP(req))) return res.status(403).send('IP BANNED');
    next();
};

app.use(checkBan);

// --- ISOLATION LOGIC ---
const getNamespace = (key) => crypto.createHash('md5').update(key).digest('hex').substring(0, 12);

// --- AUTH MIDDLEWARE ---
const authorize = (perm) => (req, res, next) => {
    const key = req.headers['x-api-key'];
    const db = getDB();
    if (key === db.config.master_key) {
        req.namespace = 'admin_global';
        return next();
    }
    const k = db.keys[key];
    if (k && !k.revoked && k.perms.includes(perm)) {
        req.namespace = getNamespace(key); // Kamar khusus user ini
        return next();
    }
    res.status(403).json({ error: 'Akses Ditolak!' });
};

// ==========================================
// 🚀 API ROUTES
// ==========================================

// User Generate Key (PLTA Style)
app.post('/api/key/create', rateLimit({ windowMs: 60*60*1000, max: 3 }), (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Nama project wajib isi' });
    
    const db = getDB();
    const newKey = `dezz_plta_${crypto.randomBytes(12).toString('hex')}`;
    db.keys[newKey] = { name, perms: ['READ', 'WRITE', 'DELETE'], revoked: false, ip: getIP(req) };
    saveDB(db);
    
    // Siapkan folder kamar
    const nsFolder = path.join(DATA_DIR, getNamespace(newKey));
    if (!fs.existsSync(nsFolder)) fs.mkdirSync(nsFolder);
    
    res.json({ success: true, key: newKey });
});

// CRUD Data (Isolated)
app.post('/api/db/:file', authorize('WRITE'), (req, res) => {
    const userDir = path.join(DATA_DIR, req.namespace);
    if (!fs.existsSync(userDir)) fs.mkdirSync(userDir);
    fs.writeFileSync(path.join(userDir, `${req.params.file}.json`), JSON.stringify(req.body, null, 2));
    res.json({ success: true });
});

app.get('/api/db/:file', authorize('READ'), (req, res) => {
    const filePath = path.join(DATA_DIR, req.namespace, `${req.params.file}.json`);
    if (fs.existsSync(filePath)) res.json(JSON.parse(fs.readFileSync(filePath)));
    else res.status(404).json({ error: 'Data gada di kamar lu.' });
});

// ==========================================
// 🎨 UI (CLEAN & RESPONSIVE)
// ==========================================
const UI_ASSETS = `
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Plus Jakarta Sans', sans-serif; background: #0b0f1a; color: #e2e8f0; }
        .card { background: rgba(22, 27, 44, 0.6); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.05); }
    </style>
`;

app.get('/', (req, res) => {
    res.send(`<html><head>${UI_ASSETS}<meta name="viewport" content="width=device-width, initial-scale=1"><title>DezzDB</title></head>
    <body class="p-4 md:p-10">
        <div class="max-w-4xl mx-auto">
            <nav class="flex justify-between items-center mb-10 card p-4 rounded-3xl">
                <h1 class="text-xl font-800 text-white italic">DEZZ<span class="text-blue-500">DB</span></h1>
                <a href="/admin" class="text-xs text-gray-600 hover:text-gray-400">Admin Area</a>
            </nav>
            <div class="card p-8 md:p-16 rounded-[2.5rem] text-center mb-8">
                <h2 class="text-4xl md:text-6xl font-800 text-white mb-6 leading-tight">Private JSON <br>Storage System.</h2>
                <p class="text-gray-500 mb-10 text-sm md:text-lg">Database PLTA dengan isolasi data. Key lu adalah kamar lu sendiri.</p>
                <div class="flex flex-col md:flex-row justify-center gap-4">
                    <input id="projName" placeholder="Nama Project Lu..." class="bg-black/40 p-4 rounded-2xl border border-white/10 text-sm focus:outline-none focus:border-blue-500 transition-all">
                    <button onclick="createProject()" class="bg-blue-600 hover:bg-blue-500 px-8 py-4 rounded-2xl font-800 text-white shadow-lg shadow-blue-600/20">Create Project</button>
                </div>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="card p-6 rounded-3xl text-sm">
                    <p class="text-blue-400 font-bold mb-1 italic">1. Create Key</p>
                    <p class="text-gray-500">Buat project dan dapetin API Key unik lu.</p>
                </div>
                <div class="card p-6 rounded-3xl text-sm">
                    <p class="text-emerald-400 font-bold mb-1 italic">2. Store Anything</p>
                    <p class="text-gray-500">Kirim JSON via POST, data lu aman di folder tersembunyi.</p>
                </div>
            </div>
        </div>
        <script>
            async function createProject() {
                const name = document.getElementById('projName').value;
                if(!name) return Swal.fire({title:'Woi!', text:'Isi nama projectnya', icon:'warning', background:'#161b2c', color:'#fff'});
                
                Swal.fire({title:'Tunggu...', didOpen:()=>Swal.showLoading(), background:'#161b2c', color:'#fff'});
                
                const res = await fetch('/api/key/create', {
                    method: 'POST',
                    headers: {'Content-Type':'application/json'},
                    body: JSON.stringify({ name })
                });
                const d = await res.json();
                
                if(d.success) {
                    Swal.fire({
                        title: 'PROJECT CREATED!',
                        html: '<p class="text-sm mb-4">Simpan key ini baik-baik (PLTA Access):</p><div class="bg-black p-4 rounded-xl font-mono text-blue-400 text-xs break-all border border-white/10">' + d.key + '</div>',
                        icon: 'success',
                        background: '#161b2c',
                        color: '#fff',
                        confirmButtonText: 'Oke, Paham!'
                    });
                    document.getElementById('projName').value = '';
                }
            }
        </script>
    </body></html>`);
});

// Admin Page (Sederhana buat Unban)
app.get('/admin', (req, res) => {
    const db = getDB();
    res.send(`<html><head>${UI_ASSETS}<title>Admin</title></head><body class="p-8">
        <div class="max-w-2xl mx-auto card p-8 rounded-3xl">
            <h1 class="text-2xl font-800 mb-6">Banned IPs List</h1>
            <div class="space-y-3">
                ${db.bans.map(ip => `<div class="flex justify-between p-3 bg-red-500/10 rounded-xl border border-red-500/20"><span class="font-mono text-xs">${ip}</span><button onclick="unban('${ip}')" class="text-xs text-red-400 underline">Unban</button></div>`).join('') || '<p class="text-gray-600 italic">No bans yet.</p>'}
            </div>
        </div>
        <script>
            async function unban(ip) {
                const master = prompt('Master Key:');
                await fetch('/api/admin/unban', {
                    method: 'POST',
                    headers: {'Content-Type':'application/json'},
                    body: JSON.stringify({ master, ip })
                });
                location.reload();
            }
        </script>
    </body></html>`);
});

// --- ADMIN API ---
app.post('/api/admin/unban', (req, res) => {
    const { master, ip } = req.body;
    const db = getDB();
    if (master !== db.config.master_key) return res.status(401).send('Salah');
    db.bans = db.bans.filter(b => b !== ip);
    saveDB(db);
    res.json({ success: true });
});

const PORT = 3000;
app.listen(PORT, () => console.log('🚀 Serverless DB God Mode V4 Running on ' + PORT));
