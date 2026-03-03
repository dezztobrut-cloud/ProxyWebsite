const express = require('express');
const fs = require('fs');
const path = require('path');
const archiver = require('archiver');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// --- KONFIGURASI ---
const MASTER_KEY = 'dezz-admin-rahasia'; // GANTI INI! Ini buat kontrol semua.
const DATA_DIR = path.join(__dirname, 'data');
const KEYS_FILE = path.join(__dirname, 'keys.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(KEYS_FILE)) fs.writeFileSync(KEYS_FILE, JSON.stringify({}));

// --- DATABASE HELPER ---
const getKeys = () => JSON.parse(fs.readFileSync(KEYS_FILE));
const saveKeys = (keys) => fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));

// --- SECURITY & LIMITER ---
const publicLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: { error: 'Terlalu banyak request. Coba lagi nanti.' }
});

// Middleware Cek Key (Public atau Master)
const auth = (req, res, next) => {
    const userKey = req.headers['x-api-key'];
    const keys = getKeys();

    if (userKey === MASTER_KEY) return next(); // Admin tembus
    if (keys[userKey] && !keys[userKey].revoked) return next(); // User aktif tembus
    
    res.status(401).json({ error: 'API Key Ilegal atau sudah di-Revoke!' });
};

// ==========================================
// 🛠️ API ENDPOINTS
// ==========================================

// 1. Generate Key Baru (Public)
app.post('/api/key/generate', publicLimiter, (req, res) => {
    const newKey = `dezz_${crypto.randomBytes(8).toString('hex')}`;
    const keys = getKeys();
    keys[newKey] = {
        ip: req.ip,
        createdAt: new Date().toISOString(),
        revoked: false
    };
    saveKeys(keys);
    res.json({ success: true, key: newKey });
});

// 2. Revoke Key (Admin Only)
app.post('/api/key/revoke', (req, res) => {
    if (req.headers['x-api-key'] !== MASTER_KEY) return res.status(403).send('Forbidden');
    const { targetKey } = req.body;
    const keys = getKeys();
    if (keys[targetKey]) {
        keys[targetKey].revoked = true;
        saveKeys(keys);
        res.json({ success: true, message: `Key ${targetKey} dicabut!` });
    } else {
        res.status(404).json({ error: 'Key gak ketemu.' });
    }
});

// 3. CRUD Data
app.post('/api/db/:nama', auth, (req, res) => {
    fs.writeFileSync(path.join(DATA_DIR, `${req.params.nama}.json`), JSON.stringify(req.body, null, 2));
    res.json({ success: true });
});

app.get('/api/db/:nama', auth, (req, res) => {
    const p = path.join(DATA_DIR, `${req.params.nama}.json`);
    if (fs.existsSync(p)) res.json(JSON.parse(fs.readFileSync(p)));
    else res.status(404).json({ error: 'Data kosong.' });
});

// ==========================================
// 🎨 UI JOKO-STYLE (MODERN DARK)
// ==========================================
app.get('/', (req, res) => {
    const keys = getKeys();
    const files = fs.readdirSync(DATA_DIR).filter(f => f.endsWith('.json'));
    
    res.send(`
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dezz Database | JokoUI</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;800&display=swap" rel="stylesheet">
        <style>body { font-family: 'Plus Jakarta Sans', sans-serif; }</style>
    </head>
    <body class="bg-[#0b0f1a] text-gray-200 p-6">
        <div class="max-w-5xl mx-auto">
            <nav class="flex justify-between items-center mb-12 bg-[#161b2c] p-4 rounded-2xl border border-gray-800">
                <h1 class="text-xl font-800 tracking-tighter text-white">DEZZ<span class="text-blue-500">DB.</span></h1>
                <div class="flex gap-4">
                    <button onclick="generateKey()" class="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-xl text-sm font-semibold transition-all">Get API Key</button>
                    <a href="/backup" class="text-gray-400 hover:text-white text-sm py-2">Backup</a>
                </div>
            </nav>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div class="lg:col-span-2 space-y-8">
                    <div class="bg-gradient-to-br from-blue-600/20 to-purple-600/20 p-8 rounded-3xl border border-blue-500/20">
                        <h2 class="text-3xl font-800 text-white mb-2">Build faster with JSON.</h2>
                        <p class="text-gray-400 mb-6">Database minimalis untuk project kecil lu. Support Per-IP Key & Auto Backup.</p>
                        <div class="bg-black/40 p-4 rounded-xl font-mono text-xs text-blue-300 border border-white/5">
                            POST /api/db/data-gua <br>
                            Header: x-api-key: YOUR_KEY
                        </div>
                    </div>

                    <div class="bg-[#161b2c] p-6 rounded-3xl border border-gray-800">
                        <h3 class="text-lg font-bold mb-4 text-white">Interactive Docs</h3>
                        <div class="space-y-4">
                            <div class="border-l-2 border-blue-500 pl-4">
                                <p class="text-sm font-bold text-blue-400">POST /api/key/generate</p>
                                <p class="text-xs text-gray-500">Dapatkan key baru tanpa admin.</p>
                            </div>
                            <div class="border-l-2 border-emerald-500 pl-4">
                                <p class="text-sm font-bold text-emerald-400">POST /api/db/:nama</p>
                                <p class="text-xs text-gray-500">Simpan JSON body lu ke server.</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="space-y-6">
                    <div class="bg-[#161b2c] p-6 rounded-3xl border border-gray-800">
                        <h3 class="text-sm font-bold text-gray-400 uppercase tracking-widest mb-4 text-center">Active Storage</h3>
                        <div class="space-y-3">
                            ${files.map(f => `
                                <div class="flex justify-between items-center bg-black/20 p-3 rounded-xl border border-white/5">
                                    <span class="text-sm text-gray-300 font-mono">${f}</span>
                                    <span class="text-[10px] bg-blue-500/10 text-blue-400 px-2 py-1 rounded-md">JSON</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            async function generateKey() {
                const res = await fetch('/api/key/generate', { method: 'POST' });
                const data = await res.json();
                if(data.key) {
                    alert('SIMPAN KEY INI BRO:\\n\\n' + data.key);
                } else {
                    alert('Limit tercapai. Coba nanti.');
                }
            }
        </script>
    </body>
    </html>
    `);
});

app.get('/backup', (req, res) => {
    const archive = archiver('zip', { zlib: { level: 9 } });
    res.attachment(\`backup-\${Date.now()}.zip\`);
    archive.pipe(res);
    archive.directory(DATA_DIR, false);
    archive.finalize();
});

const PORT = 3000;
app.listen(PORT, () => console.log(\`✅ Serverless DB ready on port \${PORT}\`));
