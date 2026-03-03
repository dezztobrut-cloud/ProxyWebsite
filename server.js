const express = require('express');
const fs = require('fs');
const path = require('path');
const archiver = require('archiver');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

// --- KONFIGURASI ---
const API_KEY = 'kunci-rahasia-vps-gua'; // Ganti ini!
const DATA_DIR = path.join(__dirname, 'data');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

// --- KEAMANAN & LIMITER ---
// Bikin aturan: 1 IP maksimal 100 request tiap 15 menit
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: { error: 'Santai bro! Terlalu banyak request dari IP lu. Tunggu 15 menit lagi.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Pakai limiter khusus buat jalur API aja
app.use('/api/', apiLimiter);

// Middleware buat ngecek API Key
const cekApiKey = (req, res, next) => {
    if (req.headers['x-api-key'] === API_KEY) next();
    else res.status(401).json({ error: 'Akses Ditolak! API Key salah bro.' });
};

// --- ENDPOINT API UTAMA ---
app.post('/api/db/:nama_db', cekApiKey, (req, res) => {
    const dbName = req.params.nama_db;
    const filePath = path.join(DATA_DIR, `${dbName}.json`);
    fs.writeFileSync(filePath, JSON.stringify(req.body, null, 2));
    res.json({ success: true, message: `Data di '${dbName}' sukses disimpan!` });
});

app.get('/api/db/:nama_db', cekApiKey, (req, res) => {
    const dbName = req.params.nama_db;
    const filePath = path.join(DATA_DIR, `${dbName}.json`);
    if (fs.existsSync(filePath)) {
        res.json(JSON.parse(fs.readFileSync(filePath)));
    } else {
        res.status(404).json({ error: 'Database kosong atau nggak ketemu!' });
    }
});

// --- FUNGSI MENGHITUNG USAGE DATABASE ---
const getDbStats = () => {
    const files = fs.readdirSync(DATA_DIR).filter(f => f.endsWith('.json'));
    let totalSize = 0;
    const dbList = files.map(file => {
        const stats = fs.statSync(path.join(DATA_DIR, file));
        totalSize += stats.size;
        return { 
            name: file.replace('.json', ''), 
            size: (stats.size / 1024).toFixed(2) + ' KB', 
            date: stats.mtime.toLocaleString('id-ID') 
        };
    });
    return { count: files.length, totalSize: (totalSize / 1024).toFixed(2) + ' KB', dbList };
};

// --- WEB DASHBOARD KEREN (TAILWIND CSS) ---
app.get('/', (req, res) => {
    const stats = getDbStats();
    
    let html = `
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Database Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-900 text-white font-sans antialiased p-4 md:p-8">
        <div class="max-w-4xl mx-auto">
            <div class="flex flex-col md:flex-row justify-between items-center mb-8 border-b border-gray-700 pb-6 gap-4">
                <h1 class="text-3xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-emerald-400">
                    🚀 Serverless DB
                </h1>
                <a href="/backup" class="bg-blue-600 hover:bg-blue-500 font-semibold px-5 py-2.5 rounded-lg shadow-lg shadow-blue-500/30 transition-all">
                    📦 Download Backup ZIP
                </a>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                <div class="bg-gray-800 p-6 rounded-2xl border border-gray-700 shadow-xl">
                    <h2 class="text-gray-400 text-xs font-bold uppercase tracking-widest mb-2">Total Koleksi</h2>
                    <p class="text-5xl font-black text-blue-400">${stats.count}</p>
                </div>
                <div class="bg-gray-800 p-6 rounded-2xl border border-gray-700 shadow-xl">
                    <h2 class="text-gray-400 text-xs font-bold uppercase tracking-widest mb-2">Storage Usage</h2>
                    <p class="text-5xl font-black text-emerald-400">${stats.totalSize}</p>
                </div>
            </div>

            <div class="bg-gray-800 rounded-2xl border border-gray-700 shadow-xl overflow-hidden">
                <div class="p-6 border-b border-gray-700 bg-gray-800/50">
                    <h2 class="text-xl font-bold text-gray-100">📂 Detail Database</h2>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left">
                        <thead>
                            <tr class="bg-gray-900/50 text-gray-400 text-sm border-b border-gray-700">
                                <th class="p-4 font-semibold">Nama Endpoint</th>
                                <th class="p-4 font-semibold">Ukuran</th>
                                <th class="p-4 font-semibold">Terakhir Update</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-700/50">
                            ${stats.dbList.length > 0 ? stats.dbList.map(db => `
                                <tr class="hover:bg-gray-700/30 transition-colors">
                                    <td class="p-4 font-medium text-blue-300">/api/db/${db.name}</td>
                                    <td class="p-4"><span class="bg-gray-900 text-gray-300 px-3 py-1 rounded-md text-xs border border-gray-600">${db.size}</span></td>
                                    <td class="p-4 text-gray-400 text-sm">${db.date}</td>
                                </tr>
                            `).join('') : '<tr><td colspan="3" class="p-8 text-center text-gray-500 italic">Belum ada data yang disimpan.</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </body>
    </html>
    `;
    res.send(html);
});

// Endpoint Download
app.get('/backup', (req, res) => {
    const archive = archiver('zip', { zlib: { level: 9 } });
    res.attachment(\`backup-database-\${Date.now()}.zip\`);
    archive.pipe(res);
    archive.directory(DATA_DIR, false);
    archive.finalize();
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(\`✅ Server nyala di port \${PORT}\`);
});
