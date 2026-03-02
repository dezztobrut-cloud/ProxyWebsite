const express = require('express');
const axios = require('axios');
const app = express();
const PORT = 3000;

const ALIEN_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Dezz/99.9';

const DEVTOOLS_SCRIPT = `
<script src="https://cdn.jsdelivr.net/npm/eruda"></script>
<script src="https://cdn.jsdelivr.net/npm/eruda-code"></script>
<script src="https://cdn.jsdelivr.net/npm/eruda-dom"></script>

<script>
    // Inisialisasi aman
    if (typeof eruda !== 'undefined') {
        eruda.init(); 
        try { eruda.add(erudaCode); } catch(e) {}
        try { eruda.add(erudaDom); } catch(e) {}

        const OrigWebSocket = window.WebSocket;
        window.WebSocket = function(url, protocols) {
            console.log('%c[WS] Saluran terbuka ke: ' + url, 'color: #00ffff; font-weight: bold;');
            const ws = new OrigWebSocket(url, protocols);
            ws.addEventListener('message', function(e) { console.log('%c[WS TARGET MEMBALAS]', 'color: #00ff00', e.data); });
            const origSend = ws.send;
            ws.send = function(data) {
                console.log('%c[WS DATA DIKIRIM KELUAR]', 'color: #ff0000', data);
                origSend.apply(this, arguments);
            };
            return ws;
        };

        const origFetch = window.fetch;
        window.fetch = async function() {
            console.log('%c[API CALL DETECTED]', 'color: #ffaa00; font-weight: bold;', arguments);
            return origFetch.apply(this, arguments);
        };

        document.addEventListener('submit', function(e) {
            e.preventDefault(); 
            const formData = new FormData(e.target);
            const dataBajakan = {};
            for (let [key, value] of formData.entries()) { dataBajakan[key] = value; }
            console.log('%c[🔥 DATA FORM DICEGAT 🔥]', 'color: #ffffff; background: #ff0000; font-weight: bold; padding: 5px;');
            console.table(dataBajakan);
            alert('Form dicegat! Buka Console Eruda buat liat datanya!');
        });

        setTimeout(() => {
            if(eruda.get('snippets')) {
                eruda.get('snippets').add('💥 Kuras Storage Lokal', 'Ambil semua data rahasia browser', () => {
                    console.log('Cookies:', document.cookie);
                    console.log('LocalStorage:', localStorage);
                    alert('Data Storage dibongkar di Console!');
                });
            }
        }, 1500);
        
        console.log("%c[DEZZ INTERCEPTOR AKTIF - READY TO HIJACK!]", "color: #00ff00; font-weight: bold; padding: 10px; border: 1px solid #00ff00;");
    }
</script>
`;

app.get('/', (req, res) => {
    res.send(`
        <div style="font-family: monospace; text-align: center; margin-top: 50px; background-color: #0a0a0a; color: #00ffcc; padding: 50px; border-radius: 10px;">
            <h2>👁️ DEZZ DEEP INSPECTOR (FIXED)</h2>
            <form action="/proxy" method="GET">
                <input type="text" name="url" placeholder="https://tools.dezz.biz.id/tt" style="width: 350px; padding: 10px;" required>
                <button type="submit" style="padding: 10px; background-color: #00ffcc; color: #000; font-weight: bold;">SUNTIK WEB!</button>
            </form>
        </div>
        <style>body { background-color: #050505; color: white; }</style>
    `);
});

app.get('/proxy', async (req, res) => {
    let targetUrl = req.query.url;
    if (!targetUrl) return res.send('URL KOSONG!');
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

    try {
        const response = await axios.get(targetUrl, {
            headers: { 
                'User-Agent': ALIEN_USER_AGENT,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            },
            responseType: 'arraybuffer',
            validateStatus: () => true 
        });

        const contentType = response.headers['content-type'] || '';
        res.set('Content-Type', contentType);

        if (contentType.includes('text/html')) {
            let htmlData = response.data.toString('utf-8');
            
            if (/<head[^>]*>/i.test(htmlData)) {
                htmlData = htmlData.replace(/<head[^>]*>/i, match => match + DEVTOOLS_SCRIPT);
            } else {
                htmlData = DEVTOOLS_SCRIPT + htmlData;
            }

            // PERBAIKAN REGEX: BIARKAN CDN & FILE JS LEWAT TANPA DIPROXY!
            htmlData = htmlData.replace(/(href|src|action)=["'](.*?)["']/gi, (match, attr, link) => {
                if (link.startsWith('data:') || link.startsWith('javascript:') || link.startsWith('#') || 
                    link.includes('cdn.jsdelivr.net') || link.includes('unpkg.com') || link.includes('cdnjs.cloudflare.com')) {
                    return match; // Loloskan CDN biar script target/Eruda gak meledak!
                }
                try {
                    const absoluteUrl = new URL(link, targetUrl).href;
                    // Loloskan script eksternal JS biar gak error parse di proxy
                    if(absoluteUrl.endsWith('.js')) return `${attr}="${absoluteUrl}"`; 
                    
                    return `${attr}="/proxy?url=${encodeURIComponent(absoluteUrl)}"`;
                } catch (e) { return match; }
            });

            return res.send(htmlData);
        }
        res.send(response.data);
    } catch (error) {
        res.status(500).send('<h2>[ERROR] Web Target Menolak: ' + error.message + '</h2>');
    }
});

app.listen(PORT, () => {
    console.log("🔥 DEZZ INSPECTOR NYALA Boss! Akses di http://localhost:" + PORT);
});
