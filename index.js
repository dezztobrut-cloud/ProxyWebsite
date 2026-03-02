const express = require('express');
const axios = require('axios');
const app = express();
const PORT = 3000;

// 1. Setting User-Agent iOS (iPhone 14 Pro, Safari)
const IOS_USER_AGENT = 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1';

// 2. Script Suntikan untuk memalsukan Hardware (Baterai, CPU, RAM)
const SPOOF_SCRIPT = `
<script>
    Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 6});
    Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});
    Object.defineProperty(navigator, 'platform', {get: () => 'iPhone'});
    const mockBattery = { level: 0.85, charging: false, chargingTime: Infinity, dischargingTime: 3600, addEventListener: () => {} };
    navigator.getBattery = () => Promise.resolve(mockBattery);
</script>
`;

app.get('/', (req, res) => {
    res.send(`
        <div style="font-family: sans-serif; text-align: center; margin-top: 50px;">
            <h2>iOS Stealth Proxy 😎</h2>
            <form action="/proxy" method="GET">
                <input type="text" name="url" placeholder="Contoh: https://whatsmyua.info" style="width: 300px; padding: 10px;" required>
                <button type="submit" style="padding: 10px; cursor: pointer;">Nyamar Sekarang!</button>
            </form>
        </div>
    `);
});

app.get('/proxy', async (req, res) => {
    const targetUrl = req.query.url;

    if (!targetUrl) return res.status(400).send('URL-nya masukin dulu bro!');

    try {
        const response = await axios.get(targetUrl, {
            headers: {
                'User-Agent': IOS_USER_AGENT,
                'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7'
            },
            responseType: 'arraybuffer'
        });

        const contentType = response.headers['content-type'] || '';
        res.set('Content-Type', contentType);

        // 3. Logika Suntikan JS
        if (contentType.includes('text/html')) {
            let htmlData = response.data.toString('utf-8');
            htmlData = htmlData.replace('<head>', '<head>' + SPOOF_SCRIPT);
            return res.send(htmlData);
        }

        res.send(response.data);

    } catch (error) {
        res.status(500).send('Gagal ngakses web tujuan: ' + error.message);
    }
});

// FIX PALING AMAN: Pakai kutip dua biasa, gak pakai backtick biar gak error syntax
app.listen(PORT, () => {
    console.log("Stealth Proxy jalan di http://localhost:" + PORT);
});
