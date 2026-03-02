const express = require('express');
const axios = require('axios');
const app = express();
const PORT = 3000;

// Header HTTP biar dikira dari Jepang beneran
const ALIEN_USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 QuantumBrowser/99.9';

// Script Suntikan Dewa (Spek Alien / Ga Ngotak)
const SPOOF_SCRIPT = `
<script>
    const customUA = '${ALIEN_USER_AGENT}';
    
    // 1. Identitas & OS
    Object.defineProperty(navigator, 'userAgent', {get: () => customUA});
    Object.defineProperty(navigator, 'appVersion', {get: () => customUA});
    Object.defineProperty(navigator, 'vendor', {get: () => 'Apple Computer, Inc.'});
    Object.defineProperty(navigator, 'platform', {get: () => 'MacIntel'});

    // 2. RAM & CPU (Ga Ngotak: 2 TB RAM, 1024 CPU Cores)
    Object.defineProperty(navigator, 'deviceMemory', {get: () => 2048}); 
    Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 1024});

    // 3. Layar & Warna (Ga Ngotak: 32K Resolution, 256-bit Color)
    Object.defineProperty(window.screen, 'width', {get: () => 32768});
    Object.defineProperty(window.screen, 'height', {get: () => 18432});
    Object.defineProperty(window.screen, 'colorDepth', {get: () => 256});
    Object.defineProperty(window.screen, 'pixelDepth', {get: () => 256});

    // 4. Baterai (1000% Reaktor Nuklir)
    const mockBattery = { level: 10.0, charging: true, chargingTime: 0, dischargingTime: Infinity, addEventListener: () => {} };
    if(navigator.getBattery) navigator.getBattery = () => Promise.resolve(mockBattery);

    // 5. Bahasa & Waktu (Jepang)
    Object.defineProperty(navigator, 'language', {get: () => 'ja-JP'});
    Object.defineProperty(navigator, 'languages', {get: () => ['ja-JP', 'ja', 'en-US', 'en']});
    Date.prototype.getTimezoneOffset = () => -540; // UTC+9 (Asia/Tokyo)

    // 6. Koneksi Internet (6G, Ping 0.1ms, Speed 999999 Mbps)
    const mockConnection = { effectiveType: '6g', downlink: 999999, rtt: 0, saveData: false };
    Object.defineProperty(navigator, 'connection', {get: () => mockConnection});

    // 7. JS Heap Limit (10 TB Limit Memory)
    if (performance && performance.memory) {
        Object.defineProperty(performance, 'memory', {
            get: () => ({ jsHeapSizeLimit: 10995116277760, totalJSHeapSize: 104857600, usedJSHeapSize: 52428800 })
        });
    }

    // 8. GPU Renderer (NVIDIA RTX 9090 Ti Super Quantum 256GB)
    const getContext = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function(type, contextAttributes) {
        const context = getContext.apply(this, arguments);
        if (context && (type === 'webgl' || type === 'webgl2')) {
            const getParameter = context.getParameter;
            context.getParameter = function(parameter) {
                if (parameter === 37445) return 'NVIDIA Corporation'; // UNMASKED_VENDOR_WEBGL
                if (parameter === 37446) return 'NVIDIA GeForce RTX 9090 Ti Super Quantum 256GB'; // UNMASKED_RENDERER_WEBGL
                return getParameter.apply(this, arguments);
            };
        }
        return context;
    };

    // 9. Hardware Media Ports (100+ Port Aktif) & Audio 384000 Hz
    navigator.mediaDevices.enumerateDevices = () => Promise.resolve([
        {kind: 'audioinput', label: 'Quantum Mic', deviceId: 'mic1', groupId: 'g1'},
        {kind: 'videoinput', label: 'Hologram Camera', deviceId: 'cam1', groupId: 'g2'}
    ].concat(Array(98).fill({kind: 'audiooutput', label: 'Extra Quantum Port', deviceId: 'ex', groupId: 'g3'})));
    
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if(AudioContext) {
        Object.defineProperty(AudioContext.prototype, 'sampleRate', { get: () => 384000 });
    }

    // 10. Force GPS Location (Tengah kota Tokyo)
    navigator.geolocation.getCurrentPosition = (success) => {
        success({
            coords: { latitude: 35.6895, longitude: 139.6917, accuracy: 1, altitude: 100, altitudeAccuracy: 1, heading: 0, speed: 0 },
            timestamp: Date.now()
        });
    };

    // 11. Blokir WebRTC (Cegah bocor IP Local/LAN)
    const originalRTCPeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
    if (originalRTCPeerConnection) {
        window.RTCPeerConnection = function() {
            return { createDataChannel: () => ({}), setLocalDescription: () => Promise.resolve(), createOffer: () => Promise.resolve() };
        };
    }
</script>
`;

app.get('/', (req, res) => {
    res.send(`
        <div style="font-family: sans-serif; text-align: center; margin-top: 50px; background-color: #1a1a1a; color: #00ff00; padding: 50px; border-radius: 10px;">
            <h2>🛸 Alien Stealth Proxy (Area 51)</h2>
            <form action="/proxy" method="GET">
                <input type="text" name="url" placeholder="Contoh: https://deviceinfo.me" style="width: 350px; padding: 10px; border-radius: 5px; border: none;" required>
                <button type="submit" style="padding: 10px; cursor: pointer; background-color: #00ff00; color: #000; font-weight: bold; border-radius: 5px; border: none;">Teleportasi!</button>
            </form>
        </div>
        <style>body { background-color: #0d0d0d; }</style>
    `);
});

app.get('/proxy', async (req, res) => {
    const targetUrl = req.query.url;

    if (!targetUrl) return res.status(400).send('URL-nya masukin dulu bro!');

    try {
        const response = await axios.get(targetUrl, {
            headers: {
                'User-Agent': ALIEN_USER_AGENT,
                'Accept-Language': 'ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7',
                'X-Forwarded-For': '103.1.200.0' // Palsuin IPv4 Publik dari regional Asia
            },
            responseType: 'arraybuffer',
            validateStatus: () => true 
        });

        const contentType = response.headers['content-type'] || '';
        res.set('Content-Type', contentType);

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

app.listen(PORT, () => {
    console.log("Alien Proxy nyala di http://localhost:" + PORT);
});
