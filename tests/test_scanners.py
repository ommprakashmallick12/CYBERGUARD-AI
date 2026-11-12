"""CyberGuard AI - scanner tests (standard library only).  Run:  python tests/test_scanners.py"""
import os, sys, struct, zlib, random, json, threading, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import server

def png(w, h, ch, pix):                                   # pix: bytearray w*h*ch, filter 0
    raw = b''.join(b'\x00' + bytes(pix[y * w * ch:(y + 1) * w * ch]) for y in range(h))
    def chunk(t, b): return struct.pack('>I', len(b)) + t + b + struct.pack('>I', zlib.crc32(t + b) & 0xffffffff)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, {1: 0, 3: 2, 4: 6}[ch], 0, 0, 0)) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'')
def bmp(w, h, pix):                                       # 24-bit, pix RGB top-down
    stride = (w * 3 + 3) // 4 * 4; rows = b''
    for y in range(h - 1, -1, -1):
        r = pix[y * w * 3:(y + 1) * w * 3]; rows += b''.join(bytes((r[i + 2], r[i + 1], r[i])) for i in range(0, len(r), 3)).ljust(stride, b'\0')
    return b'BM' + struct.pack('<IHHI', 54 + len(rows), 0, 0, 54) + struct.pack('<IiiHHIIiiII', 40, w, h, 1, 24, 0, len(rows), 2835, 2835, 0, 0) + rows
def noise(n, seed=1):
    rnd = random.Random(seed); return bytearray(rnd.randrange(256) for _ in range(n))
def embed(buf, payload, plane=0, order='MSB', channels=None, bpp=3):
    bits = ''.join(format(b, '08b') if order == 'MSB' else format(b, '08b')[::-1] for b in payload)
    idx = [i for i in range(len(buf)) if channels is None or (i % bpp) in channels]
    assert len(bits) <= len(idx), 'payload too big'
    out = bytearray(buf)
    for b, i in zip(bits, idx): out[i] = (out[i] & ~(1 << plane) & 255) | (int(b) << plane)
    return out
R = []
def check(name, cond, extra=''):
    R.append((name, bool(cond))); print(('PASS ' if cond else 'FAIL ') + name + (' - ' + extra if extra and not cond else ''))
def stego(d, name='t.png'):
    r = server.analyze_photo(d, name); b = [x for x in r['blocks'] if x['title'] == 'STEGANOGRAPHIC HIDDEN TEXT OUTPUT']; return r, (b[0]['text'] if b else '')

W = H = 48
msg = 'Hello CyberGuard 🔐 ZW\u200bX é'
data = msg.encode('utf-8'); lp = struct.pack('>I', len(data)) + data
# photo scanner
rgb = noise(W * H * 3)
r, t = stego(png(W, H, 3, embed(rgb, lp)));                 check('PNG RGB length-prefixed LSB recovered exactly (emoji+ZWSP+accent)', msg in t and 'SUCCESS' in t)
r, t = stego(png(W, H, 3, embed(rgb, data + b'\0')));       check('PNG RGB null-terminated recovered', msg in t and 'Null-terminated' in t)
r, t = stego(png(W, H, 3, embed(rgb, lp, order='LSB')));    check('PNG LSB-first bit order recovered', msg in t)
r, t = stego(png(W, H, 3, embed(rgb, lp, plane=1)));        check('PNG bit-plane 1 recovered', msg in t)
rgba = noise(W * H * 4, 2)
r, t = stego(png(W, H, 4, embed(rgba, lp, bpp=4, channels=[0, 1, 2, 3]))); check('PNG RGBA recovered', msg in t)
r, t = stego(png(W, H, 4, embed(rgba, lp, bpp=4, channels=[3])));          check('PNG alpha-only channel recovered', msg in t)
r, t = stego(png(W, H, 3, embed(rgb, lp, channels=[0], bpp=3)));           check('PNG red-channel-only recovered', msg in t)
r, t = stego(bmp(W, H, embed(rgb, lp)), 't.bmp');           check('BMP 24-bit recovered', msg in t)
r, t = stego(png(W, H, 3, rgb));                            check('Random-noise PNG: no fake message', 'No recoverable steganographic text detected.' in t and 'SUCCESS' not in t, t[:300])
flat = bytearray([120] * (W * H * 3)); r, t = stego(png(W, H, 3, flat)); check('Flat PNG: no fake message', 'No recoverable steganographic text detected.' in t)
_rj = random.Random(5); junk = bytes(_rj.randrange(256) for _ in range(40)); r, t = stego(png(W, H, 3, embed(rgb, struct.pack('>I', 40) + junk)))
check('Undecodable payload: bytes shown, decoding problem explained', 'DECODING FAILED' in t and 'could not be decoded' in t, t[:300])
r, t = stego(b'\xff\xd8\xff\xe0' + b'\0' * 200 + b'\xff\xd9', 'x.jpg'); check('JPEG handled: unsupported pixel stego stated honestly', 'NOT SUPPORTED' in t or 'NOT CHECKED' in t)
try: server.analyze_photo(b'not an image at all', 'bad.png'); check('Invalid image does not crash', True)
except server.UserError: check('Invalid image rejected cleanly', True)
check('OCR block separate from stego block', any(b['title'].startswith('OCR') for b in r['blocks']))
# deepfake
r = server.analyze_deepfake(png(W, H, 3, rgb), 'f.png'); tx = ' '.join(b['text'] for b in r['blocks'])
check('Deepfake: model-unavailable disclosure + honest verdict', 'Deepfake detection model unavailable.' in tx and r['verdict'] in ('No supported manipulation indicators detected', 'Inconclusive', 'Potential manipulation indicators detected'))
try: server.analyze_deepfake(b'GARBAGE', 'x.mp4'); check('Deepfake: video/unsupported rejected cleanly', False)
except server.UserError: check('Deepfake: video/unsupported rejected cleanly', True)
# phishing (offline: threat intel disabled, network layers may report NOT PERFORMED)
os.environ['CYBERGUARD_THREAT_INTEL'] = '0'
for label, u in [('normal', 'https://www.wikipedia.org/'), ('suspicious', 'http://secure-login-paypal.verify-account.example.top/signin?redirect=http://evil.tk&password=1'), ('IP-based', 'http://192.0.2.10:8080/login'),
                 ('unicode domain', 'https://раураl.com/login'), ('lookalike', 'https://paypa1-support.com/verify'), ('encoded', 'https://example.com/%68%74%74%70%73%3A%2F%2Fevil.tk/%2e%2e/login')]:
    try:
        r = server.analyze_link(u); check('Phishing %s -> %s (%d)' % (label, r['verdict'], r['score']), r['layers'] and 'RECOMMENDED' in r['report'].upper())
    except Exception as e: check('Phishing %s' % label, False, repr(e))
rs = lambda u: server.analyze_link(u)['score']
check('Phishing: suspicious scores higher than normal', rs('http://secure-login-paypal.verify-account.example.top/signin') > rs('https://www.wikipedia.org/'))
# emoji
def em(t): return server.analyze_text(t)
r = em('Hello 😀👍🏽🇮🇳 world'); check('Emoji normal: not malicious', r['level'] == 'safe', r['verdict'])
r = em('Hi 👨\u200d👩\u200d👧 ❤\ufe0f'); check('Emoji ZWJ/VS16 sequence not flagged dangerous', r['level'] != 'bad', r['verdict'])
bits = ''.join(format(b, '08b') for b in b'secret!'); zw = 'A' + ''.join('\u200b' if x == '0' else '\u200c' for x in bits) + 'B'
r = em(zw); check('Hidden zero-width message recovered', 'secret!' in r['report'] and r['level'] != 'safe')
r = em('x\ufe0f\u200dy'); check('Char-level details list code point + hex', 'U+FE0F' in r['report'] and 'ef b8 8f' in r['report'])
vs = 'ok' + ''.join(chr(0xE0100 + b - 16) if b >= 16 else chr(0xFE00 + b) for b in b'hidden msg'); r = em(vs); check('Variation-selector hidden text recovered', 'hidden msg' in r['report'])
r = em('pаypal'); check('Mixed-script (Cyrillic а) flagged', 'MIXED SCRIPTS' in r['report'])
# HTTP end to end
srv = server.ThreadingHTTPServer(('127.0.0.1', 0), server.H); port = srv.server_address[1]; threading.Thread(target=srv.serve_forever, daemon=True).start()
base = 'http://127.0.0.1:%d' % port
def get(p): return urllib.request.urlopen(base + p, timeout=10).read()
def post(p, body, h=None):
    rq = urllib.request.Request(base + p, data=body, headers=h or {}); return json.loads(urllib.request.urlopen(rq, timeout=60).read())
check('HTTP /health', b'"' in get('/health'))
for pg in ('/', '/link', '/emoji', '/photo', '/deepfake', '/contacts'): check('HTTP page ' + pg, b'<script src="app.js">' in get(pg))
res = post('/api/photo', png(W, H, 3, embed(rgb, lp)), {'X-Filename': 'a.png'}); check('HTTP /api/photo end-to-end', any(b['title'] == 'STEGANOGRAPHIC HIDDEN TEXT OUTPUT' and msg in b['text'] for b in res['blocks']))
res = post('/api/emoji', json.dumps({'text': zw}).encode(), {'Content-Type': 'application/json'}); check('HTTP /api/emoji end-to-end', 'secret!' in res['report'])
res = post('/api/deepfake', png(W, H, 3, rgb), {'X-Filename': 'a.png'}); check('HTTP /api/deepfake end-to-end', res['blocks'])
srv.shutdown()
print('\n%d/%d passed' % (sum(ok for _, ok in R), len(R))); sys.exit(0 if all(ok for _, ok in R) else 1)
