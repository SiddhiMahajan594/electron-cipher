# Electron Orbital Cipher v2.0
**AES-256 Encryption with Quantum-Inspired Orbital Visualization**

Siddhi Mahajan · Parth Lohia · Ayush Kothari · Prof. Khushbu Chauhan  
MPSTME, SVKM's NMIMS, Mumbai

---

## What's New in v2.0
- **Dynamic key-dependent S-boxes** via SHA-256(key ∥ orbital_name)
- **Avalanche Effect experiment** — measures cryptographic diffusion (30 trials)
- **Shannon Entropy analysis** — validates randomness at each pipeline stage
- **Performance timing benchmark** — quantifies orbital permutation overhead
- **Full REST API** via Flask
- **Interactive web frontend** — works in demo mode without backend

---

## Project Structure
```
electron_orbital_cipher/
├── backend/
│   ├── app.py              # Flask API + full cipher implementation
│   └── requirements.txt
└── frontend/
    └── index.html          # Standalone web UI (no build step needed)
```

---

## Quick Start

### Backend
```bash
cd backend
pip install -r requirements.txt
python app.py
# Runs at http://localhost:5000
```

### Frontend
Just open `frontend/index.html` in your browser.  
Click **"Connect Backend"** to link to the Flask API for full functionality.  
Without backend, the UI runs in **demo mode** with in-browser simulation.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/encrypt` | Encrypt plaintext |
| POST | `/api/decrypt` | Decrypt ciphertext |
| POST | `/api/experiments/avalanche` | Run avalanche effect test |
| POST | `/api/experiments/entropy` | Shannon entropy analysis |
| POST | `/api/experiments/timing` | Performance benchmark |
| GET  | `/api/health` | Health check |

### Example
```bash
curl -X POST http://localhost:5000/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "Hello World", "password": "my_key"}'
```

---

## Security Architecture

```
Password
   │
   ▼ PBKDF2 (SHA-256, 100K iterations, random 16-byte salt)
AES-256 Key
   │
   ├──► SHA-256(key ∥ "s") → s-orbital S-box (2-bit permutation)
   ├──► SHA-256(key ∥ "p") → p-orbital S-box (6-bit permutation)
   ├──► SHA-256(key ∥ "d") → d-orbital S-box (10-bit permutation)
   └──► SHA-256(key ∥ "f") → f-orbital S-box (14-bit permutation)
          │
Plaintext → Binary → Orbital Permutation → AES-CBC Encrypt → Base64
```

---

## For the Paper (Results to report)

Run these after connecting backend:

1. **Avalanche Effect** → target ~49–51% mean
2. **Entropy** → AES ciphertext should reach ~7.98 bits/byte
3. **Timing** → report overhead table across 64B, 128B, 512B, 1KB, 4KB

These three experiments constitute the experimental validation section.

---

## Deployment Options

**For CV / Portfolio:**
- Host `frontend/index.html` on GitHub Pages (free, instant)
- Deploy backend to Render.com or Railway.app (free tier)
- Update `BACKEND_URL` in the HTML to your deployed URL

**For Demo:**
- Frontend works standalone — demo mode runs entirely in browser
- Share the GitHub Pages link directly
