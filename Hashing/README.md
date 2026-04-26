# CryptoLab — SHA-512 & CMAC-AES128

A Flask web application that implements **SHA-512** and **CMAC-AES128** entirely from scratch (no hashlib, no cryptography library), with step-by-step visualization of all intermediate computations.

---

## Features

- **SHA-512**: Full hand-rolled implementation including padding, message schedule (W[0]–W[79]), 80-round compression, all intermediate hash values.
- **CMAC-AES128**: Full AES-128 key expansion + encryption, subkey (K1/K2) generation, message blocking with padding, CBC-MAC chain.
- **Block highlighting**: Incomplete (padded) CMAC blocks are visually highlighted in amber with a pulse animation.
- **Collapsible steps**: Every intermediate step is shown in a collapsible card.

---

## Setup & Run

```bash
# Install Flask
pip install -r requirements.txt

# Run the app
python app.py
```

Then open http://localhost:5000

---

## Project Structure

```
crypto_app/
├── app.py              # Flask routes
├── sha512_impl.py      # SHA-512 from scratch
├── cmac_impl.py        # AES-128 + CMAC from scratch
├── requirements.txt
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── sha512.html
│   └── cmac.html
└── static/
    ├── css/style.css
    └── js/
        ├── main.js
        ├── sha512.js
        └── cmac.js
```

---

## Implementation Notes

### SHA-512
- Constants H0–H7: fractional parts of √ of first 8 primes
- Constants K[0–79]: fractional parts of ∛ of first 80 primes
- Padding: append 0x80, zero-fill, 128-bit big-endian length suffix
- Schedule: W[i] = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
- 80 rounds of Ch/Maj/Σ operations

### CMAC-AES128
- AES-128 key schedule: 10 rounds, 11 round keys
- Subkeys: L = AES(0^128), K1 = L<<1 ⊕ (0x87 if MSB), K2 = K1<<1 ⊕ (0x87 if MSB)
- Padding for incomplete last block: append 0x80 then zeros
- Last complete block XORed with K1; last incomplete block XORed with K2
