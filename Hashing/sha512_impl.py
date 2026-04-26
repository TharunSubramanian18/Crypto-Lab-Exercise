"""
SHA-512 implementation from scratch (no hashlib or cryptography libraries).
Returns detailed intermediate steps for educational display.
"""

import struct

# SHA-512 Initial Hash Values (first 64 bits of fractional parts of sqrt of first 8 primes)
H0 = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
]

# SHA-512 Round Constants (first 64 bits of fractional parts of cube roots of first 80 primes)
K = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
]

MASK64 = 0xFFFFFFFFFFFFFFFF


def rotr64(x, n):
    """Right rotate 64-bit integer x by n bits."""
    return ((x >> n) | (x << (64 - n))) & MASK64


def ch(x, y, z):
    return (x & y) ^ (~x & z) & MASK64


def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def sigma0_big(x):
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39)


def sigma1_big(x):
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41)


def sigma0_small(x):
    return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7)


def sigma1_small(x):
    return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6)


def pad_message(message_bytes):
    """
    SHA-512 padding:
    1. Append bit '1' (0x80 byte)
    2. Append zeros until length ≡ 896 mod 1024 bits
    3. Append original length as 128-bit big-endian integer
    """
    msg = bytearray(message_bytes)
    original_bit_length = len(message_bytes) * 8

    msg.append(0x80)
    while len(msg) % 128 != 112:
        msg.append(0x00)

    # Append 128-bit big-endian length
    msg += original_bit_length.to_bytes(16, 'big')
    return bytes(msg)


def sha512(message_str):
    """
    Full SHA-512 computation with detailed step logging.
    Returns (digest_hex, steps_list)
    """
    steps = []
    message_bytes = message_str.encode('utf-8')

    steps.append({
        "title": "Step 1: Input Encoding",
        "detail": f"Input string: \"{message_str}\"",
        "data": [
            f"UTF-8 bytes ({len(message_bytes)} bytes): {message_bytes.hex().upper()}",
            f"Binary bit length: {len(message_bytes) * 8} bits"
        ]
    })

    # Padding
    padded = pad_message(message_bytes)
    steps.append({
        "title": "Step 2: Message Padding",
        "detail": "Pad message to multiple of 1024 bits (128 bytes):",
        "data": [
            f"Original length: {len(message_bytes)} bytes ({len(message_bytes)*8} bits)",
            "Append 0x80 byte (binary: 10000000)",
            f"Append zero bytes until length ≡ 112 (mod 128)",
            f"Append original bit-length as 128-bit big-endian",
            f"Padded length: {len(padded)} bytes ({len(padded)*8} bits)",
            f"Padded hex (first 64 bytes): {padded[:64].hex().upper()}",
            f"Padded hex (last 16 bytes / length field): {padded[-16:].hex().upper()}"
        ]
    })

    # Initial hash values
    h = list(H0)
    steps.append({
        "title": "Step 3: Initial Hash Values (H0–H7)",
        "detail": "First 64 bits of fractional parts of square roots of first 8 primes:",
        "data": [f"H{i} = {hex(H0[i]).upper()}" for i in range(8)]
    })

    # Process each 1024-bit block
    num_blocks = len(padded) // 128
    steps.append({
        "title": "Step 4: Message Schedule & Compression",
        "detail": f"Processing {num_blocks} block(s) of 1024 bits each:",
        "data": [f"Total padded message: {len(padded)*8} bits → {num_blocks} block(s)"]
    })

    for block_idx in range(num_blocks):
        block = padded[block_idx * 128: (block_idx + 1) * 128]
        block_steps = []

        # Parse 16 words of 64 bits
        W = list(struct.unpack('>16Q', block))

        block_steps.append({
            "sub": f"Block {block_idx+1} — Initial 16 words (W[0]–W[15]) from block bytes:",
            "lines": [f"W[{i:02d}] = {hex(W[i]).upper()}" for i in range(16)]
        })

        # Extend to 80 words
        ext_lines = []
        for i in range(16, 80):
            s0 = sigma0_small(W[i - 15])
            s1 = sigma1_small(W[i - 2])
            W.append((W[i - 16] + s0 + W[i - 7] + s1) & MASK64)
            ext_lines.append(
                f"W[{i:02d}] = W[{i-16:02d}] + σ0(W[{i-15:02d}]) + W[{i-7:02d}] + σ1(W[{i-2:02d}]) = {hex(W[i]).upper()}"
            )

        block_steps.append({
            "sub": f"Block {block_idx+1} — Extended Message Schedule W[16]–W[79]:",
            "lines": ext_lines
        })

        # Initialize working variables
        a, b, c, d, e, f_, g, hh = h
        block_steps.append({
            "sub": f"Block {block_idx+1} — Working Variables at Start:",
            "lines": [
                f"a={hex(a).upper()}  b={hex(b).upper()}  c={hex(c).upper()}  d={hex(d).upper()}",
                f"e={hex(e).upper()}  f={hex(f_).upper()}  g={hex(g).upper()}  h={hex(hh).upper()}"
            ]
        })

        # 80 rounds
        round_lines = []
        for i in range(80):
            S1 = sigma1_big(e)
            ch_val = ch(e, f_, g)
            temp1 = (hh + S1 + ch_val + K[i] + W[i]) & MASK64
            S0 = sigma0_big(a)
            maj_val = maj(a, b, c)
            temp2 = (S0 + maj_val) & MASK64

            hh = g
            g = f_
            f_ = e
            e = (d + temp1) & MASK64
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & MASK64

            round_lines.append(
                f"Round {i:02d}: T1={hex(temp1).upper()} T2={hex(temp2).upper()} "
                f"a={hex(a).upper()} e={hex(e).upper()}"
            )

        block_steps.append({
            "sub": f"Block {block_idx+1} — 80 Compression Rounds:",
            "lines": round_lines
        })

        # Add back to hash
        h[0] = (h[0] + a) & MASK64
        h[1] = (h[1] + b) & MASK64
        h[2] = (h[2] + c) & MASK64
        h[3] = (h[3] + d) & MASK64
        h[4] = (h[4] + e) & MASK64
        h[5] = (h[5] + f_) & MASK64
        h[6] = (h[6] + g) & MASK64
        h[7] = (h[7] + hh) & MASK64

        block_steps.append({
            "sub": f"Block {block_idx+1} — Updated Hash Values (H += working vars):",
            "lines": [f"H{i} = {hex(h[i]).upper()}" for i in range(8)]
        })

        steps.append({
            "title": f"Block {block_idx+1} Processing",
            "detail": f"1024-bit block: {block.hex().upper()[:48]}...",
            "block_steps": block_steps
        })

    # Final digest
    digest = b''.join(v.to_bytes(8, 'big') for v in h)
    digest_hex = digest.hex().upper()

    steps.append({
        "title": "Step 5: Final Digest",
        "detail": "Concatenate H0–H7 to produce 512-bit (64-byte) hash:",
        "data": [f"H{i} = {hex(h[i]).upper()}" for i in range(8)] + [
            f"SHA-512 = {digest_hex}"
        ]
    })

    return digest_hex, steps
