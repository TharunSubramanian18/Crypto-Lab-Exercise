"""
MD5 implementation from scratch (no hashlib or cryptography libraries).
Returns detailed intermediate steps for educational display.
"""

import struct
import math

# MD5 per-round shift amounts
S = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
]

# MD5 round constants T[i] = floor(2^32 * |sin(i+1)|)
T = [int(2**32 * abs(math.sin(i + 1))) & 0xFFFFFFFF for i in range(64)]

# MD5 Initial Hash Values (little-endian)
A0 = 0x67452301
B0 = 0xefcdab89
C0 = 0x98badcfe
D0 = 0x10325476

MASK32 = 0xFFFFFFFF


def rotl32(x, n):
    """Left rotate 32-bit integer x by n bits."""
    return ((x << n) | (x >> (32 - n))) & MASK32


def F(b, c, d):
    return (b & c) | (~b & d) & MASK32


def G(b, c, d):
    return (b & d) | (c & ~d) & MASK32


def H(b, c, d):
    return b ^ c ^ d


def I(b, c, d):
    return c ^ (b | ~d)


def pad_message(message_bytes):
    """
    MD5 padding:
    1. Append bit '1' (0x80 byte)
    2. Append zeros until length ≡ 56 (mod 64)
    3. Append original length as 64-bit little-endian integer
    """
    msg = bytearray(message_bytes)
    original_bit_length = len(message_bytes) * 8

    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)

    # Append 64-bit little-endian length
    msg += original_bit_length.to_bytes(8, 'little')
    return bytes(msg)


def md5(message_str):
    """
    Full MD5 computation with detailed step logging.
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
        "detail": "Pad message to multiple of 512 bits (64 bytes):",
        "data": [
            f"Original length: {len(message_bytes)} bytes ({len(message_bytes)*8} bits)",
            "Append 0x80 byte (binary: 10000000)",
            "Append zero bytes until length ≡ 56 (mod 64)",
            "Append original bit-length as 64-bit little-endian",
            f"Padded length: {len(padded)} bytes ({len(padded)*8} bits)",
            f"Padded hex (first 32 bytes): {padded[:32].hex().upper()}",
            f"Padded hex (last 8 bytes / length field): {padded[-8:].hex().upper()}"
        ]
    })

    # Initial hash values
    steps.append({
        "title": "Step 3: Initial Hash Values (A, B, C, D)",
        "detail": "Four 32-bit magic constants (little-endian representation):",
        "data": [
            f"A = {hex(A0).upper()}",
            f"B = {hex(B0).upper()}",
            f"C = {hex(C0).upper()}",
            f"D = {hex(D0).upper()}",
        ]
    })

    # Round constants info
    steps.append({
        "title": "Step 4: Round Constants T[0]–T[63]",
        "detail": "T[i] = floor(2^32 × |sin(i+1)|) — one per round:",
        "data": [f"T[{i:02d}] = {hex(T[i]).upper()}" for i in range(64)]
    })

    # Process each 512-bit block
    num_blocks = len(padded) // 64
    steps.append({
        "title": "Step 5: Message Schedule & Compression",
        "detail": f"Processing {num_blocks} block(s) of 512 bits each:",
        "data": [f"Total padded message: {len(padded)*8} bits → {num_blocks} block(s)"]
    })

    # State
    a0, b0, c0, d0 = A0, B0, C0, D0

    for block_idx in range(num_blocks):
        block = padded[block_idx * 64: (block_idx + 1) * 64]
        block_steps = []

        # Parse 16 little-endian 32-bit words
        M = list(struct.unpack('<16I', block))

        block_steps.append({
            "sub": f"Block {block_idx+1} — 16 message words M[0]–M[15] (little-endian 32-bit):",
            "lines": [f"M[{i:02d}] = {hex(M[i]).upper()}" for i in range(16)]
        })

        # Initialize working variables
        A, B, C, D = a0, b0, c0, d0

        block_steps.append({
            "sub": f"Block {block_idx+1} — Working Variables at Start:",
            "lines": [
                f"A = {hex(A).upper()}",
                f"B = {hex(B).upper()}",
                f"C = {hex(C).upper()}",
                f"D = {hex(D).upper()}"
            ]
        })

        # 64 rounds across 4 functions
        round_lines = []
        for i in range(64):
            if i < 16:
                func_val = F(B, C, D)
                g = i
                func_name = "F"
            elif i < 32:
                func_val = G(B, C, D)
                g = (5 * i + 1) % 16
                func_name = "G"
            elif i < 48:
                func_val = H(B, C, D)
                g = (3 * i + 5) % 16
                func_name = "H"
            else:
                func_val = I(B, C, D)
                g = (7 * i) % 16
                func_name = "I"

            temp = (A + func_val + M[g] + T[i]) & MASK32
            temp = rotl32(temp, S[i])
            temp = (temp + B) & MASK32

            A = D
            D = C
            C = B
            B = temp

            round_lines.append(
                f"Round {i:02d} [{func_name}] g={g:02d} s={S[i]:02d}: "
                f"A={hex(A).upper()} B={hex(B).upper()} C={hex(C).upper()} D={hex(D).upper()}"
            )

        block_steps.append({
            "sub": f"Block {block_idx+1} — 64 Compression Rounds (4 functions × 16 rounds):",
            "lines": round_lines
        })

        # Add back to state
        a0 = (a0 + A) & MASK32
        b0 = (b0 + B) & MASK32
        c0 = (c0 + C) & MASK32
        d0 = (d0 + D) & MASK32

        block_steps.append({
            "sub": f"Block {block_idx+1} — Updated Hash Values (state += working vars):",
            "lines": [
                f"A = {hex(a0).upper()}",
                f"B = {hex(b0).upper()}",
                f"C = {hex(c0).upper()}",
                f"D = {hex(d0).upper()}"
            ]
        })

        steps.append({
            "title": f"Block {block_idx+1} Processing",
            "detail": f"512-bit block: {block.hex().upper()[:48]}...",
            "block_steps": block_steps
        })

    # Final digest — little-endian output
    digest = struct.pack('<4I', a0, b0, c0, d0)
    digest_hex = digest.hex().upper()

    steps.append({
        "title": "Step 6: Final Digest",
        "detail": "Concatenate A, B, C, D as little-endian 32-bit words to produce 128-bit hash:",
        "data": [
            f"A = {hex(a0).upper()}",
            f"B = {hex(b0).upper()}",
            f"C = {hex(c0).upper()}",
            f"D = {hex(d0).upper()}",
            f"MD5 = {digest_hex}"
        ]
    })

    return digest_hex, steps
