"""
AES-128 and CMAC (Cipher-based Message Authentication Code) implementations from scratch.
No use of cryptography or hashlib libraries.
"""

# ─────────────────────────────────────────────
# AES-128 CONSTANTS
# ─────────────────────────────────────────────

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

INV_SBOX = [0]*256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

MIX_COL = [
    [2,3,1,1],
    [1,2,3,1],
    [1,1,2,3],
    [3,1,1,2]
]

INV_MIX_COL = [
    [14,11,13,9],
    [9,14,11,13],
    [13,9,14,11],
    [11,13,9,14]
]


# ─────────────────────────────────────────────
# GF(2^8) arithmetic
# ─────────────────────────────────────────────

def xtime(a):
    """Multiply by 2 in GF(2^8) with reduction polynomial x^8+x^4+x^3+x+1."""
    return (((a << 1) ^ 0x1b) & 0xff) if (a & 0x80) else ((a << 1) & 0xff)


def gf_mul(a, b):
    """Multiply two bytes in GF(2^8)."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return result


# ─────────────────────────────────────────────
# AES Key Expansion
# ─────────────────────────────────────────────

def key_expansion(key_bytes):
    """Expand 16-byte key into 11 round keys (each 16 bytes)."""
    assert len(key_bytes) == 16
    w = [list(key_bytes[i*4:(i+1)*4]) for i in range(4)]

    for i in range(4, 44):
        temp = list(w[i-1])
        if i % 4 == 0:
            # RotWord + SubBytes + Rcon
            temp = [SBOX[temp[1]], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
            temp[0] ^= RCON[(i//4)-1]
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])

    round_keys = []
    for r in range(11):
        rk = []
        for j in range(4):
            rk += w[r*4 + j]
        round_keys.append(bytes(rk))
    return round_keys


# ─────────────────────────────────────────────
# AES Core Operations
# ─────────────────────────────────────────────

def add_round_key(state, round_key):
    return [state[i] ^ round_key[i] for i in range(16)]


def sub_bytes(state):
    return [SBOX[b] for b in state]


def shift_rows(state):
    s = list(state)
    # Row 1: shift left 1
    s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
    # Row 2: shift left 2
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    # Row 3: shift left 3
    s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
    return s


def mix_columns(state):
    result = [0]*16
    for col in range(4):
        c = [state[col*4 + row] for row in range(4)]
        for row in range(4):
            val = 0
            for k in range(4):
                val ^= gf_mul(MIX_COL[row][k], c[k])
            result[col*4 + row] = val
    return result


def aes_encrypt_block(plaintext_bytes, round_keys):
    """Encrypt a single 16-byte block with AES-128. Returns ciphertext bytes."""
    assert len(plaintext_bytes) == 16
    state = list(plaintext_bytes)

    # Initial round key addition
    state = add_round_key(state, list(round_keys[0]))

    for rnd in range(1, 11):
        state = sub_bytes(state)
        state = shift_rows(state)
        if rnd < 10:
            state = mix_columns(state)
        state = add_round_key(state, list(round_keys[rnd]))

    return bytes(state)


# ─────────────────────────────────────────────
# CMAC Subkey Generation
# ─────────────────────────────────────────────

R_128 = 0x87  # Constant for GF(2^128) with reduction polynomial


def left_shift_1(b):
    """Left shift 16-byte bytearray by 1 bit."""
    result = bytearray(16)
    carry = 0
    for i in range(15, -1, -1):
        result[i] = ((b[i] << 1) & 0xff) | carry
        carry = (b[i] >> 7) & 1
    return result, (b[0] >> 7) & 1  # (shifted, msb)


def generate_subkeys(round_keys):
    """Generate CMAC subkeys K1 and K2."""
    L = aes_encrypt_block(b'\x00' * 16, round_keys)
    L_ba = bytearray(L)

    K1_ba, msb = left_shift_1(L_ba)
    if msb:
        K1_ba[15] ^= R_128
    K1 = bytes(K1_ba)

    K2_ba, msb = left_shift_1(K1_ba)
    if msb:
        K2_ba[15] ^= R_128
    K2 = bytes(K2_ba)

    return K1, K2, bytes(L)


# ─────────────────────────────────────────────
# CMAC
# ─────────────────────────────────────────────

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def cmac(key_hex, message_str):
    """
    Full CMAC computation with detailed step logging.
    key_hex: 32-char hex string (16 bytes for AES-128)
    message_str: input string
    Returns (mac_hex, steps_list)
    """
    steps = []
    key_bytes = bytes.fromhex(key_hex)
    message_bytes = message_str.encode('utf-8')

    steps.append({
        "title": "Step 1: Input",
        "detail": "Key and message:",
        "data": [
            f"Key (hex): {key_hex.upper()}",
            f"Message string: \"{message_str}\"",
            f"Message bytes ({len(message_bytes)} bytes): {message_bytes.hex().upper()}"
        ]
    })

    # Key expansion
    round_keys = key_expansion(key_bytes)
    steps.append({
        "title": "Step 2: AES-128 Key Expansion",
        "detail": "Expand 128-bit key into 11 round keys:",
        "data": [f"RoundKey[{i:02d}]: {rk.hex().upper()}" for i, rk in enumerate(round_keys)]
    })

    # Subkey generation
    K1, K2, L = generate_subkeys(round_keys)
    steps.append({
        "title": "Step 3: CMAC Subkey Generation",
        "detail": "Encrypt zero block, derive K1 and K2 via left-shift and conditional XOR with R_128=0x87:",
        "data": [
            f"L = AES(key, 0^128) = {L.hex().upper()}",
            f"K1 = L << 1 {'XOR 0x87 (MSB was 1)' if (L[0]>>7) else ''} = {K1.hex().upper()}",
            f"K2 = K1 << 1 {'XOR 0x87 (MSB was 1)' if (K1[0]>>7) else ''} = {K2.hex().upper()}"
        ]
    })

    # Message blocking
    BLOCK_SIZE = 16
    n_bytes = len(message_bytes)

    if n_bytes == 0:
        # Special case: empty message
        num_blocks = 1
        blocks = [b'\x00' * 16]
        last_complete = False
    else:
        num_full = n_bytes // BLOCK_SIZE
        remainder = n_bytes % BLOCK_SIZE
        if remainder == 0:
            num_blocks = num_full
            blocks = [message_bytes[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE] for i in range(num_full)]
            last_complete = True
        else:
            num_blocks = num_full + 1
            blocks = [message_bytes[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE] for i in range(num_full)]
            # Pad last block
            last_raw = message_bytes[num_full*BLOCK_SIZE:]
            padded_last = last_raw + b'\x80' + b'\x00' * (BLOCK_SIZE - len(last_raw) - 1)
            blocks.append(padded_last)
            last_complete = False

    block_info = []
    for i, blk in enumerate(blocks):
        if i < num_blocks - 1:
            block_info.append(f"Block {i+1} (complete, {BLOCK_SIZE} bytes): {blk.hex().upper()}")
        else:
            if last_complete:
                block_info.append(
                    f"Block {i+1} [LAST — complete, XOR with K1]: {blk.hex().upper()}"
                )
            else:
                raw_len = n_bytes % BLOCK_SIZE if n_bytes % BLOCK_SIZE != 0 else BLOCK_SIZE
                block_info.append(
                    f"Block {i+1} [LAST — INCOMPLETE ({raw_len} bytes), padded + XOR with K2 ⚠️]: {blk.hex().upper()}"
                )

    steps.append({
        "title": "Step 4: Message Blocking",
        "detail": f"Split message into {num_blocks} block(s) of 16 bytes each:",
        "data": [
            f"Message length: {n_bytes} bytes",
            f"Number of blocks: {num_blocks}",
            f"Last block complete: {last_complete}",
        ] + block_info
    })

    # Apply subkey to last block
    if last_complete:
        last_xored = xor_bytes(blocks[-1], K1)
        subkey_used = "K1"
    else:
        last_xored = xor_bytes(blocks[-1], K2)
        subkey_used = "K2"

    modified_blocks = blocks[:-1] + [last_xored]

    steps.append({
        "title": "Step 5: Apply Subkey to Last Block",
        "detail": f"XOR last block with {subkey_used} ({'complete block → K1' if last_complete else 'incomplete/padded block → K2'}):",
        "data": [
            f"Last block (before XOR): {blocks[-1].hex().upper()}",
            f"{subkey_used}: {(K1 if last_complete else K2).hex().upper()}",
            f"Last block (after XOR):  {last_xored.hex().upper()}"
        ]
    })

    # CBC-MAC computation
    X = b'\x00' * 16
    cbc_steps = []
    for i, blk in enumerate(modified_blocks):
        xored = xor_bytes(X, blk)
        Y = aes_encrypt_block(xored, round_keys)
        cbc_steps.append(
            f"Block {i+1}: X={X.hex().upper()} XOR M={blk.hex().upper()} → AES → {Y.hex().upper()}"
        )
        X = Y

    steps.append({
        "title": "Step 6: CBC-MAC Computation",
        "detail": "Iteratively XOR each block with running state, then AES encrypt:",
        "data": cbc_steps
    })

    mac = X
    steps.append({
        "title": "Step 7: Final MAC",
        "detail": "The output of the last AES encryption is the CMAC:",
        "data": [f"CMAC = {mac.hex().upper()}"]
    })

    # Block summary for display highlighting
    block_summary = []
    for i, blk in enumerate(blocks):
        is_last = (i == num_blocks - 1)
        is_incomplete = is_last and not last_complete
        block_summary.append({
            "index": i + 1,
            "hex": blk.hex().upper(),
            "is_last": is_last,
            "is_incomplete": is_incomplete,
            "label": (
                "Last Block (Incomplete — Padded + K2)" if is_incomplete else
                ("Last Block (Complete + K1)" if is_last else f"Block {i+1}")
            )
        })

    return mac.hex().upper(), steps, block_summary, last_complete
