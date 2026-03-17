from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# ------------------ Helper Functions ------------------

def permute(bits, table):
    return ''.join(bits[i - 1] for i in table)

def xor(a, b):
    return ''.join('0' if i == j else '1' for i, j in zip(a, b))

def left_shift(bits, n):
    return bits[n:] + bits[:n]


@app.route('/')
def home():
    return render_template('des.html')


@app.route('/run-des', methods=['POST'])
def run_des():
    data = request.json

    pt = data['plaintext']      # 8 bits
    key = data['key']           # 10 bits (S-DES key)

    IP = data['ip']
    IP_INV = data['ipinv']
    E = data['e']
    P = data['p']
    P10 = data['p10']
    P8 = data['p8']
    s1, s2 = data['sboxes']

    steps = []

    # =====================================================
    #                    KEY GENERATION
    # =====================================================

    steps.append("=========== KEY GENERATION ===========")
    steps.append(f"Original 10-bit Key: {key}")

    # P10
    steps.append(f"\nP10 Table: {P10}")
    key_p10 = permute(key, P10)
    steps.append(f"After P10: {key_p10}")

    left = key_p10[:5]
    right = key_p10[5:]
    steps.append(f"Left Half (5 bits): {left}")
    steps.append(f"Right Half (5 bits): {right}")

    # LS-1
    steps.append("\n--- Left Shift 1 (LS-1) ---")
    left1 = left_shift(left, 1)
    right1 = left_shift(right, 1)
    steps.append(f"Left  after LS-1: {left1}")
    steps.append(f"Right after LS-1: {right1}")

    combined1 = left1 + right1
    steps.append(f"Combined after LS-1: {combined1}")

    # P8 → K1
    steps.append(f"\nP8 Table: {P8}")
    K1 = permute(combined1, P8)
    steps.append(f"K1 (Round 1 Key): {K1}")

    # LS-2
    steps.append("\n--- Left Shift 2 (LS-2) ---")
    left2 = left_shift(left1, 2)
    right2 = left_shift(right1, 2)
    steps.append(f"Left  after LS-2: {left2}")
    steps.append(f"Right after LS-2: {right2}")

    combined2 = left2 + right2
    steps.append(f"Combined after LS-2: {combined2}")

    # P8 → K2
    K2 = permute(combined2, P8)
    steps.append(f"K2 (Round 2 Key): {K2}")

    # =====================================================
    #                  INITIAL PERMUTATION
    # =====================================================

    steps.append("\n\n=========== INITIAL PERMUTATION ===========")
    steps.append(f"IP Table: {IP}")

    ip = permute(pt, IP)
    steps.append(f"After IP: {ip}")

    L = ip[:4]
    R = ip[4:]
    steps.append(f"L0 = {L}")
    steps.append(f"R0 = {R}")

    # =====================================================
    #                  4 ROUND ENCRYPTION
    # =====================================================

    round_keys = [K1, K2, K1, K2]

    for rnd in range(1, 5):

        round_key = round_keys[rnd - 1]

        steps.append(f"\n\n================ ROUND {rnd} ================")
        steps.append(f"L{rnd-1} = {L}")
        steps.append(f"R{rnd-1} = {R}")

        # -------- Expansion --------
        steps.append("\n--- Expansion Step ---")
        steps.append("Expansion duplicates and reorders bits of R using E table")
        steps.append(f"Expansion Table (E): {E}")

        exp = permute(R, E)
        steps.append(f"Expanded R{rnd-1}: {exp}")

        # -------- XOR --------
        steps.append("\n--- XOR with Round Key ---")
        steps.append("Expanded R is XORed with current round key")
        steps.append(f"Round Key Used: {round_key}")
        steps.append(f"Expanded R : {exp}")
        steps.append(f"Round Key  : {round_key}")

        x = xor(exp, round_key)
        steps.append(f"XOR Result : {x}")

        # -------- S-Box --------
        steps.append("\n--- S-Box Substitution ---")
        steps.append("Split XOR result into two 4-bit halves")

        left4 = x[:4]
        right4 = x[4:]

        def sbox_lookup(bits, box, name):
            row_bits = bits[0] + bits[3]
            col_bits = bits[1] + bits[2]
            row = int(row_bits, 2)
            col = int(col_bits, 2)
            val = box[row][col]
            out = format(val, '02b')

            steps.append(f"\n{name} Input: {bits}")
            steps.append(f"{name} Row Bits    : {row_bits} → Decimal {row}")
            steps.append(f"{name} Column Bits : {col_bits} → Decimal {col}")
            steps.append(f"{name} Lookup Value: {val}")
            steps.append(f"{name} Output (Binary): {out}")

            return out

        s1_out = sbox_lookup(left4, s1, "S1")
        s2_out = sbox_lookup(right4, s2, "S2")

        s_out = s1_out + s2_out
        steps.append(f"\nCombined S-Box Output (4 bits): {s_out}")

        # -------- P Permutation --------
        steps.append("\n--- Permutation (P) ---")
        steps.append("Rearranging S-box output using P table")
        steps.append(f"P Table: {P}")

        p_out = permute(s_out, P)
        steps.append(f"P Output: {p_out}")

        # -------- Feistel XOR --------
        steps.append("\n--- Feistel Function ---")
        steps.append("New Right = L XOR f(R)")
        steps.append(f"L{rnd-1}        : {L}")
        steps.append(f"f(R{rnd-1})     : {p_out}")

        new_R = xor(L, p_out)
        steps.append(f"L{rnd-1} XOR f(R{rnd-1}) = {new_R}")

        # -------- Swap --------
        steps.append("\n--- Swap Operation ---")
        steps.append("Left and Right halves are swapped")

        steps.append(f"L{rnd} = {R}")
        steps.append(f"R{rnd} = {new_R}")

        L, R = R, new_R

    # =====================================================
    #                  FINAL PERMUTATION
    # =====================================================

    steps.append("\n\n=========== FINAL PERMUTATION ===========")
    steps.append(f"IP Inverse Table: {IP_INV}")

    preoutput = R + L
    steps.append(f"Preoutput (R4 + L4): {preoutput}")

    final = permute(preoutput, IP_INV)
    steps.append(f"Final Ciphertext: {final}")

    return jsonify({"steps": steps})


if __name__ == '__main__':
    app.run(debug=True)
