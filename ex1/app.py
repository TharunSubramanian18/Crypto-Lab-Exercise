from flask import Flask, render_template, request, jsonify
print("Starting Flask app...")

app = Flask(__name__)

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def caesar(text, shift):
    result = ""
    steps = []
    for c in text.upper():
        if c in ALPHA:
            i = (ALPHA.index(c) + shift) % 26
            result += ALPHA[i]
            steps.append(f"{c} → {ALPHA[i]}")
        else:
            result += c
    return result, "\n".join(steps)

def playfair_prepare(text):
    text = text.upper().replace("J", "I")
    text = "".join(c for c in text if c.isalpha())
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else "X"
        if a == b:
            pairs.append(a + "X")
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    return pairs


def playfair(text, key, encrypt=True):
    key = key.upper().replace("J", "I")
    key = "".join(c for c in key if c.isalpha())

    used = set()
    matrix = []
    for c in key + ALPHA.replace("J", ""):
        if c not in used:
            used.add(c)
            matrix.append(c)

    pairs = playfair_prepare(text)
    shift = 1 if encrypt else -1

    res = ""
    steps = [f"PAIRS: {' '.join(pairs)}\n"]

    for p in pairs:
        i1, i2 = matrix.index(p[0]), matrix.index(p[1])
        r1, c1 = divmod(i1, 5)
        r2, c2 = divmod(i2, 5)

        if r1 == r2:
            n1 = matrix[r1 * 5 + (c1 + shift) % 5]
            n2 = matrix[r2 * 5 + (c2 + shift) % 5]
            steps.append(f"{p} (Row) → {n1}{n2}")
        elif c1 == c2:
            n1 = matrix[((r1 + shift) % 5) * 5 + c1]
            n2 = matrix[((r2 + shift) % 5) * 5 + c2]
            steps.append(f"{p} (Col) → {n1}{n2}")
        else:
            n1 = matrix[r1 * 5 + c2]
            n2 = matrix[r2 * 5 + c1]
            steps.append(f"{p} (Rect) → {n1}{n2}")

        res += n1 + n2

    return res, "\n".join(steps), matrix


def hill(text, key, encrypt=True):
    if len(key) != 4:
        return "ERROR", "Hill key must have exactly 4 numbers"

    key = list(map(int, key))
    a, b, c, d = key

    if not encrypt:
        det = (a * d - b * c) % 26
        inv = next((i for i in range(26) if (det * i) % 26 == 1), None)
        if inv is None:
            return "NON-INVERTIBLE", "Matrix not invertible"

        a = ( d * inv) % 26
        b = (-b * inv) % 26
        c = (-c * inv) % 26
        d = ( a * inv) % 26

    clean = "".join(c for c in text.upper() if c.isalpha())
    if len(clean) % 2:
        clean += "X"

    res = ""
    steps = ["HILL MATRIX OPERATION:\n"]

    for i in range(0, len(clean), 2):
        p1, p2 = ALPHA.index(clean[i]), ALPHA.index(clean[i + 1])
        c1 = (a * p1 + b * p2) % 26
        c2 = (c * p1 + d * p2) % 26
        res += ALPHA[c1] + ALPHA[c2]
        steps.append(f"[{p1},{p2}] → [{c1},{c2}]")

    return res, "\n".join(steps)


# ---------- ROUTES ----------
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/process", methods=["POST"])
def process():
    data = request.get_json()
    if not data:
        return jsonify(error="No JSON data received"), 400

    algo = data.get("algorithm")
    text = data.get("text", "")
    key = data.get("key", "")
    encrypt = data.get("encrypt", True)

    if algo == "caesar":
        out, steps = caesar(text, int(key))
        return jsonify(output=out, steps=steps)

    elif algo == "playfair":
        out, steps, matrix = playfair(text, key, encrypt)
        return jsonify(output=out, steps=steps, matrix=matrix)

    elif algo == "hill":
        out, steps = hill(text, key.split(), encrypt)
        return jsonify(output=out, steps=steps)

    else:
        return jsonify(error="Invalid algorithm"), 400


if __name__ == "__main__":
    app.run(debug=True)
