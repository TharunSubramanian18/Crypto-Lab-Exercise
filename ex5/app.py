from flask import Flask, render_template, request, jsonify
import random
import math

app = Flask(__name__)

# ---------- PRIMALITY TEST ----------
def is_prime(n, steps):

    steps.append(f"Checking if {n} is prime")

    if n < 2:
        steps.append(f"{n} < 2 → Not Prime")
        return False

    for i in range(2, int(math.sqrt(n)) + 1):

        steps.append(f"Testing divisor {i}")

        if n % i == 0:
            steps.append(f"{n} % {i} = 0 → Not Prime")
            return False

    steps.append(f"No divisors found → {n} is PRIME")
    return True


# ---------- PRIME GENERATION ----------
def generate_prime(steps):

    while True:

        num = random.randint(100, 300)

        steps.append(f"Generated Random Number → {num}")

        if is_prime(num, steps):
            return num


# ---------- GCD ----------
def gcd(a, b):

    while b:
        a, b = b, a % b

    return a


# ---------- MODULAR INVERSE ----------
def mod_inverse(e, phi, steps):

    d = 1

    while True:

        if (d * e) % phi == 1:

            steps.append(f"Found d where ({d} × {e}) mod {phi} = 1")

            return d

        d += 1


# ---------- DASHBOARD ----------
@app.route("/")
def dashboard():
    return render_template("dashboard.html")


# ---------- RSA PAGE ----------
@app.route("/rsa")
def rsa():
    return render_template("rsa.html")


# ---------- RSA GENERATION + ENCRYPTION ----------
@app.route("/generate_rsa", methods=["POST"])
def generate_rsa():

    data = request.json

    if not data or "plaintext" not in data:
        return jsonify({"steps": ["Error: No plaintext received"]})

    plaintext = data["plaintext"]

    steps = []

    steps.append("------ GENERATING PRIME p ------")
    p = generate_prime(steps)

    steps.append("------ GENERATING PRIME q ------")
    q = generate_prime(steps)

    while q == p:
        steps.append("q equals p → regenerating q")
        q = generate_prime(steps)

    steps.append(f"Chosen primes: p = {p}, q = {q}")

    # n calculation
    n = p * q
    steps.append(f"Compute n = p × q = {p} × {q} = {n}")

    # phi calculation
    phi = (p - 1) * (q - 1)
    steps.append(f"Compute φ(n) = (p-1)(q-1) = {phi}")

    # find e
    e = 2
    steps.append("Finding e such that gcd(e, φ)=1")

    while e < phi:

        if gcd(e, phi) == 1:
            steps.append(f"gcd({e},{phi}) = 1 → Valid e")
            break
        else:
            steps.append(f"gcd({e},{phi}) ≠ 1 → Reject")

        e += 1

    # find d
    d = mod_inverse(e, phi, steps)

    steps.append("------ FINAL KEYS ------")
    steps.append(f"Public Key (e,n) = ({e},{n})")
    steps.append(f"Private Key (d,n) = ({d},{n})")

# ---------- ENCRYPTION ----------
    steps.append("------ ENCRYPTION ------")

    plaintext = data["plaintext"]

    steps.append(f"Plaintext String = {plaintext}")

    cipher_numbers = []
    cipher_text = ""

    for ch in plaintext:

        ascii_val = ord(ch)

        steps.append(f"'{ch}' → ASCII {ascii_val}")

        if ascii_val >= n:
            steps.append(f"ASCII {ascii_val} must be smaller than n")
            return jsonify({"steps": steps})

        cipher = pow(ascii_val, e, n)

        steps.append(f"C = {ascii_val}^{e} mod {n} = {cipher}")

        cipher_numbers.append(cipher)

        # convert encrypted number to printable char
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        cipher_char = alphabet[cipher % len(alphabet)]
        cipher_text += cipher_char


    steps.append(f"Cipher Numbers = {cipher_numbers}")
    steps.append(f"Cipher Text = {cipher_text}")

    return jsonify({"steps": steps})


# ---------- DIFFIE HELLMAN PAGE ----------
@app.route("/diffie")
def diffie():
    return render_template("diffie.html")


# ---------- DIFFIE HELLMAN GENERATION ----------
@app.route("/generate_diffie", methods=["POST"])
def generate_diffie():

    data = request.json

    p = int(data["p"])
    g = int(data["g"])
    a = int(data["a"])
    b = int(data["b"])

    steps = []

    steps.append("Public parameters")
    steps.append(f"Prime p = {p}")
    steps.append(f"Generator g = {g}")

    A = pow(g, a, p)
    steps.append("Alice computes public key")
    steps.append(f"A = {g}^{a} mod {p} = {A}")

    B = pow(g, b, p)
    steps.append("Bob computes public key")
    steps.append(f"B = {g}^{b} mod {p} = {B}")

    secret1 = pow(B, a, p)
    steps.append("Alice computes shared secret")
    steps.append(f"Secret = {B}^{a} mod {p} = {secret1}")

    secret2 = pow(A, b, p)
    steps.append("Bob computes shared secret")
    steps.append(f"Secret = {A}^{b} mod {p} = {secret2}")

    steps.append(f"Shared Secret Key = {secret1}")

    return jsonify({"steps": steps})


if __name__ == "__main__":
    app.run(debug=True)