from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# ---------------- GCD FUNCTION ----------------
def gcd(a, b):
    steps = []
    while b != 0:
        steps.append(f"{a} = {b} × {a//b} + {a%b}")
        a, b = b, a % b
    steps.append(f"GCD = {a}")
    return a, steps


# ---------------- PRIMITIVE ROOT FULL CHECK ----------------
def primitive_root_full(p):
    results = []

    for g in range(2, p):
        steps = []
        values = []

        for i in range(1, p):
            val = pow(g, i, p)
            steps.append(f"{g}^{i} mod {p} = {val}")
            values.append(val)

        # Check if values contain all numbers 1 to p-1
        is_root = set(values) == set(range(1, p))

        results.append({
            "g": g,
            "steps": steps,
            "is_root": is_root
        })

    return results


# ---------------- ROUTES ----------------
@app.route('/')
def dashboard():
    return render_template("dashboard.html")


@app.route('/gcd-page')
def gcd_page():
    return render_template("gcd.html")


@app.route('/primitive-page')
def primitive_page():
    return render_template("primitive.html")


@app.route('/calculate-gcd', methods=['POST'])
def calculate_gcd():
    data = request.json
    a = int(data['a'])
    b = int(data['b'])
    result, steps = gcd(a, b)
    return jsonify({"gcd": result, "steps": steps})


@app.route('/check-primitive', methods=['POST'])
def check_primitive():
    data = request.json
    p = int(data['p'])
    results = primitive_root_full(p)
    return jsonify({"results": results})


if __name__ == '__main__':
    app.run(debug=True)
