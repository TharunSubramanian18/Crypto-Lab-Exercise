from flask import Flask, render_template, request, jsonify
from sha512_impl import sha512
from cmac_impl import cmac
from md5_impl import md5

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/sha512')
def sha512_page():
    return render_template('sha512.html')


@app.route('/cmac')
def cmac_page():
    return render_template('cmac.html')


@app.route('/md5')
def md5_page():
    return render_template('md5.html')


@app.route('/api/sha512', methods=['POST'])
def api_sha512():
    data = request.get_json()
    message = data.get('message', '')
    try:
        digest, steps = sha512(message)
        return jsonify({'success': True, 'digest': digest, 'steps': steps})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/cmac', methods=['POST'])
def api_cmac():
    data = request.get_json()
    message = data.get('message', '')
    key_hex = data.get('key', '')

    if len(key_hex) != 32:
        return jsonify({'success': False, 'error': 'Key must be exactly 32 hex characters (128-bit AES key)'}), 400
    try:
        bytes.fromhex(key_hex)
    except ValueError:
        return jsonify({'success': False, 'error': 'Key must be valid hexadecimal'}), 400

    try:
        mac, steps, block_summary, last_complete = cmac(key_hex, message)
        return jsonify({
            'success': True,
            'mac': mac,
            'steps': steps,
            'block_summary': block_summary,
            'last_complete': last_complete
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/md5', methods=['POST'])
def api_md5():
    data = request.get_json()
    message = data.get('message', '')
    try:
        digest, steps = md5(message)
        return jsonify({'success': True, 'digest': digest, 'steps': steps})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True, port=5000)
