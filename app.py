from flask import Flask, request, jsonify, session, redirect, url_for, render_template
from werkzeug.security import generate_password_hash, check_password_hash
import RSA_Algorithm
import ThreeDES_Algorithm
import AES_Algorithm
import hashlib


app = Flask(__name__)
app.secret_key = '1234567890'
users = []

#Link to index page
@app.route('/')
def index():
    return render_template('index.html')

@app.route("/registerForm")
def registerForm():
    return render_template('registerForm.html')

@app.route("/loginForm")
def loginForm():
    return render_template('loginForm.html')

@app.route('/home')
def home():
    protected()
    return render_template('home.html')

@app.route('/encrypt3DESForm')
def encrypt3DESForm():
    return render_template('encrypt3DESForm.html')

@app.route('/decrypt3DESForm')
def decrypt3DESForm():
    return render_template('decrypt3DESForm.html')

@app.route('/encryptAES128Form')
def encryptAES128Form():
    return render_template('encryptAES128Form.html')

@app.route('/decryptAES128Form')
def decryptAES128Form():
    return render_template('decryptAES128Form.html')

@app.route('/encryptAES256Form')
def encryptAES256Form():
    return render_template('encryptAES256Form.html')

@app.route('/decryptAES256Form')
def decryptAES256Form():
    return render_template('decryptAES256Form.html')

@app.route('/encryptRSAForm')
def encryptRSAForm():
    return render_template('encryptRSAForm.html')

@app.route('/decryptRSAForm')
def decryptRSAForm():
    return render_template('decryptRSAForm.html')


@app.route('/compareHashesForm')
def compareHashesForm():
    return render_template('compareHashesForm.html')

@app.route('/generateKeyForm')
def generateKeyForm():
    return render_template('generateKeyForm.html')


@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return jsonify({'error': 'Missing username or password'}), 400
        hashed_password = generate_password_hash(password)
        users.append({'username': username, 'password': hashed_password})
        return redirect('/loginForm')
            # jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return jsonify({'error': 'Missing username or password'}), 400
        user = next((user for user in users if user['username'] == username), None)
        if not user or not check_password_hash(user['password'], password):
            return jsonify({'error': 'Invalid username or password'}), 401
        session['user'] = username
        return redirect('/home')
            # jsonify({'message': 'User authenticated successfully'}), 200

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return jsonify({'message': 'User logged out successfully'}), 200

@app.route('/protected')
def protected():
    if 'user' not in session:
        return redirect(url_for('loginForm'))
    return True


# 3 DES
@app.route('/encrypt3DES', methods=['POST'])
def encrypt3DES():
    protected()
    ip_file = request.files["ip_file"]
    key = request.form.get("key")
    op_file = request.files["op_file"]

    return ThreeDES_Algorithm.encrypt3DES(ip_file, key, op_file)


@app.route('/decrypt3DES', methods=['POST'])
def decrypt3DES():
    protected()
    ip_file = request.files["ip_file"]
    key = request.form.get("key")
    op_file = request.files["op_file"]

    return ThreeDES_Algorithm.decrypt3DES(ip_file, key, op_file)


# RSA

@app.route('/encryptRSA', methods=['POST'])
def encryptRSA():
    protected()
    ip_file = request.files["ip_file"]
    op_file = request.files["op_file"]
    folder = request.form.get("uploadFolder")
    key = RSA_Algorithm.pairKeyGen(folder)
    return RSA_Algorithm.encryptRSA(key, ip_file, op_file)


@app.route('/decryptRSA', methods=['POST'])
def decryptRSA():
    protected()
    ip_file = request.files["ip_file"]
    op_file = request.files["op_file"]
    folder = request.form.get("uploadFolder")
    key = RSA_Algorithm.pairKeyGen(folder)
    return RSA_Algorithm.decryptRSA(key, ip_file, op_file)




# AES256

@app.route('/encryptAES256', methods=['POST'])
def encryptAES256():
    protected()
    ip_file = request.files["ip_file"]
    op_file = request.files["op_file"]

    return AES_Algorithm.encryptAES256(ip_file, op_file)


@app.route('/decryptAES256', methods=['POST'])
def decryptAES256():
    protected()
    ip_file = request.files["ip_file"]
    op_file = request.files["op_file"]
    key = request.form.get("key")
    return AES_Algorithm.decryptAES256(key, ip_file, op_file)


# AES128

@app.route('/encryptAES128', methods=['POST'])
def encryptAES128():
    protected()
    ip_file = request.files["ip_file"]
    op_file = request.files["op_file"]

    return AES_Algorithm.encryptAES128(ip_file, op_file)


@app.route('/decryptAES128', methods=['POST'])
def decryptAES128():
    protected()
    ip_file = request.files["ip_file"]
    op_file = request.files["op_file"]
    key = request.form.get("key")
    return AES_Algorithm.decryptAES256(key, ip_file, op_file)


# Compare SHA 2 and SHA 3 hashes


@app.route('/compare_hashes', methods=['POST'])
def compare_hashes():
    file_path_1 = request.files['file_path_1']
    file_path_2 = request.files['file_path_2']

    sha2_1 = hashlib.sha256()
    with file_path_1 as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha2_1.update(chunk)

    sha2_2 = hashlib.sha256()
    with file_path_2 as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha2_2.update(chunk)

    sha3_1 = hashlib.sha3_256()
    with file_path_1 as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha3_1.update(chunk)

    sha3_2 = hashlib.sha3_256()
    with file_path_2 as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha3_2.update(chunk)

    if sha2_1.hexdigest() == sha2_2.hexdigest() and sha3_1.hexdigest() == sha3_2.hexdigest():
        return jsonify({'message': 'The SHA2 and SHA3 hashes of the two files match.'}), 200
    else:
        return jsonify({'message': 'The SHA2 and/or SHA3 hashes of the two files do not match.'}), 400


if __name__ == '__main__':
    app.run()
