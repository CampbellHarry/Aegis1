from flask import Flask, request, render_template, redirect, url_for
import json
import os
import pyotp
from passlib.hash import pbkdf2_sha256 as sha256

app = Flask(__name__)
app.static_folder = 'static'

DATA_FILE = 'data.json'

def load_data():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'w') as f:
            json.dump({"users": []}, f)
    with open(DATA_FILE, 'r') as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    data = load_data()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = next((u for u in data['users'] if u['username'] == username), None)

        if user and sha256.verify(password, user['password']):
            if user.get('otp_secret'):
                if '2fa_token' in request.form:
                    totp = pyotp.TOTP(user['otp_secret'], interval=30)
                    if totp.verify(request.form['2fa_token']):
                        # Proceed with login
                        return "Login successful!"
                    else:
                        return "Invalid 2FA token."
                else:
                    return render_template('login.html', user=user)  # Pass user variable here
            else:
                # Proceed with login for users without 2FA
                return "Login successful!"
        else:
            return "Invalid credentials."
    return render_template('login.html')  # Do not pass user variable here


@app.route('/setup', methods=['GET', 'POST'])
def setup():
    data = load_data()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = next((u for u in data['users'] if u['username'] == username), None)

        if user:
            return "Username already exists. Please choose another username."

        new_user = {
            'username': username,
            'password': sha256.hash(password),
            'email': request.form['email']
        }
        new_user['otp_secret'] = pyotp.random_base32() if request.form.get('enable_2fa') else None
        data['users'].append(new_user)
        save_data(data)

        return redirect(url_for('dashboard'))

    return render_template('setup.html')


@app.route('/verify_2fa/<username>', methods=['POST'])
def verify_2fa(username):
    data = load_data()
    user = next((u for u in data['users'] if u['username'] == username), None)

    if user and user.get('otp_secret') and user['otp_secret']:
        totp = pyotp.TOTP(user['otp_secret'], interval=30)
        if totp.verify(request.form['token']):
            # Proceed with login
            return "Login successful!"
        else:
            return "Invalid 2FA token."
    else:
        return "2FA is not enabled for this user."

if __name__ == '__main__':
    app.run()
