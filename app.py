from flask import Flask, request, jsonify, send_file, session
from flask_cors import CORS
import google.generativeai as genai
import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "chatbot.db")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", secrets.token_hex(16))
CORS(app, supports_credentials=True)

# Get API key from Render
GEMINI_API_KEY = "AIzaSyB0FyFweTCOEPZmdo5n3HOtjHg92m-djog"

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('models/gemini-2.5-flash')


# Initialize database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS chat_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')

    conn.commit()
    conn.close()

init_db()


# Serve index.html (root)
@app.route('/')
def index():
    return send_file(os.path.join(BASE_DIR, "index.html"))


@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username or not email or not password:
            return jsonify({'error': 'Tüm alanları doldurun'}), 400

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        c.execute('SELECT id FROM users WHERE username=? OR email=?', (username, email))
        if c.fetchone():
            conn.close()
            return jsonify({'error': 'Kullanıcı adı veya email zaten kullanımda'}), 400

        hashed_password = generate_password_hash(password)
        c.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                  (username, email, hashed_password))
        conn.commit()
        user_id = c.lastrowid
        conn.close()

        session['user_id'] = user_id
        session['username'] = username

        return jsonify({'success': True, 'username': username})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Kullanıcı adı ve şifre gerekli'}), 400

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, username, password FROM users WHERE username=?', (username,))
        user = c.fetchone()
        conn.close()

        if not user or not check_password_hash(user[2], password):
            return jsonify({'error': 'Kullanıcı adı veya şifre hatalı'}), 401

        session['user_id'] = user[0]
        session['username'] = user[1]

        return jsonify({'success': True, 'username': user[1]})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})


@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if 'user_id' in session:
        return jsonify({'authenticated': True, 'username': session['username']})
    return jsonify({'authenticated': False})


@app.route('/api/chat-history', methods=['GET'])
def get_chat_history():
    if 'user_id' not in session:
        return jsonify({'error': 'Oturum açmanız gerekli'}), 401

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT role, content FROM chat_history WHERE user_id=? ORDER BY created_at',
                  (session['user_id'],))
        messages = [{'role': row[0], 'content': row[1]} for row in c.fetchall()]
        conn.close()

        return jsonify({'messages': messages})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/clear-history', methods=['POST'])
def clear_history():
    if 'user_id' not in session:
        return jsonify({'error': 'Oturum açmanız gerekli'}), 401

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM chat_history WHERE user_id=?', (session['user_id'],))
        conn.commit()
        conn.close()

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/chat', methods=['POST'])
def chat():
    if 'user_id' not in session:
        return jsonify({'error': 'Oturum açmanız gerekli'}), 401

    try:
        data = request.json
        messages = data.get('messages', [])

        if not GEMINI_API_KEY:
            return jsonify({'error': 'API key tanımlanmamış'}), 500

        if not messages:
            return jsonify({'error': 'Mesaj bulunamadı'}), 400

        last_message = messages[-1]['content']

        chat_history = []
        for msg in messages[:-1]:
            role = 'user' if msg['role'] == 'user' else 'model'
            chat_history.append({'role': role, 'parts': [msg['content']]})

        chat = model.start_chat(history=chat_history)
        response = chat.send_message(last_message)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('INSERT INTO chat_history (user_id, role, content) VALUES (?, ?, ?)',
                  (session['user_id'], 'user', last_message))
        c.execute('INSERT INTO chat_history (user_id, role, content) VALUES (?, ?, ?)',
                  (session['user_id'], 'assistant', response.text))
        conn.commit()
        conn.close()

        return jsonify({'content': response.text, 'role': 'assistant'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)



