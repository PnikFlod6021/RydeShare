from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3

app = Flask(__name__)
app.config['STATIC_FOLDER'] = 'static'
app.secret_key = 'ASDA3D35ASD'

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()


    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]

    if 'first_name' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN first_name TEXT")
        cursor.execute("ALTER TABLE users ADD COLUMN last_name TEXT")

    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/central')
def central():
    return render_template('central.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, first_name, last_name) VALUES (?, ?, ?, ?)", (username, password, first_name, last_name))
        conn.commit()
        conn.close()
        return redirect(url_for('central'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()
        if user:
            flash('Login successful!', 'success')
            return redirect(url_for('central'))
        else:
            flash('Login failed. Please check your credentials.', 'error')
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
