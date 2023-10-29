from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3

app = Flask(__name__)
app.config['STATIC_FOLDER'] = 'static'
app.secret_key = 'ASDA3D35ASD'

def init_db():
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute(""" CREATE TABLE IF NOT EXISTS users (
                            id integer PRIMARY KEY,
                            name text NOT NULL,
                            begin_date text,
                            end_date text
                        ); """)

    cursor.execute("PRAGMA table_info(users)")
    columns_user = [column[1] for column in cursor.fetchall()]

    if 'first_name' not in columns_user:
        cursor.execute("ALTER TABLE users ADD COLUMN first_name TEXT")
        cursor.execute("ALTER TABLE users ADD COLUMN last_name TEXT")
    
    conn.commit();

init_db()

# our color palatte: https://coolors.co/061a40-f1f0ea-4cb963-1c6e8c-274156

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/central')
def central():
    return render_template('central.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']

        cursor.execute("INSERT INTO users (username, password, first_name, last_name) VALUES (?, ?, ?, ?)", (username, password, first_name, last_name))
        conn.commit()

        return redirect(url_for('central'))

    conn.close()
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