from flask import Flask, render_template, request, redirect, url_for, session, g, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import time
import pyotp
import random
import string

app = Flask(__name__)
app.secret_key = "supersecretkey" 

DATABASE = 'members.db'

# USERS now include MFA settings. In production, you'd store these in your database.
USERS = {
    "staff": {
        "password": generate_password_hash("staffpass"),
        "role": "staff",
        "mfa_enabled": True,
        "mfa_secret": pyotp.random_base32()
    },
    "member": {
        "password": generate_password_hash("memberpass"),
        "role": "member",
        "mfa_enabled": False
    },
    "pakkarim": {
        "password": generate_password_hash("karim"),
        "role": "staff",
        "mfa_enabled": True,
        "mfa_secret": pyotp.random_base32()
    }
}

def demonstrate_hashed_passwords():
    print("USERS dictionary with hashed passwords:")
    for username, info in USERS.items():
        print(f"{username}: {info['password']}")

if __name__ == "__main__":
    demonstrate_hashed_passwords()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # optional: allows accessing columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.before_request
def create_tables():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS members (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    membership_status TEXT NOT NULL
                  )''')
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                    id INTEGER PRIMARY KEY,
                    class_name TEXT NOT NULL,
                    class_time TEXT NOT NULL
                  )''')
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                    member_id INTEGER,
                    class_id INTEGER,
                    FOREIGN KEY (member_id) REFERENCES members (id),
                    FOREIGN KEY (class_id) REFERENCES classes (id)
                  )''')
    db.commit()

# Home Route (Login) with account lockout and MFA integration
@app.route('/', methods=['GET', 'POST'])
def login():
    # Initialize failed attempt tracking in the session if not present
    if 'failed_attempts' not in session:
        session['failed_attempts'] = 0
    if 'cooldown_until' not in session:
        session['cooldown_until'] = 0

    current_time = time.time()
    disabled = False  # Flag to indicate if inputs should be disabled

    # Check if cooldown is active
    if current_time < session.get('cooldown_until', 0):
        disabled = True
        wait_time = int(session['cooldown_until'] - current_time)
        flash(f"Too many failed attempts. Please wait {wait_time} seconds before trying again.")

    # On GET, (CAPTCHA code removed)
    if request.method == 'GET':
        pass  # Removed: CAPTCHA generation code

    if request.method == 'POST':
        # Removed: CAPTCHA answer check

        # Prevent processing login if inputs are disabled
        if disabled:
            return render_template('login.html', disabled=disabled)

        username = request.form['username']
        password = request.form['password']

        if username in USERS and check_password_hash(USERS[username]['password'], password):
            # If user has MFA enabled, store a pending state and redirect to MFA verification
            if USERS[username].get('mfa_enabled'):
                session['pending_user'] = username
                return redirect(url_for('mfa'))
            else:
                # Successful login: reset failed attempts and cooldown
                session.pop('failed_attempts', None)
                session.pop('cooldown_until', None)
                session['user'] = username
                session['role'] = USERS[username]['role']
                return redirect(url_for('dashboard'))
        else:
            session['failed_attempts'] += 1

            # If three or more failed attempts, set/extend cooldown period
            if session['failed_attempts'] >= 3:
                multiplier = (session['failed_attempts'] - 3) // 3 + 1
                cooldown = 30 * multiplier
                session['cooldown_until'] = time.time() + cooldown
                flash(f"Login failed. You have reached {session['failed_attempts']} failed attempts. Please wait {cooldown} seconds before trying again.")
            else:
                flash("Login Failed!")
            return redirect(url_for('login'))
    return render_template('login.html', disabled=disabled)

# MFA Verification Route with valid_window to allow for slight time drift
@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    pending_user = session.get('pending_user')
    if not pending_user:
        flash("Session expired or invalid access to MFA.")
        return redirect(url_for('login'))

    user_data = USERS.get(pending_user)
    totp = pyotp.TOTP(user_data['mfa_secret'])
    otp_code = totp.now()  # Generate the OTP code

    if request.method == 'POST':
        mfa_code = request.form.get('mfa_code')
        if totp.verify(mfa_code, valid_window=1):
            session.pop('pending_user', None)
            session.pop('failed_attempts', None)
            session.pop('cooldown_until', None)
            session['user'] = pending_user
            session['role'] = user_data['role']
            flash("MFA verified successfully!")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid MFA code. Please try again.")
    return render_template('mfa.html', otp_code=otp_code)

# Dashboard (for both staff and members)
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    username = session['user']
    return render_template('dashboard.html', username=username)

# Member Management Routes
@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    if 'user' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('add_member.html')

# View specific member classes
@app.route('/member/<int:member_id>/classes')
def member_classes(member_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    member = query_db("SELECT * FROM members WHERE id = ?", [member_id], one=True)
    classes = query_db("SELECT c.class_name, c.class_time FROM classes c "
                        "JOIN member_classes mc ON c.id = mc.class_id "
                        "WHERE mc.member_id = ?", [member_id])
    
    return render_template('member_classes.html', member=member, classes=classes)

# Register class
@app.route('/register_class/<int:member_id>', methods=['GET', 'POST'])
def register_class(member_id):
    if 'user' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))

    classes = query_db("SELECT * FROM classes")  # Get all available classes
    if request.method == 'POST':
        class_id = request.form['class_id']
        db = get_db()
        db.execute("INSERT INTO member_classes (member_id, class_id) VALUES (?, ?)", (member_id, class_id))
        db.commit()
        return redirect(url_for('member_classes', member_id=member_id))
    
    return render_template('register_class.html', member_id=member_id, classes=classes)

# View users
@app.route('/view_members')
def view_members():
    if 'user' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))
    
    members = query_db("SELECT * FROM members")
    return render_template('view_members.html', members=members)

# New Route for Registering a Member
@app.route('/register_member', methods=['GET', 'POST'])
def register_member():
    if 'user' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('register_member.html')

# Class Scheduling Routes
@app.route('/add_class', methods=['GET', 'POST'])
def add_class():
    if 'user' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        class_name = request.form['class_name']
        class_time = request.form['class_time']
        db = get_db()
        db.execute("INSERT INTO classes (class_name, class_time) VALUES (?, ?)", (class_name, class_time))
        db.commit()
        return redirect(url_for('view_classes'))
    
    return render_template('add_class.html')

@app.route('/view_classes')
def view_classes():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    classes = query_db("SELECT * FROM classes")
    return render_template('view_classes.html', classes=classes)

# Deleting member
@app.route('/delete_member/<int:member_id>', methods=['POST'])
def delete_member(member_id):
    if 'user' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))
    
    db = get_db()
    db.execute("DELETE FROM members WHERE id = ?", [member_id])
    db.execute("DELETE FROM member_classes WHERE member_id = ?", [member_id])
    db.commit()
    
    return redirect(url_for('view_members'))

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    session.pop('failed_attempts', None)
    session.pop('cooldown_until', None)
    session.pop('pending_user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
