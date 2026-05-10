"""
Authentication routes: Login, Register, Logout.
Security features:
  - Rate limiting (5/min login, 3/min register)
  - Account lockout after 5 failed attempts (15 min)
  - bcrypt password hashing (12 rounds)
  - CSRF protection on all forms
  - Input sanitization (XSS prevention)
  - NoSQL injection prevention (type checking)
  - Full audit logging
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from extensions import mongo, limiter
from utils.security import (
    verify_password, hash_password, sanitize_input,
    validate_password_strength, validate_email, validate_voter_id
)
from datetime import datetime, timedelta
import logging

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit: prevent brute-force attacks
def login():
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin.dashboard'))
        return redirect(url_for('voting.dashboard'))

    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')

        # --- Input validation ---
        if not username or not password:
            flash('All fields are required.', 'danger')
            return render_template('auth/login.html')

        # --- NoSQL Injection Prevention: ensure inputs are strings ---
        if not isinstance(username, str) or not isinstance(password, str):
            flash('Invalid input type.', 'danger')
            logging.warning(f"NoSQL injection attempt from {request.remote_addr}")
            return render_template('auth/login.html')

        user = mongo.db.users.find_one({'username': username})

        if user:
            # Check account lockout
            if user.get('locked_until') and user['locked_until'] > datetime.utcnow():
                remaining = (user['locked_until'] - datetime.utcnow()).seconds // 60
                flash(f'Account locked. Try again in {remaining + 1} minutes.', 'danger')
                logging.warning(f"Login attempt on locked account: {username}")
                return render_template('auth/login.html')

            if verify_password(password, user['password']):
                # Reset login attempts on success
                mongo.db.users.update_one(
                    {'_id': user['_id']},
                    {'$set': {
                        'login_attempts': 0,
                        'locked_until': None,
                        'last_login': datetime.utcnow()
                    }}
                )

                # --- Secure session setup ---
                session.permanent = True
                session['user_id'] = str(user['_id'])
                session['username'] = user['username']
                session['role'] = user['role']
                session['is_verified'] = user.get('is_verified', False)

                logging.info(f"Successful login: {username} from {request.remote_addr}")

                # Audit log
                mongo.db.audit_log.insert_one({
                    'action': 'LOGIN',
                    'user_id': str(user['_id']),
                    'username': username,
                    'ip_address': request.remote_addr,
                    'user_agent': request.user_agent.string,
                    'timestamp': datetime.utcnow(),
                    'status': 'SUCCESS'
                })

                if user['role'] == 'admin':
                    return redirect(url_for('admin.dashboard'))
                return redirect(url_for('voting.dashboard'))
            else:
                # --- Account lockout mechanism ---
                attempts = user.get('login_attempts', 0) + 1
                update = {'$set': {'login_attempts': attempts}}

                if attempts >= 5:
                    update['$set']['locked_until'] = datetime.utcnow() + timedelta(minutes=15)
                    flash('Too many failed attempts. Account locked for 15 minutes.', 'danger')
                    logging.warning(f"Account locked: {username}")
                else:
                    flash(f'Invalid credentials. {5 - attempts} attempts remaining.', 'danger')

                mongo.db.users.update_one({'_id': user['_id']}, update)

                # Audit log - failed attempt
                mongo.db.audit_log.insert_one({
                    'action': 'LOGIN',
                    'username': username,
                    'ip_address': request.remote_addr,
                    'user_agent': request.user_agent.string,
                    'timestamp': datetime.utcnow(),
                    'status': 'FAILED'
                })
        else:
            # Generic message to prevent username enumeration
            flash('Invalid credentials.', 'danger')
            logging.warning(f"Login attempt with unknown username: {username}")

    return render_template('auth/login.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute")  # Rate limit: prevent mass registration
def register():
    if 'user_id' in session:
        return redirect(url_for('voting.dashboard'))

    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        email = sanitize_input(request.form.get('email', ''))
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        voter_id = sanitize_input(request.form.get('voter_id', '').upper())

        # --- NoSQL Injection Prevention ---
        for field in [username, email, password, confirm_password, voter_id]:
            if not isinstance(field, str):
                flash('Invalid input type detected.', 'danger')
                logging.warning(f"NoSQL injection attempt during registration from {request.remote_addr}")
                return render_template('auth/register.html')

        errors = []

        if not all([username, email, password, confirm_password, voter_id]):
            errors.append('All fields are required.')

        if password != confirm_password:
            errors.append('Passwords do not match.')

        # --- Strong password policy enforcement ---
        pwd_errors = validate_password_strength(password)
        errors.extend(pwd_errors)

        if not validate_email(email):
            errors.append('Invalid email format.')

        if not validate_voter_id(voter_id):
            errors.append('Voter ID must be 6-12 uppercase alphanumeric characters.')

        if len(username) < 3 or len(username) > 30:
            errors.append('Username must be 3-30 characters long.')

        # Check uniqueness
        if mongo.db.users.find_one({'username': username}):
            errors.append('Username already taken.')
        if mongo.db.users.find_one({'email': email}):
            errors.append('Email already registered.')
        if mongo.db.users.find_one({'voter_id': voter_id}):
            errors.append('Voter ID already registered.')

        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('auth/register.html')

        # --- Secure password storage with bcrypt (12 rounds) ---
        user = {
            'username': username,
            'password': hash_password(password),
            'email': email,
            'voter_id': voter_id,
            'role': 'voter',
            'is_verified': False,
            'created_at': datetime.utcnow(),
            'login_attempts': 0,
            'locked_until': None,
            'last_login': None
        }

        mongo.db.users.insert_one(user)

        logging.info(f"New registration: {username} (VoterID: {voter_id}) from {request.remote_addr}")

        mongo.db.audit_log.insert_one({
            'action': 'REGISTER',
            'username': username,
            'voter_id': voter_id,
            'ip_address': request.remote_addr,
            'timestamp': datetime.utcnow(),
            'status': 'SUCCESS'
        })

        flash('Registration successful! Wait for admin verification before voting.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html')


@auth_bp.route('/logout')
def logout():
    username = session.get('username', 'unknown')

    mongo.db.audit_log.insert_one({
        'action': 'LOGOUT',
        'user_id': session.get('user_id'),
        'username': username,
        'ip_address': request.remote_addr,
        'timestamp': datetime.utcnow(),
        'status': 'SUCCESS'
    })

    logging.info(f"User logged out: {username}")
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('auth.login'))
