"""
Secure Online Voting System - Main Application
Flask application factory with security middleware.
"""

from flask import Flask, redirect, url_for, render_template
from extensions import mongo, csrf, limiter
from config import Config
from datetime import datetime
import logging


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions with app
    mongo.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # ---- Security Headers Middleware ----
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'"
        )
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        return response

    # ---- Audit Logging Setup ----
    logging.basicConfig(
        filename='audit.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # ---- Register Blueprints ----
    from routes.auth import auth_bp
    from routes.voting import voting_bp
    from routes.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(voting_bp, url_prefix='/vote')
    app.register_blueprint(admin_bp, url_prefix='/admin')

    # ---- Root Route ----
    @app.route('/')
    def index():
        return redirect(url_for('auth.login'))

    # ---- Security Features Page (for demonstration) ----
    @app.route('/security')
    def security():
        return render_template('security.html')

    # ---- Create Default Admin ----
    with app.app_context():
        _create_default_admin()
        _create_db_indexes()

    return app


def _create_default_admin():
    """Create default admin user if not exists."""
    from utils.security import hash_password

    admin = mongo.db.users.find_one({'username': 'admin'})
    if not admin:
        mongo.db.users.insert_one({
            'username': 'admin',
            'password': hash_password('Admin@123'),
            'email': 'admin@voting.com',
            'role': 'admin',
            'is_verified': True,
            'voter_id': 'ADMIN001',
            'created_at': datetime.utcnow(),
            'login_attempts': 0,
            'locked_until': None
        })
        logging.info("Default admin account created (username: admin)")


def _create_db_indexes():
    """Create MongoDB indexes for security and performance."""
    # Unique index on username and email
    mongo.db.users.create_index('username', unique=True)
    mongo.db.users.create_index('email', unique=True)
    mongo.db.users.create_index('voter_id', unique=True)

    # Unique compound index: one vote per user per election
    mongo.db.votes.create_index(
        [('user_id', 1), ('election_id', 1)],
        unique=True
    )

    # Index for audit log queries
    mongo.db.audit_log.create_index('timestamp')


# ---- Run Application ----
if __name__ == '__main__':
    app = create_app()
    print("\n=== Secure Online Voting System ===")
    print("Default Admin -> username: admin | password: Admin@123")
    print("Running on http://127.0.0.1:5000\n")
    app.run(debug=True, port=5000)
