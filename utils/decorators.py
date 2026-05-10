"""
Authentication and authorization decorators.
"""

from functools import wraps
from flask import session, redirect, url_for, flash
import logging


def login_required(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        if session.get('role') != 'admin':
            flash('Admin access required.', 'danger')
            logging.warning(
                f"Unauthorized admin access attempt by user {session.get('user_id')}"
            )
            return redirect(url_for('voting.dashboard'))
        return f(*args, **kwargs)
    return decorated


def verified_required(f):
    """Decorator to require verified voter status."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        if not session.get('is_verified'):
            flash('Your account is not yet verified by admin.', 'warning')
            return redirect(url_for('voting.dashboard'))
        return f(*args, **kwargs)
    return decorated
