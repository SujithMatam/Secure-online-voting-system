"""
Security utility functions for the Secure Online Voting System.
Handles password hashing, vote integrity, input sanitization, and validation.
"""

import bcrypt
import hashlib
import secrets
import re
import bleach


def hash_password(password):
    """Hash password using bcrypt with salt (12 rounds)."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt)


def verify_password(password, hashed):
    """Verify password against bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed)


def generate_vote_hash(voter_id, election_id, candidate_id, timestamp):
    """Generate SHA-256 hash for vote integrity verification."""
    nonce = secrets.token_hex(16)
    data = f"{voter_id}:{election_id}:{candidate_id}:{timestamp}:{nonce}"
    return hashlib.sha256(data.encode()).hexdigest()


def generate_vote_receipt():
    """Generate a unique vote receipt token."""
    return secrets.token_hex(16)


def validate_password_strength(password):
    """Enforce strong password policy. Returns list of errors."""
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    if not re.search(r'[0-9]', password):
        errors.append("Password must contain at least one digit")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character")
    return errors


def sanitize_input(text):
    """Sanitize user input to prevent XSS attacks."""
    if text is None:
        return ''
    return bleach.clean(str(text).strip())


def validate_email(email):
    """Validate email format using regex."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_voter_id(voter_id):
    """Validate voter ID format: 6-12 uppercase alphanumeric characters."""
    pattern = r'^[A-Z0-9]{6,12}$'
    return re.match(pattern, voter_id) is not None
