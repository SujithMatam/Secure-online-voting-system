"""
Extensions module - avoids circular imports.
All Flask extensions are initialized here and imported by app.py and routes.
"""

from flask_pymongo import PyMongo
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

mongo = PyMongo()
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per hour"]
)
