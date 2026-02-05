from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from pymongo import MongoClient
from flask import current_app
from bson import ObjectId


# ==================================================
# Flask Extensions (uninitialized)
# ==================================================

bcrypt = Bcrypt()
login_manager = LoginManager()


# ==================================================
# MongoDB Client (internal)
# ==================================================

_mongo_client: MongoClient | None = None


# ==================================================
# MongoDB Initialization
# ==================================================

def init_mongo(app):
    """
    Initialize MongoDB and attach database handle to Flask app.

    Access anywhere via:
        current_app.db
    """
    global _mongo_client

    mongo_uri = app.config.get("MONGO_URI")
    if not mongo_uri:
        raise RuntimeError("MONGO_URI is not set")

    _mongo_client = MongoClient(mongo_uri)

    # Use default database from URI
    app.db = _mongo_client.get_default_database()


def close_mongo():
    """
    Close MongoDB connection (optional cleanup).
    """
    global _mongo_client
    if _mongo_client:
        _mongo_client.close()
        _mongo_client = None


# ==================================================
# Flask-Login Configuration
# ==================================================

def init_login_manager(app):
    """
    Configure Flask-Login.
    """

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id: str):
        """
        Load user from MongoDB for Flask-Login.
        """
        try:
            user = app.db.users.find_one(
                {"_id": ObjectId(user_id)}
            )
            if not user:
                return None

            # Import locally to avoid circular imports
            from app.auth.routes import LoginUser
            return LoginUser(user)

        except Exception:
            return None


# ==================================================
# Extension Initializer (Single Entry Point)
# ==================================================

def init_extensions(app):
    """
    Initialize all Flask extensions.
    Call this inside create_app().
    """

    # Bcrypt
    bcrypt.init_app(app)

    # MongoDB
    init_mongo(app)

    # Flask-Login
    init_login_manager(app)
