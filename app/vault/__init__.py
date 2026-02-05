from flask import Blueprint

vault_bp = Blueprint("vault", __name__, url_prefix="/vault")

from . import routes  # noqa
