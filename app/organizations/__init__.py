from flask import Blueprint

organizations_bp = Blueprint(
    "organizations",
    __name__,
    url_prefix="/organizations"
)

from . import routes  # noqa
