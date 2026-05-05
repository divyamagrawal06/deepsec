from flask import Blueprint, Flask, request

app = Flask(__name__)
admin = Blueprint("admin", __name__)


@app.route("/healthz")
def healthz():
    return "ok"


@admin.post("/users")
def create_user():
    return request.json
