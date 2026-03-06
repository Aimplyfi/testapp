from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import operator
import logging

app = Flask(__name__)

# Limit request size (1 KB)
app.config["MAX_CONTENT_LENGTH"] = 1024

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Rate limiter
limiter = Limiter(get_remote_address, app=app, default_limits=["20/minute"])


# -----------------------------
# Security Headers
# -----------------------------
@app.after_request
def add_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# -----------------------------
# Allowed operations
# -----------------------------
ALLOWED_OPERATIONS = {
    "add": operator.add,
    "sub": operator.sub,
    "mul": operator.mul,
    "div": operator.truediv
}


# -----------------------------
# Health endpoint (K8s probes)
# -----------------------------
@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# -----------------------------
# Home
# -----------------------------
@app.route("/")
@limiter.limit("10/minute")
def home():
    return jsonify({"status": "Server running"})


# -----------------------------
# Secure computation endpoint
# -----------------------------
@app.route("/run", methods=["POST"])
@limiter.limit("10/minute")
def run():

    if not request.is_json:
        abort(400, "Content-Type must be application/json")

    data = request.get_json(silent=True)

    if not data:
        abort(400, "Invalid JSON")

    op = data.get("operation")
    a = data.get("a")
    b = data.get("b")

    # Validate operation
    if op not in ALLOWED_OPERATIONS:
        abort(400, "Unsupported operation")

    # Validate numbers
    if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
        abort(400, "Invalid numeric input")

    try:
        result = ALLOWED_OPERATIONS[op](a, b)
    except ZeroDivisionError:
        abort(400, "Division by zero")

    logger.info("Operation executed: %s %s %s", a, op, b)

    return jsonify({
        "operation": op,
        "a": a,
        "b": b,
        "result": result
    })


# -----------------------------
# Error handlers (prevent stack leaks)
# -----------------------------
@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": str(e)}), 400


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500


# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )