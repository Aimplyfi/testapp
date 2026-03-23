from flask import Flask, request, abort

app = Flask(__name__)

@app.route("/")
def home():
    return "Vulnerable Server Running"

# Enforce hostname verification to prevent direct IP access
@app.before_request
def enforce_hostname():
    host = request.host.split(":")[0]
    # Allow only the service DNS name (e.g., vuln-server-service) or localhost
    allowed_hosts = ["vuln-server-service", "localhost"]
    if host not in allowed_hosts:
        return abort(400, "Direct IP access not allowed")

@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    if not cmd:
        return "No command provided"

    # Simple safe execution: only allow alphanumeric commands without shell operators
    import re, subprocess
    if not re.fullmatch(r"[A-Za-z0-9_]+", cmd):
        return "Invalid command", 400
    try:
        result = subprocess.check_output([cmd], text=True)
    except Exception as e:
        return f"Error: {e}", 500
    return result

if __name__ == "__main__":
    # Run with HTTPS using a self-signed certificate (adhoc)
    app.run(host="0.0.0.0", port=5000, ssl_context='adhoc')