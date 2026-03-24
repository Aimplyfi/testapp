from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def home():
    return "Vulnerable Server Running"

# ⚠️ Intentionally vulnerable endpoint
@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    if not cmd:
        return "No command provided"

    # 🚨 VULNERABILITY: unsafe eval
    result = eval(cmd)   # DO NOT EVER DO THIS IN REAL CODE
    return str(result)

if __name__ == "__main__":
    # Run the Flask app with TLS. Cert and key are expected to be in the container root.
    app.run(host="0.0.0.0", port=5000, ssl_context=('cert.pem', 'key.pem'))