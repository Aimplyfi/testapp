from flask import Flask, request
import ast

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
    try:
        result = ast.literal_eval(cmd)   # Safe evaluation using literal_eval
    except Exception as e:
        return f"Invalid expression: {e}", 400
    return str(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)