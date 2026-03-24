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
    # Safely evaluate the expression using ast.literal_eval to prevent code execution
    import ast
    try:
        result = ast.literal_eval(cmd)
    except Exception:
        return "Invalid expression"
    # End of safe evaluation
    return str(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)