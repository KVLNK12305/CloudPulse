from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify({
        "service": "cloudpulse-detection-worker",
        "status": "healthy"
    })


@app.route("/")
def home():
    return jsonify({
        "service": "cloudpulse-detection-worker",
        "message": "CloudPulse detection worker is running"
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)