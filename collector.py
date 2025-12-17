from flask import Flask, request

app = Flask(__name__)

@app.route("/alert", methods=["POST"])
def alert():
    print("\n🚨 FAILED LOGIN EVENT RECEIVED 🚨")
    print(request.json)
    return "ok"

app.run(host="0.0.0.0", port=5000)
